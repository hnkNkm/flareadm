package zerotrust

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func cmdutilValueOrFile(flag, v string) (string, error) { return cmdutil.ValueOrFile(flag, v) }

// parseSettingsObject reads a JSON object (inline or @file) into a map for
// arbitrary field overrides.
func parseSettingsObject(flag, v string) (map[string]any, error) {
	text, err := cmdutil.ValueOrFile(flag, v)
	if err != nil {
		return nil, err
	}
	parsed, err := parseJSONObjectText(flag, text)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(parsed, &out); err != nil {
		return nil, errors.Usage("--%s must be a JSON object", flag)
	}
	return out, nil
}

// parseJSONArrayList validates a JSON array (inline or @file) and returns it
// verbatim so unknown rule fields survive.
func parseJSONArrayList(flag, v string) (json.RawMessage, error) {
	text, err := cmdutil.ValueOrFile(flag, v)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(text)
	var arr []json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &arr); err != nil {
		return nil, errors.Usage("--%s must be a JSON array", flag)
	}
	return json.RawMessage(trimmed), nil
}

// splitList splits a comma-separated flag value into trimmed, non-empty items.
func splitList(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// protectSecretValues registers every string value whose JSON key looks like a
// credential, so user-supplied objects (identity provider configs, SaaS app
// definitions) can never leak through diagnostics or error text.
func protectSecretValues(rt *app.Runtime, v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if s, ok := val.(string); ok && isSecretKey(k) {
				rt.ProtectSecret(s)
				continue
			}
			protectSecretValues(rt, val)
		}
	case []any:
		for _, item := range t {
			protectSecretValues(rt, item)
		}
	}
}

func isSecretKey(key string) bool {
	return strings.Contains(strings.ToLower(key), "secret")
}

// parseSecretCarryingObject reads a JSON object (inline or @file) and registers
// its credential-looking values as protected secrets.
func parseSecretCarryingObject(rt *app.Runtime, flag, v string) (json.RawMessage, error) {
	text, err := cmdutil.ValueOrFile(flag, v)
	if err != nil {
		return nil, err
	}
	obj, err := parseJSONObjectText(flag, text)
	if err != nil {
		return nil, err
	}
	var decoded any
	if err := json.Unmarshal(obj, &decoded); err == nil {
		protectSecretValues(rt, decoded)
	}
	return obj, nil
}

// parseSecretCarryingSettings is parseSettingsObject plus secret registration.
func parseSecretCarryingSettings(rt *app.Runtime, flag, v string) (map[string]any, error) {
	out, err := parseSettingsObject(flag, v)
	if err != nil {
		return nil, err
	}
	protectSecretValues(rt, any(out))
	return out, nil
}

// compactJSON renders a raw JSON value on one line for table cells.
func compactJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return string(raw)
	}
	return buf.String()
}

// scalarString renders an untyped JSON value for table cells.
func scalarString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(b)
	}
}

// parseJSONObjectText validates an already-read JSON object.
func parseJSONObjectText(flag, text string) (json.RawMessage, error) {
	trimmed := strings.TrimSpace(text)
	var obj map[string]any
	if err := json.Unmarshal([]byte(trimmed), &obj); err != nil || obj == nil {
		return nil, errors.Usage("--%s must be a JSON object", flag)
	}
	return json.RawMessage(trimmed), nil
}
