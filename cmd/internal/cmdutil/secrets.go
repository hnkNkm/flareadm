package cmdutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
)

// PreviewLine prints a --dry-run preview: plain text in table mode, a
// normalized {"preview": ...} object otherwise. The line is redacted.
func PreviewLine(rt *app.Runtime, line string) error {
	if rt.Format() == output.Table {
		_, _ = fmt.Fprintln(rt.Out, line)
		return nil
	}
	return rt.Printer().Emit(map[string]string{"preview": rt.Redact(line)})
}

// IsSecretKey reports whether a JSON key conventionally holds a credential.
func IsSecretKey(key string) bool {
	return strings.Contains(strings.ToLower(key), "secret")
}

// ProtectSecretValues registers every string value whose JSON key looks like a
// credential, so user-supplied objects (bindings, provider configs, project
// environment variables) can never leak through diagnostics or error text.
func ProtectSecretValues(rt *app.Runtime, v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if s, ok := val.(string); ok && IsSecretKey(k) {
				rt.ProtectSecret(s)
				continue
			}
			ProtectSecretValues(rt, val)
		}
	case []any:
		for _, item := range t {
			ProtectSecretValues(rt, item)
		}
	}
}

// ProtectBindingValues registers binding values carried by Worker metadata: the
// text of secret_text and plain_text bindings is treated as a credential.
func ProtectBindingValues(rt *app.Runtime, v any) {
	switch t := v.(type) {
	case map[string]any:
		if typ, _ := t["type"].(string); typ == "secret_text" || typ == "plain_text" {
			if text, ok := t["text"].(string); ok && text != "" {
				rt.ProtectSecret(text)
			}
		}
		for _, val := range t {
			ProtectBindingValues(rt, val)
		}
	case []any:
		for _, item := range t {
			ProtectBindingValues(rt, item)
		}
	}
}

// ProtectEnvVarValues registers Pages environment variable values, which may
// hold credentials.
func ProtectEnvVarValues(rt *app.Runtime, v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if k == "env_vars" {
				if vars, ok := val.(map[string]any); ok {
					for _, entry := range vars {
						if obj, ok := entry.(map[string]any); ok {
							if text, ok := obj["value"].(string); ok && text != "" {
								rt.ProtectSecret(text)
							}
						}
					}
				}
			}
			ProtectEnvVarValues(rt, val)
		}
	case []any:
		for _, item := range t {
			ProtectEnvVarValues(rt, item)
		}
	}
}

// ParseJSONObjectText validates an already-read JSON object.
func ParseJSONObjectText(flag, text string) (json.RawMessage, error) {
	trimmed := strings.TrimSpace(text)
	var obj map[string]any
	if err := json.Unmarshal([]byte(trimmed), &obj); err != nil || obj == nil {
		return nil, errors.Usage("--%s must be a JSON object", flag)
	}
	return json.RawMessage(trimmed), nil
}

// ParseJSONArrayList validates a JSON array (inline or @file) and returns it
// verbatim so unknown fields survive.
func ParseJSONArrayList(flag, v string) (json.RawMessage, error) {
	text, err := ValueOrFile(flag, v)
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

// SettingsObject reads a JSON object (inline or @file) into a map for arbitrary
// field overrides.
func SettingsObject(flag, v string) (map[string]any, error) {
	text, err := ValueOrFile(flag, v)
	if err != nil {
		return nil, err
	}
	parsed, err := ParseJSONObjectText(flag, text)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(parsed, &out); err != nil {
		return nil, errors.Usage("--%s must be a JSON object", flag)
	}
	return out, nil
}

// ParseSecretCarryingObject reads a JSON object (inline or @file), registers its
// credential-looking values, and returns it verbatim.
func ParseSecretCarryingObject(rt *app.Runtime, flag, v string) (json.RawMessage, error) {
	text, err := ValueOrFile(flag, v)
	if err != nil {
		return nil, err
	}
	obj, err := ParseJSONObjectText(flag, text)
	if err != nil {
		return nil, err
	}
	var decoded any
	if err := json.Unmarshal(obj, &decoded); err == nil {
		ProtectSecretValues(rt, decoded)
	}
	return obj, nil
}

// ParseSecretCarryingSettings is SettingsObject plus secret registration.
func ParseSecretCarryingSettings(rt *app.Runtime, flag, v string) (map[string]any, error) {
	out, err := SettingsObject(flag, v)
	if err != nil {
		return nil, err
	}
	ProtectSecretValues(rt, any(out))
	return out, nil
}

// ParseSecretCarryingBindings reads a bindings array (@file or inline), registers
// secret_text/plain_text values, and returns the array verbatim.
func ParseSecretCarryingBindings(rt *app.Runtime, flag, v string) (json.RawMessage, error) {
	arr, err := ParseJSONArrayList(flag, v)
	if err != nil {
		return nil, err
	}
	var decoded any
	if err := json.Unmarshal(arr, &decoded); err == nil {
		ProtectBindingValues(rt, decoded)
	}
	return arr, nil
}

// ProtectHeaderValues registers the values of HTTP header maps (keys named
// header or headers): probes and health checks routinely carry Authorization
// tokens there.
func ProtectHeaderValues(rt *app.Runtime, v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if strings.EqualFold(k, "header") || strings.EqualFold(k, "headers") {
				ProtectHeaderMap(rt, val)
				continue
			}
			ProtectHeaderValues(rt, val)
		}
	case []any:
		for _, item := range t {
			ProtectHeaderValues(rt, item)
		}
	}
}

// ProtectHeaderMap registers every string value of a header map (or list),
// used when the flag value is the header map itself.
func ProtectHeaderMap(rt *app.Runtime, v any) {
	switch t := v.(type) {
	case map[string]any:
		for _, val := range t {
			ProtectHeaderMap(rt, val)
		}
	case []any:
		for _, item := range t {
			ProtectHeaderMap(rt, item)
		}
	case string:
		if t != "" {
			rt.ProtectSecret(t)
		}
	}
}

// ProtectURLCredentials registers the individual credential values carried by a
// URL-like string (query parameters such as secret_access_key, tokens, sig, and
// URL userinfo passwords). Registering the values rather than only the whole
// string keeps redaction working when the API echoes the URL JSON-escaped.
func ProtectURLCredentials(rt *app.Runtime, raw string) {
	if raw == "" {
		return
	}
	query := raw
	if i := strings.Index(query, "?"); i >= 0 {
		query = query[i+1:]
	} else {
		return
	}
	values, err := url.ParseQuery(query)
	if err != nil {
		return
	}
	for key, vals := range values {
		if !isCredentialKey(key) {
			continue
		}
		for _, v := range vals {
			if v != "" {
				rt.ProtectSecret(v)
			}
		}
	}
}

// isCredentialKey reports whether a query parameter name holds a credential.
func isCredentialKey(key string) bool {
	k := strings.ToLower(key)
	for _, needle := range []string{"key", "token", "password", "passwd", "sig", "credential", "auth"} {
		if strings.Contains(k, needle) {
			return true
		}
	}
	return false
}

// FileOnly reads a credential flag that accepts only the @file form.
func FileOnly(flag, v string) (string, error) {
	if len(v) == 0 || v[0] != '@' {
		return "", errors.Usage(
			"--%s accepts only the @file form (for example @secret.txt); inline secret values are rejected because process arguments are observable",
			flag)
	}
	return ValueOrFile(flag, v)
}

// SplitList splits a comma-separated flag value into trimmed, non-empty items.
func SplitList(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// CompactJSON renders a raw JSON value on one line for table cells.
func CompactJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return string(raw)
	}
	return buf.String()
}

// ScalarString renders an untyped JSON value for table cells.
func ScalarString(v any) string {
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
