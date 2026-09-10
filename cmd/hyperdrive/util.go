package hyperdrive

import (
	"encoding/json"
	"strings"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func jsonUnmarshal(data []byte, dst any) error { return json.Unmarshal(data, dst) }

func cmdutilValueOrFile(flag, v string) (string, error) { return cmdutil.ValueOrFile(flag, v) }

// parseJSONObjectText validates an already-read JSON object.
func parseJSONObjectText(flag, text string) (json.RawMessage, error) {
	trimmed := strings.TrimSpace(text)
	var obj map[string]any
	if err := json.Unmarshal([]byte(trimmed), &obj); err != nil || obj == nil {
		return nil, errors.Usage("--%s must be a JSON object", flag)
	}
	return json.RawMessage(trimmed), nil
}

// cmdutilParseObjectOrArray resolves a flag (inline or @file) into raw JSON.
func cmdutilParseObjectOrArray(flag, v string, objectOnly bool) (json.RawMessage, error) {
	if objectOnly {
		return cmdutil.ParseJSONObject(flag, v)
	}
	return cmdutil.ParseJSONObjectOrArray(flag, v)
}
