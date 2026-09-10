package zerotrust

import (
	"encoding/json"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
)

// Shared helpers for the zero-trust commands. The implementations live in
// cmd/internal/cmdutil so the workers and pages groups reuse them.

func cmdutilValueOrFile(flag, v string) (string, error) { return cmdutil.ValueOrFile(flag, v) }

func previewLine(rt *app.Runtime, line string) error { return cmdutil.PreviewLine(rt, line) }

func fileOnly(flag, v string) (string, error) { return cmdutil.FileOnly(flag, v) }

func dateOnly(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func splitList(v string) []string { return cmdutil.SplitList(v) }

func compactJSON(raw json.RawMessage) string { return cmdutil.CompactJSON(raw) }

func scalarString(v any) string { return cmdutil.ScalarString(v) }

func parseJSONObjectText(flag, text string) (json.RawMessage, error) {
	return cmdutil.ParseJSONObjectText(flag, text)
}

func parseJSONArrayList(flag, v string) (json.RawMessage, error) {
	return cmdutil.ParseJSONArrayList(flag, v)
}

func parseSettingsObject(flag, v string) (map[string]any, error) {
	return cmdutil.SettingsObject(flag, v)
}

func parseSecretCarryingObject(rt *app.Runtime, flag, v string) (json.RawMessage, error) {
	return cmdutil.ParseSecretCarryingObject(rt, flag, v)
}

func parseSecretCarryingSettings(rt *app.Runtime, flag, v string) (map[string]any, error) {
	return cmdutil.ParseSecretCarryingSettings(rt, flag, v)
}
