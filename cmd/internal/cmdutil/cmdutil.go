// Package cmdutil holds small helpers shared by command packages.
package cmdutil

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

// ValueOrFile resolves a flag value: "@path" reads the file, anything else
// is used verbatim.
func ValueOrFile(flag, v string) (string, error) {
	if !strings.HasPrefix(v, "@") {
		return v, nil
	}
	path := v[1:]
	if path == "" {
		return "", errors.Usage("--%s @ requires a file path", flag)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", errors.Wrap(errors.CodeInvalid, fmt.Sprintf("reading %s file %s", flag, path), err)
	}
	return string(data), nil
}

// ParseJSONArray resolves a flag (inline or @file) into a validated JSON
// array of objects and returns it as raw JSON.
func ParseJSONArray(flag, v string) (json.RawMessage, error) {
	text, err := ValueOrFile(flag, v)
	if err != nil {
		return nil, err
	}
	var items []json.RawMessage
	if err := json.Unmarshal([]byte(text), &items); err != nil {
		return nil, errors.Usage("--%s must be a JSON array of objects: %v", flag, err)
	}
	for i, item := range items {
		var obj map[string]any
		if err := json.Unmarshal(item, &obj); err != nil || obj == nil {
			return nil, errors.Usage("--%s entry %d must be a JSON object", flag, i)
		}
	}
	return json.RawMessage(text), nil
}

// ParseJSONObject resolves a flag (inline or @file) into a validated JSON
// object.
func ParseJSONObject(flag, v string) (json.RawMessage, error) {
	text, err := ValueOrFile(flag, v)
	if err != nil {
		return nil, err
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(text), &obj); err != nil || obj == nil {
		return nil, errors.Usage("--%s must be a JSON object", flag)
	}
	return json.RawMessage(text), nil
}

// ClientAndScope resolves the API client plus the ruleset scope: an explicit
// --account-id selects account scope (no discovery); otherwise the zone is
// resolved through the shared zone resolver. --zone and --account-id are
// mutually exclusive.
func ClientAndScope(ctx context.Context, rt *app.Runtime) (*cloudflare.Client, cloudflare.RulesetScope, error) {
	if rt.AccountIDFlag != "" && rt.ZoneFlag != "" {
		return nil, cloudflare.RulesetScope{}, errors.Usage("--zone and --account-id are mutually exclusive; pick one ruleset scope")
	}
	if rt.AccountIDFlag != "" {
		client, err := rt.CloudClient()
		if err != nil {
			return nil, cloudflare.RulesetScope{}, err
		}
		return client, cloudflare.RulesetScope{AccountID: rt.AccountIDFlag}, nil
	}
	client, zoneID, err := rt.ResolveZone(ctx)
	if err != nil {
		return nil, cloudflare.RulesetScope{}, err
	}
	return client, cloudflare.RulesetScope{ZoneID: zoneID}, nil
}

// ParseJSONObjectOrArray resolves a flag (inline or @file) that may hold
// either a JSON object or a JSON array, returning the raw JSON.
func ParseJSONObjectOrArray(flag, v string) (json.RawMessage, error) {
	text, err := ValueOrFile(flag, v)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(text)
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		return nil, errors.Usage("--%s must be a JSON object or array", flag)
	}
	var probe any
	if err := json.Unmarshal([]byte(trimmed), &probe); err != nil {
		return nil, errors.Usage("--%s is not valid JSON: %v", flag, err)
	}
	return json.RawMessage(trimmed), nil
}
