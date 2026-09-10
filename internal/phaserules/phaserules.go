// Package phaserules provides the shared rule-array manipulation used by
// the phase-scoped convenience commands (cache rules, redirect rules).
//
// Rules are kept as raw JSON so fields this CLI does not model survive
// round trips through the entrypoint PUT.
package phaserules

import (
	"encoding/json"
	"fmt"

	"github.com/hnkNkm/flareadm/internal/errors"
)

// Rule is the normalized view of one entrypoint rule for display.
type Rule struct {
	ID          string `json:"id,omitempty" yaml:"id,omitempty"`
	Action      string `json:"action,omitempty" yaml:"action,omitempty"`
	Expression  string `json:"expression,omitempty" yaml:"expression,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Enabled     bool   `json:"enabled" yaml:"enabled"`
}

// View decodes one raw rule into the display model.
func View(raw json.RawMessage) (Rule, error) {
	var r Rule
	if err := json.Unmarshal(raw, &r); err != nil {
		return Rule{}, errors.Wrap(errors.CodeUnclassified, "decoding rule", err)
	}
	return r, nil
}

// Views decodes every rule in order.
func Views(rules []json.RawMessage) ([]Rule, error) {
	out := make([]Rule, 0, len(rules))
	for _, raw := range rules {
		v, err := View(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// Find returns the index of the rule with the given id or ref.
func Find(rules []json.RawMessage, ref string) (int, error) {
	for i, raw := range rules {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return -1, errors.Wrap(errors.CodeUnclassified, "decoding rule", err)
		}
		if s, _ := m["id"].(string); s == ref {
			return i, nil
		}
		if s, _ := m["ref"].(string); s != "" && s == ref {
			return i, nil
		}
	}
	return -1, errors.New(errors.CodeNotFound, "rule %q not found in the phase entrypoint", ref)
}

// Map decodes one raw rule into a mutable map.
func Map(raw json.RawMessage) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding rule", err)
	}
	if m == nil {
		return nil, errors.Usage("rule is not a JSON object")
	}
	return m, nil
}

// Marshal encodes a mutable rule map back to raw JSON.
func Marshal(m map[string]any) (json.RawMessage, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "encoding rule", err)
	}
	return raw, nil
}

// Replace swaps the rule at index i with m.
func Replace(rules []json.RawMessage, i int, m map[string]any) ([]json.RawMessage, error) {
	raw, err := Marshal(m)
	if err != nil {
		return nil, err
	}
	out := append([]json.RawMessage(nil), rules...)
	out[i] = raw
	return out, nil
}

// Append adds one rule.
func Append(rules []json.RawMessage, m map[string]any) ([]json.RawMessage, error) {
	raw, err := Marshal(m)
	if err != nil {
		return nil, err
	}
	return append(append([]json.RawMessage(nil), rules...), raw), nil
}

// Remove deletes the rule at index i.
func Remove(rules []json.RawMessage, i int) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(rules)-1)
	out = append(out, rules[:i]...)
	out = append(out, rules[i+1:]...)
	return out
}

// Describe renders a short human description of a rule for prompts and
// previews.
func Describe(r Rule) string {
	switch {
	case r.Description != "":
		return fmt.Sprintf("%s (%s)", r.ID, r.Description)
	case r.Action != "":
		return fmt.Sprintf("%s (%s)", r.ID, r.Action)
	default:
		return r.ID
	}
}
