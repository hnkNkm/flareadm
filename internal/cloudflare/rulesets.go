package cloudflare

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"

	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/pagination"
)

// RulesetScope selects the zone or account API surface. Exactly one of the
// two identifiers must be set.
type RulesetScope struct {
	ZoneID    string
	AccountID string
}

// rulesetsBasePath builds /zones/{id}/rulesets or /accounts/{id}/rulesets.
func (s RulesetScope) basePath() (string, error) {
	switch {
	case s.ZoneID != "" && s.AccountID != "":
		return "", errors.Usage("rulesets cannot target a zone and an account at the same time")
	case s.ZoneID != "":
		return "/zones/" + url.PathEscape(s.ZoneID) + "/rulesets", nil
	case s.AccountID != "":
		return "/accounts/" + url.PathEscape(s.AccountID) + "/rulesets", nil
	default:
		return "", errors.Usage("a zone (--zone) or account (--account-id) is required")
	}
}

// RulesetRule is one normalized rule inside a ruleset.
type RulesetRule struct {
	ID                     string          `json:"id,omitempty" yaml:"id,omitempty"`
	Action                 string          `json:"action,omitempty" yaml:"action,omitempty"`
	Expression             string          `json:"expression,omitempty" yaml:"expression,omitempty"`
	Description            string          `json:"description,omitempty" yaml:"description,omitempty"`
	Ref                    string          `json:"ref,omitempty" yaml:"ref,omitempty"`
	Enabled                bool            `json:"enabled" yaml:"enabled"`
	ActionParameters       json.RawMessage `json:"action_parameters,omitempty" yaml:"action_parameters,omitempty"`
	Logging                json.RawMessage `json:"logging,omitempty" yaml:"logging,omitempty"`
	Ratelimit              json.RawMessage `json:"ratelimit,omitempty" yaml:"ratelimit,omitempty"`
	Categories             json.RawMessage `json:"categories,omitempty" yaml:"categories,omitempty"`
	ExposedCredentialCheck json.RawMessage `json:"exposed_credential_check,omitempty" yaml:"exposed_credential_check,omitempty"`
}

// Ruleset is the normalized ruleset model. Rules are populated by get and
// the phase entrypoint calls only (the list endpoint omits them).
type Ruleset struct {
	ID          string        `json:"id" yaml:"id"`
	Name        string        `json:"name" yaml:"name"`
	Description string        `json:"description,omitempty" yaml:"description,omitempty"`
	Kind        string        `json:"kind" yaml:"kind"`
	Phase       string        `json:"phase" yaml:"phase"`
	Version     string        `json:"version,omitempty" yaml:"version,omitempty"`
	LastUpdated string        `json:"last_updated,omitempty" yaml:"last_updated,omitempty"`
	Rules       []RulesetRule `json:"rules,omitempty" yaml:"rules,omitempty"`
}

// EntrypointRuleset is the phase entrypoint ruleset with its rules kept as
// raw JSON so unknown rule fields survive round trips.
type EntrypointRuleset struct {
	ID          string            `json:"id" yaml:"id"`
	Name        string            `json:"name,omitempty" yaml:"name,omitempty"`
	Phase       string            `json:"phase" yaml:"phase"`
	Version     string            `json:"version,omitempty" yaml:"version,omitempty"`
	LastUpdated string            `json:"last_updated,omitempty" yaml:"last_updated,omitempty"`
	Rules       []json.RawMessage `json:"rules" yaml:"rules"`
}

// RulesetListQuery carries the client-side filters applied after fetching
// (the rulesets API has no server-side phase/kind filter). Phase matches one
// exact phase; Phases matches any of a set (used by the WAF view).
type RulesetListQuery struct {
	Phase  string
	Phases []string
	Kind   string
}

// RulesetWrite is the create model for a ruleset. Rules is the raw JSON
// array supplied by the operator (or nil).
type RulesetWrite struct {
	Kind        string
	Name        string
	Phase       string
	Description string
	Rules       json.RawMessage
}

// RulesetUpdate carries the update overrides; nil fields are preserved from
// the existing ruleset. Rules replaces the whole rules array when non-nil.
type RulesetUpdate struct {
	Name        *string
	Description *string
	Rules       json.RawMessage
}

// cfRulesetPage decodes a cursor-paginated rulesets list page.
type cfRulesetPage struct {
	Result     []json.RawMessage `json:"result"`
	ResultInfo struct {
		Count   int64  `json:"count"`
		Cursor  string `json:"cursor"`
		PerPage int64  `json:"per_page"`
	} `json:"result_info"`
}

func decodeRuleset(raw json.RawMessage) (Ruleset, error) {
	var r Ruleset
	if err := json.Unmarshal(raw, &r); err != nil {
		return Ruleset{}, errors.Wrap(errors.CodeUnclassified, "decoding ruleset", err)
	}
	return r, nil
}

// matchesQuery applies the client-side phase/kind filters.
func (r Ruleset) matchesQuery(q RulesetListQuery) bool {
	if q.Phase != "" && r.Phase != q.Phase {
		return false
	}
	if len(q.Phases) > 0 && !containsString(q.Phases, r.Phase) {
		return false
	}
	if q.Kind != "" && r.Kind != q.Kind {
		return false
	}
	return true
}

// ListRulesets lists zone or account rulesets with cursor pagination and
// client-side phase/kind filtering.
func (c *Client) ListRulesets(ctx context.Context, scope RulesetScope, q RulesetListQuery, pol pagination.Policy) (*ListResult[Ruleset], error) {
	base, err := scope.basePath()
	if err != nil {
		return nil, err
	}
	if err := pol.Validate(); err != nil {
		return nil, errors.Usage("%s", err.Error())
	}
	perPage := pageSize(pol)

	var (
		items    []Ruleset
		rawItems []json.RawMessage
		bodies   [][]byte
		cursor   string
		guard    = pagination.NewCursorGuard()
	)
	maxReached := func() bool {
		if pol.MaxItems <= 0 {
			return false
		}
		if c.raw {
			return len(rawItems) >= pol.MaxItems
		}
		return len(items) >= pol.MaxItems
	}

	for {
		if err := guard.Step(cursor); err != nil {
			return nil, err
		}
		query := url.Values{}
		query.Set("per_page", strconv.Itoa(perPage))
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		_, raw, err := c.requestJSON(ctx, "GET", base, query, nil, "")
		if err != nil {
			return nil, err
		}
		bodies = append(bodies, raw)
		var page cfRulesetPage
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, errors.Wrap(errors.CodeUnclassified, "decoding ruleset list page", err)
		}
		for _, itemRaw := range page.Result {
			r, err := decodeRuleset(itemRaw)
			if err != nil {
				return nil, err
			}
			if !r.matchesQuery(q) {
				continue
			}
			if c.raw {
				rawItems = append(rawItems, itemRaw)
			} else {
				items = append(items, r)
			}
			if maxReached() {
				break
			}
		}
		if pol.NoPaginate || page.ResultInfo.Cursor == "" || maxReached() {
			break
		}
		cursor = page.ResultInfo.Cursor
	}

	if pol.MaxItems > 0 {
		if c.raw && len(rawItems) > pol.MaxItems {
			rawItems = rawItems[:pol.MaxItems]
		}
		if !c.raw && len(items) > pol.MaxItems {
			items = items[:pol.MaxItems]
		}
	}

	if c.raw {
		exact := len(bodies) == 1 && q.Phase == "" && len(q.Phases) == 0 && q.Kind == "" && pol.MaxItems == 0
		return &ListResult[Ruleset]{RawBody: mergeCursorResults(bodies, rawItems, perPage, exact)}, nil
	}
	return &ListResult[Ruleset]{Items: items}, nil
}

// mergeCursorResults builds the closest practical raw representation for a
// cursor-paginated list: the original body for an unfiltered single page
// (exact=true), otherwise a synthetic envelope with the resulting items.
func mergeCursorResults(bodies [][]byte, result []json.RawMessage, perPage int, exact bool) []byte {
	if exact && len(bodies) == 1 {
		return bodies[0]
	}
	out, err := json.Marshal(map[string]any{
		"success":  true,
		"errors":   []any{},
		"messages": []any{},
		"result":   result,
		"result_info": map[string]any{
			"count":    len(result),
			"per_page": perPage,
			"cursor":   "",
		},
	})
	if err != nil {
		if len(bodies) > 0 {
			return bodies[0]
		}
		return nil
	}
	return out
}

// GetRuleset fetches one ruleset including its rules.
func (c *Client) GetRuleset(ctx context.Context, scope RulesetScope, rulesetID string) (*GetResult[Ruleset], error) {
	base, err := scope.basePath()
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "GET", base+"/"+url.PathEscape(rulesetID), nil, nil, "")
	if err != nil {
		return nil, err
	}
	item, err := decodeRuleset(env.Result)
	if err != nil {
		return nil, err
	}
	return &GetResult[Ruleset]{Item: item, RawBody: raw}, nil
}

// CreateRuleset creates a ruleset. dryRun asks the API to validate without
// persisting.
func (c *Client) CreateRuleset(ctx context.Context, scope RulesetScope, w RulesetWrite, dryRun bool) (*GetResult[Ruleset], error) {
	base, err := scope.basePath()
	if err != nil {
		return nil, err
	}
	if w.Name == "" {
		return nil, errors.Usage("--name is required")
	}
	if w.Phase == "" {
		return nil, errors.Usage("--phase is required")
	}
	if w.Kind == "" {
		return nil, errors.Usage("--kind is required")
	}
	body := map[string]any{"kind": w.Kind, "name": w.Name, "phase": w.Phase}
	if w.Description != "" {
		body["description"] = w.Description
	}
	if len(w.Rules) > 0 {
		body["rules"] = w.Rules
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	query := url.Values{}
	if dryRun {
		query.Set("dry_run", "true")
	}
	env, respRaw, err := c.requestJSON(ctx, "POST", base, query, raw, "application/json")
	if err != nil {
		return nil, err
	}
	item, err := decodeRuleset(env.Result)
	if err != nil {
		return nil, err
	}
	return &GetResult[Ruleset]{Item: item, RawBody: respRaw}, nil
}

// UpdateRuleset merges overrides into the existing ruleset and PUTs the
// full representation, preserving kind/phase and (when no rules override is
// given) the existing rules verbatim.
func (c *Client) UpdateRuleset(ctx context.Context, scope RulesetScope, rulesetID string, up RulesetUpdate, dryRun bool) (*GetResult[Ruleset], error) {
	base, err := scope.basePath()
	if err != nil {
		return nil, err
	}
	if up.Name == nil && up.Description == nil && up.Rules == nil {
		return nil, errors.Usage("nothing to update; pass at least one of --name, --description, --rules")
	}
	env, _, err := c.requestJSON(ctx, "GET", base+"/"+url.PathEscape(rulesetID), nil, nil, "")
	if err != nil {
		return nil, err
	}
	var existing map[string]any
	if err := json.Unmarshal(env.Result, &existing); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding existing ruleset", err)
	}
	if up.Name != nil {
		existing["name"] = *up.Name
	}
	if up.Description != nil {
		existing["description"] = *up.Description
	}
	if up.Rules != nil {
		existing["rules"] = up.Rules
	}
	// The PUT body is the ruleset representation without server-managed
	// fields (id, version, last_updated).
	delete(existing, "id")
	delete(existing, "version")
	delete(existing, "last_updated")
	if _, ok := existing["kind"]; !ok {
		existing["kind"] = "custom"
	}
	raw, err := json.Marshal(existing)
	if err != nil {
		return nil, err
	}
	query := url.Values{}
	if dryRun {
		query.Set("dry_run", "true")
	}
	putEnv, respRaw, err := c.requestJSON(ctx, "PUT", base+"/"+url.PathEscape(rulesetID), query, raw, "application/json")
	if err != nil {
		return nil, err
	}
	item, err := decodeRuleset(putEnv.Result)
	if err != nil {
		return nil, err
	}
	return &GetResult[Ruleset]{Item: item, RawBody: respRaw}, nil
}

// DeleteRuleset deletes a ruleset. dryRun asks the API to validate without
// persisting.
func (c *Client) DeleteRuleset(ctx context.Context, scope RulesetScope, rulesetID string, dryRun bool) error {
	base, err := scope.basePath()
	if err != nil {
		return err
	}
	query := url.Values{}
	if dryRun {
		query.Set("dry_run", "true")
	}
	_, _, err = c.requestJSON(ctx, "DELETE", base+"/"+url.PathEscape(rulesetID), query, nil, "")
	return err
}

// entrypointPath builds
// /zones|accounts/{id}/rulesets/phases/{phase}/entrypoint.
func (c *Client) entrypointPath(scope RulesetScope, phase string) (string, error) {
	base, err := scope.basePath()
	if err != nil {
		return "", err
	}
	if phase == "" {
		return "", errors.Usage("a ruleset phase is required")
	}
	return base + "/phases/" + url.PathEscape(phase) + "/entrypoint", nil
}

// GetEntrypointRules reads the phase entrypoint ruleset (rules included).
func (c *Client) GetEntrypointRules(ctx context.Context, scope RulesetScope, phase string) (*GetResult[EntrypointRuleset], error) {
	path, err := c.entrypointPath(scope, phase)
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "GET", path, nil, nil, "")
	if err != nil {
		return nil, err
	}
	var item EntrypointRuleset
	if err := json.Unmarshal(env.Result, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding phase entrypoint", err)
	}
	if item.Rules == nil {
		item.Rules = []json.RawMessage{}
	}
	return &GetResult[EntrypointRuleset]{Item: item, RawBody: raw}, nil
}

// PutEntrypointRules replaces the phase entrypoint rules array. dryRun asks
// the API to validate without persisting.
func (c *Client) PutEntrypointRules(ctx context.Context, scope RulesetScope, phase string, rules []json.RawMessage, dryRun bool) (*GetResult[EntrypointRuleset], error) {
	path, err := c.entrypointPath(scope, phase)
	if err != nil {
		return nil, err
	}
	if rules == nil {
		rules = []json.RawMessage{}
	}
	body, err := json.Marshal(map[string]any{"rules": rules})
	if err != nil {
		return nil, err
	}
	query := url.Values{}
	if dryRun {
		query.Set("dry_run", "true")
	}
	env, raw, err := c.requestJSON(ctx, "PUT", path, query, body, "application/json")
	if err != nil {
		return nil, err
	}
	var item EntrypointRuleset
	if err := json.Unmarshal(env.Result, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding phase entrypoint", err)
	}
	if item.Rules == nil {
		item.Rules = []json.RawMessage{}
	}
	return &GetResult[EntrypointRuleset]{Item: item, RawBody: raw}, nil
}
