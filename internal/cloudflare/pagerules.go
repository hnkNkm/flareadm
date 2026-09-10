package cloudflare

import (
	"context"
	"encoding/json"
	"net/url"
	"time"

	"github.com/hnkNkm/flareadm/internal/errors"
)

// PageRuleStatuses are the accepted page rule statuses.
var PageRuleStatuses = []string{"active", "disabled"}

// PageRuleQuery carries the supported page rule list filters.
type PageRuleQuery struct {
	Status    string
	Order     string
	Direction string
	Match     string
}

// PageRuleWrite is the write model for page rules. Nil fields are omitted
// (which keeps them unchanged on PATCH updates).
type PageRuleWrite struct {
	Targets  json.RawMessage
	Actions  json.RawMessage
	Priority *int64
	Status   *string
}

func pageRulesPath(zoneID, ruleID string) string {
	p := "/zones/" + url.PathEscape(zoneID) + "/pagerules"
	if ruleID != "" {
		p += "/" + url.PathEscape(ruleID)
	}
	return p
}

// cfPageRule mirrors the page rule JSON shape.
type cfPageRule struct {
	ID         string          `json:"id"`
	Status     string          `json:"status"`
	Priority   int64           `json:"priority"`
	Targets    json.RawMessage `json:"targets"`
	Actions    json.RawMessage `json:"actions"`
	CreatedOn  time.Time       `json:"created_on"`
	ModifiedOn time.Time       `json:"modified_on"`
}

func convertPageRule(cf cfPageRule) PageRule {
	out := PageRule{
		ID: cf.ID, Status: cf.Status, Priority: cf.Priority,
		Targets: cf.Targets, Actions: cf.Actions,
	}
	if !cf.CreatedOn.IsZero() {
		out.CreatedOn = cf.CreatedOn.UTC().Format(time.RFC3339)
	}
	if !cf.ModifiedOn.IsZero() {
		out.ModifiedOn = cf.ModifiedOn.UTC().Format(time.RFC3339)
	}
	return out
}

func decodePageRuleList(env envelope) ([]PageRule, error) {
	var raw []json.RawMessage
	if err := decodeResult(env, &raw); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding page rules", err)
	}
	out := make([]PageRule, 0, len(raw))
	for _, item := range raw {
		var cf cfPageRule
		if err := json.Unmarshal(item, &cf); err != nil {
			return nil, errors.Wrap(errors.CodeUnclassified, "decoding page rule", err)
		}
		out = append(out, convertPageRule(cf))
	}
	return out, nil
}

// ListPageRules lists page rules of a zone (the endpoint returns all rules;
// it is not paginated).
func (c *Client) ListPageRules(ctx context.Context, zoneID string, q PageRuleQuery) (*ListResult[PageRule], error) {
	query := url.Values{}
	if q.Status != "" {
		query.Set("status", q.Status)
	}
	if q.Order != "" {
		query.Set("order", q.Order)
	}
	if q.Direction != "" {
		query.Set("direction", q.Direction)
	}
	if q.Match != "" {
		query.Set("match", q.Match)
	}
	env, raw, err := c.requestJSON(ctx, "GET", pageRulesPath(zoneID, ""), query, nil, "")
	if err != nil {
		return nil, err
	}
	if c.raw {
		return &ListResult[PageRule]{RawBody: raw}, nil
	}
	items, err := decodePageRuleList(env)
	if err != nil {
		return nil, err
	}
	return &ListResult[PageRule]{Items: items}, nil
}

// GetPageRule fetches one page rule.
func (c *Client) GetPageRule(ctx context.Context, zoneID, ruleID string) (*GetResult[PageRule], error) {
	env, raw, err := c.requestJSON(ctx, "GET", pageRulesPath(zoneID, ruleID), nil, nil, "")
	if err != nil {
		return nil, err
	}
	var cf cfPageRule
	if err := decodeResult(env, &cf); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding page rule response", err)
	}
	return &GetResult[PageRule]{Item: convertPageRule(cf), RawBody: raw}, nil
}

func pageRuleBody(w PageRuleWrite) ([]byte, error) {
	body := map[string]any{}
	if len(w.Targets) > 0 {
		body["targets"] = w.Targets
	}
	if len(w.Actions) > 0 {
		body["actions"] = w.Actions
	}
	if w.Priority != nil {
		body["priority"] = *w.Priority
	}
	if w.Status != nil {
		body["status"] = *w.Status
	}
	return json.Marshal(body)
}

// CreatePageRule creates a page rule (POST; never automatically retried).
func (c *Client) CreatePageRule(ctx context.Context, zoneID string, w PageRuleWrite) (*GetResult[PageRule], error) {
	if len(w.Targets) == 0 || string(w.Targets) == "[]" {
		return nil, errors.Usage("--targets is required (JSON array)")
	}
	if len(w.Actions) == 0 || string(w.Actions) == "[]" {
		return nil, errors.Usage("--actions is required (JSON array)")
	}
	body, err := pageRuleBody(w)
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "POST", pageRulesPath(zoneID, ""), nil, body, "application/json")
	if err != nil {
		return nil, err
	}
	var cf cfPageRule
	if err := decodeResult(env, &cf); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding page rule response", err)
	}
	return &GetResult[PageRule]{Item: convertPageRule(cf), RawBody: raw}, nil
}

// UpdatePageRule patches a page rule with the provided fields (idempotent).
func (c *Client) UpdatePageRule(ctx context.Context, zoneID, ruleID string, w PageRuleWrite) (*GetResult[PageRule], error) {
	if len(w.Targets) == 0 && len(w.Actions) == 0 && w.Priority == nil && w.Status == nil {
		return nil, errors.Usage("nothing to update; pass at least one of --targets, --actions, --priority, --status")
	}
	body, err := pageRuleBody(w)
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "PATCH", pageRulesPath(zoneID, ruleID), nil, body, "application/json")
	if err != nil {
		return nil, err
	}
	var cf cfPageRule
	if err := decodeResult(env, &cf); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding page rule response", err)
	}
	return &GetResult[PageRule]{Item: convertPageRule(cf), RawBody: raw}, nil
}

// DeletePageRule deletes a page rule (DELETE, idempotent).
func (c *Client) DeletePageRule(ctx context.Context, zoneID, ruleID string) error {
	_, _, err := c.requestJSON(ctx, "DELETE", pageRulesPath(zoneID, ruleID), nil, nil, "")
	return err
}
