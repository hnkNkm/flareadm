package cloudflare

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/pagination"
)

func alertingPath(accountID, resource, id string) string {
	p := "/accounts/" + url.PathEscape(accountID) + "/alerting/v3/" + resource
	if id != "" {
		p += "/" + url.PathEscape(id)
	}
	return p
}

// ListAlertingPolicies lists notification policies (not paginated).
func (c *Client) ListAlertingPolicies(ctx context.Context, accountID string, pol pagination.Policy) (*ListResult[AlertingPolicy], error) {
	return singlePageList[AlertingPolicy](ctx, c, alertingPath(accountID, "policies", ""), nil, pol)
}

// GetAlertingPolicy fetches one policy.
func (c *Client) GetAlertingPolicy(ctx context.Context, accountID, policyID string) (*GetResult[AlertingPolicy], error) {
	return accessGet[AlertingPolicy](ctx, c, alertingPath(accountID, "policies", policyID))
}

// CreateAlertingPolicy creates a policy (POST).
func (c *Client) CreateAlertingPolicy(ctx context.Context, accountID string, body map[string]any) (*GetResult[AlertingPolicy], error) {
	for _, key := range []string{"name", "alert_type", "enabled", "mechanisms"} {
		if _, ok := body[key]; !ok {
			return nil, errors.Usage("--%s is required", key)
		}
	}
	return accessCreate[AlertingPolicy](ctx, c, alertingPath(accountID, "policies", ""), body)
}

// UpdateAlertingPolicy patches a policy by read-modify-PUT.
func (c *Client) UpdateAlertingPolicy(ctx context.Context, accountID, policyID string, overrides map[string]any) (*GetResult[AlertingPolicy], error) {
	return accessMergeUpdate[AlertingPolicy](ctx, c, alertingPath(accountID, "policies", policyID), overrides)
}

// DeleteAlertingPolicy deletes a policy (DELETE, idempotent).
func (c *Client) DeleteAlertingPolicy(ctx context.Context, accountID, policyID string) error {
	return accessDelete(ctx, c, alertingPath(accountID, "policies", policyID))
}

// ListAlertingWebhooks lists webhook destinations (not paginated).
func (c *Client) ListAlertingWebhooks(ctx context.Context, accountID string, pol pagination.Policy) (*ListResult[AlertingWebhook], error) {
	return singlePageList[AlertingWebhook](ctx, c, alertingPath(accountID, "destinations/webhooks", ""), nil, pol)
}

// GetAlertingWebhook fetches one webhook destination.
func (c *Client) GetAlertingWebhook(ctx context.Context, accountID, webhookID string) (*GetResult[AlertingWebhook], error) {
	return accessGet[AlertingWebhook](ctx, c, alertingPath(accountID, "destinations/webhooks", webhookID))
}

// CreateAlertingWebhook creates a webhook destination (POST).
func (c *Client) CreateAlertingWebhook(ctx context.Context, accountID string, body map[string]any) (*GetResult[AlertingWebhook], error) {
	if _, ok := body["name"]; !ok {
		return nil, errors.Usage("--name is required")
	}
	if _, ok := body["url"]; !ok {
		return nil, errors.Usage("--url is required")
	}
	return accessCreate[AlertingWebhook](ctx, c, alertingPath(accountID, "destinations/webhooks", ""), body)
}

// UpdateAlertingWebhook patches a webhook destination by read-modify-PUT.
func (c *Client) UpdateAlertingWebhook(ctx context.Context, accountID, webhookID string, overrides map[string]any) (*GetResult[AlertingWebhook], error) {
	return accessMergeUpdate[AlertingWebhook](ctx, c, alertingPath(accountID, "destinations/webhooks", webhookID), overrides)
}

// DeleteAlertingWebhook deletes a webhook destination (DELETE, idempotent).
func (c *Client) DeleteAlertingWebhook(ctx context.Context, accountID, webhookID string) error {
	return accessDelete(ctx, c, alertingPath(accountID, "destinations/webhooks", webhookID))
}

// ListAlertingPagerduty lists the PagerDuty destinations (not paginated).
func (c *Client) ListAlertingPagerduty(ctx context.Context, accountID string, pol pagination.Policy) (*ListResult[AlertingPagerduty], error) {
	return singlePageList[AlertingPagerduty](ctx, c, alertingPath(accountID, "destinations/pagerduty", ""), nil, pol)
}

// DeleteAlertingPagerduty disconnects the account's PagerDuty integration.
func (c *Client) DeleteAlertingPagerduty(ctx context.Context, accountID string) error {
	return accessDelete(ctx, c, alertingPath(accountID, "destinations/pagerduty", ""))
}

// ListAlertingSilences lists silences (not paginated).
func (c *Client) ListAlertingSilences(ctx context.Context, accountID string, pol pagination.Policy) (*ListResult[AlertingSilence], error) {
	return singlePageList[AlertingSilence](ctx, c, alertingPath(accountID, "silences", ""), nil, pol)
}

// GetAlertingSilence fetches one silence.
func (c *Client) GetAlertingSilence(ctx context.Context, accountID, silenceID string) (*GetResult[AlertingSilence], error) {
	return accessGet[AlertingSilence](ctx, c, alertingPath(accountID, "silences", silenceID))
}

// CreateAlertingSilence creates a silence (POST).
func (c *Client) CreateAlertingSilence(ctx context.Context, accountID string, body map[string]any) (*GetResult[AlertingSilence], error) {
	for _, key := range []string{"policy_id", "start_time", "end_time"} {
		if _, ok := body[key]; !ok {
			return nil, errors.Usage("--%s is required", key)
		}
	}
	return accessCreate[AlertingSilence](ctx, c, alertingPath(accountID, "silences", ""), body)
}

// UpdateAlertingSilence updates a silence. The API's only update path is the
// collection endpoint with the silence id in the body, so the current silence
// is read first and merged.
func (c *Client) UpdateAlertingSilence(ctx context.Context, accountID, silenceID string, overrides map[string]any) (*GetResult[AlertingSilence], error) {
	if len(overrides) == 0 {
		return nil, errors.Usage("nothing to update")
	}
	current, err := c.GetAlertingSilence(ctx, accountID, silenceID)
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"id":         silenceID,
		"start_time": current.Item.StartTime,
		"end_time":   current.Item.EndTime,
	}
	for k, v := range overrides {
		body[k] = v
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "PUT", alertingPath(accountID, "silences", ""), nil, payload, "application/json")
	if err != nil {
		return nil, err
	}
	var item AlertingSilence
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding silence response", err)
	}
	return &GetResult[AlertingSilence]{Item: item, RawBody: raw}, nil
}

// DeleteAlertingSilence deletes a silence (DELETE, idempotent).
func (c *Client) DeleteAlertingSilence(ctx context.Context, accountID, silenceID string) error {
	return accessDelete(ctx, c, alertingPath(accountID, "silences", silenceID))
}

// AlertingHistoryQuery carries the history list filters.
type AlertingHistoryQuery struct {
	Since  string
	Before string
}

// ListAlertingHistory lists sent notifications (page pagination).
func (c *Client) ListAlertingHistory(ctx context.Context, accountID string, q AlertingHistoryQuery, pol pagination.Policy) (*ListResult[AlertingHistory], error) {
	query := url.Values{}
	if q.Since != "" {
		query.Set("since", q.Since)
	}
	if q.Before != "" {
		query.Set("before", q.Before)
	}
	return listTyped[AlertingHistory](ctx, c, listQuery{path: alertingPath(accountID, "history", ""), q: query, pol: pol})
}

// ListAlertingAvailable describes the alert types available to the account.
func (c *Client) ListAlertingAvailable(ctx context.Context, accountID string, pol pagination.Policy) (*GetResult[json.RawMessage], error) {
	if err := pol.Validate(); err != nil {
		return nil, errors.Usage("%s", err.Error())
	}
	env, raw, err := c.requestJSON(ctx, "GET", alertingPath(accountID, "available_alerts", ""), nil, nil, "")
	if err != nil {
		return nil, err
	}
	return &GetResult[json.RawMessage]{Item: env.Result, RawBody: raw}, nil
}
