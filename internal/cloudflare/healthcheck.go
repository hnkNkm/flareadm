package cloudflare

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/pagination"
)

func healthchecksPath(zoneID, healthcheckID string) string {
	p := "/zones/" + url.PathEscape(zoneID) + "/healthchecks"
	if healthcheckID != "" {
		p += "/" + url.PathEscape(healthcheckID)
	}
	return p
}

func healthcheckPreviewPath(zoneID, previewID string) string {
	p := "/zones/" + url.PathEscape(zoneID) + "/healthchecks/preview"
	if previewID != "" {
		p += "/" + url.PathEscape(previewID)
	}
	return p
}

// healthcheckBody wraps the health check object the way the API expects it.
func healthcheckBody(overrides map[string]any) ([]byte, error) {
	if len(overrides) == 0 {
		return nil, errors.Usage("nothing to write")
	}
	return json.Marshal(map[string]any{"query_healthcheck": overrides})
}

// ListHealthchecks lists zone health checks (page pagination).
func (c *Client) ListHealthchecks(ctx context.Context, zoneID string, pol pagination.Policy) (*ListResult[Healthcheck], error) {
	return listTyped[Healthcheck](ctx, c, listQuery{path: healthchecksPath(zoneID, ""), q: url.Values{}, pol: pol})
}

// GetHealthcheck fetches one health check.
func (c *Client) GetHealthcheck(ctx context.Context, zoneID, healthcheckID string) (*GetResult[Healthcheck], error) {
	return accessGet[Healthcheck](ctx, c, healthchecksPath(zoneID, healthcheckID))
}

// CreateHealthcheck creates a health check (POST).
func (c *Client) CreateHealthcheck(ctx context.Context, zoneID string, overrides map[string]any) (*GetResult[Healthcheck], error) {
	if _, ok := overrides["name"]; !ok {
		return nil, errors.Usage("--name is required")
	}
	if _, ok := overrides["address"]; !ok {
		return nil, errors.Usage("--address is required")
	}
	if _, ok := overrides["type"]; !ok {
		return nil, errors.Usage("--type is required")
	}
	body, err := healthcheckBody(overrides)
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "POST", healthchecksPath(zoneID, ""), nil, body, "application/json")
	if err != nil {
		return nil, err
	}
	var item Healthcheck
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding health check response", err)
	}
	return &GetResult[Healthcheck]{Item: item, RawBody: raw}, nil
}

// UpdateHealthcheck patches a health check by read-modify-PUT (the API replaces
// the wrapped object).
func (c *Client) UpdateHealthcheck(ctx context.Context, zoneID, healthcheckID string, overrides map[string]any) (*GetResult[Healthcheck], error) {
	if len(overrides) == 0 {
		return nil, errors.Usage("nothing to update")
	}
	env, _, err := c.requestJSON(ctx, "GET", healthchecksPath(zoneID, healthcheckID), nil, nil, "")
	if err != nil {
		return nil, err
	}
	var current map[string]any
	if err := json.Unmarshal(env.Result, &current); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding existing health check", err)
	}
	for k, v := range overrides {
		current[k] = v
	}
	body, err := healthcheckBody(current)
	if err != nil {
		return nil, err
	}
	putEnv, raw, err := c.requestJSON(ctx, "PUT", healthchecksPath(zoneID, healthcheckID), nil, body, "application/json")
	if err != nil {
		return nil, err
	}
	var item Healthcheck
	if err := decodeResult(putEnv, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding health check response", err)
	}
	return &GetResult[Healthcheck]{Item: item, RawBody: raw}, nil
}

// DeleteHealthcheck deletes a health check (DELETE, idempotent).
func (c *Client) DeleteHealthcheck(ctx context.Context, zoneID, healthcheckID string) error {
	return accessDelete(ctx, c, healthchecksPath(zoneID, healthcheckID))
}

// CreateHealthcheckPreview creates a preview (POST).
func (c *Client) CreateHealthcheckPreview(ctx context.Context, zoneID string, overrides map[string]any) (*GetResult[Healthcheck], error) {
	body, err := healthcheckBody(overrides)
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "POST", healthcheckPreviewPath(zoneID, ""), nil, body, "application/json")
	if err != nil {
		return nil, err
	}
	var item Healthcheck
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding health check preview", err)
	}
	return &GetResult[Healthcheck]{Item: item, RawBody: raw}, nil
}

// GetHealthcheckPreview fetches one preview.
func (c *Client) GetHealthcheckPreview(ctx context.Context, zoneID, previewID string) (*GetResult[Healthcheck], error) {
	return accessGet[Healthcheck](ctx, c, healthcheckPreviewPath(zoneID, previewID))
}

// DeleteHealthcheckPreview deletes a preview (DELETE, idempotent).
func (c *Client) DeleteHealthcheckPreview(ctx context.Context, zoneID, previewID string) error {
	return accessDelete(ctx, c, healthcheckPreviewPath(zoneID, previewID))
}
