package cloudflare

import (
	"context"
	"encoding/json"
	"net/url"
	"time"

	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/pagination"
)

func hyperdriveConfigsPath(accountID string) string {
	return "/accounts/" + url.PathEscape(accountID) + "/hyperdrive/configs"
}

func hyperdriveConfigPath(accountID, configID string) string {
	return hyperdriveConfigsPath(accountID) + "/" + url.PathEscape(configID)
}

// cfHyperdrive mirrors the Hyperdrive configuration JSON shape.
type cfHyperdrive struct {
	ID                    string          `json:"id"`
	Name                  string          `json:"name"`
	Origin                json.RawMessage `json:"origin"`
	Caching               json.RawMessage `json:"caching"`
	OriginConnectionLimit int64           `json:"origin_connection_limit"`
	CreatedOn             time.Time       `json:"created_on"`
	ModifiedOn            time.Time       `json:"modified_on"`
}

func convertHyperdrive(cf cfHyperdrive) HyperdriveConfig {
	out := HyperdriveConfig{
		ID: cf.ID, Name: cf.Name,
		Origin: cf.Origin, Caching: cf.Caching,
		OriginConnectionLimit: cf.OriginConnectionLimit,
	}
	if len(out.Origin) > 0 && string(out.Origin) == "null" {
		out.Origin = nil
	}
	if len(out.Caching) > 0 && string(out.Caching) == "null" {
		out.Caching = nil
	}
	if !cf.CreatedOn.IsZero() {
		out.CreatedOn = cf.CreatedOn.UTC().Format(time.RFC3339)
	}
	if !cf.ModifiedOn.IsZero() {
		out.ModifiedOn = cf.ModifiedOn.UTC().Format(time.RFC3339)
	}
	return out
}

func decodeHyperdrive(env envelope) (HyperdriveConfig, error) {
	var cf cfHyperdrive
	if err := decodeResult(env, &cf); err != nil {
		return HyperdriveConfig{}, errors.Wrap(errors.CodeUnclassified, "decoding Hyperdrive response", err)
	}
	return convertHyperdrive(cf), nil
}

// ListHyperdriveConfigs lists Hyperdrive configurations (page pagination).
func (c *Client) ListHyperdriveConfigs(ctx context.Context, accountID string, pol pagination.Policy) (*ListResult[HyperdriveConfig], error) {
	lq := listQuery{path: hyperdriveConfigsPath(accountID), q: url.Values{}, pol: pol}
	if c.raw {
		return rawList[HyperdriveConfig](ctx, c, lq)
	}
	return listMapped[cfHyperdrive, HyperdriveConfig](ctx, c, lq, convertHyperdrive)
}

// GetHyperdriveConfig fetches one configuration.
func (c *Client) GetHyperdriveConfig(ctx context.Context, accountID, configID string) (*GetResult[HyperdriveConfig], error) {
	env, raw, err := c.requestJSON(ctx, "GET", hyperdriveConfigPath(accountID, configID), nil, nil, "")
	if err != nil {
		return nil, err
	}
	item, err := decodeHyperdrive(env)
	if err != nil {
		return nil, err
	}
	return &GetResult[HyperdriveConfig]{Item: item, RawBody: raw}, nil
}

// HyperdriveWrite is the write model shared by create (POST) and update
// (PATCH). Origin carries credentials and is always supplied by the caller
// as an already-parsed JSON object.
type HyperdriveWrite struct {
	Name                  *string
	Origin                json.RawMessage
	Caching               json.RawMessage
	OriginConnectionLimit *int64
}

func (w HyperdriveWrite) body() ([]byte, error) {
	inner := map[string]any{}
	if w.Name != nil {
		inner["name"] = *w.Name
	}
	if len(w.Origin) > 0 {
		inner["origin"] = w.Origin
	}
	if len(w.Caching) > 0 {
		inner["caching"] = w.Caching
	}
	if w.OriginConnectionLimit != nil {
		inner["origin_connection_limit"] = *w.OriginConnectionLimit
	}
	if len(inner) == 0 {
		return nil, errors.Usage("nothing to write")
	}
	return json.Marshal(map[string]any{"hyperdrive": inner})
}

// CreateHyperdriveConfig creates a configuration (POST; never auto-retried).
func (c *Client) CreateHyperdriveConfig(ctx context.Context, accountID string, w HyperdriveWrite) (*GetResult[HyperdriveConfig], error) {
	if w.Name == nil || *w.Name == "" {
		return nil, errors.Usage("--name is required")
	}
	if len(w.Origin) == 0 {
		return nil, errors.Usage("--origin is required (JSON object from @file)")
	}
	body, err := w.body()
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "POST", hyperdriveConfigsPath(accountID), nil, body, "application/json")
	if err != nil {
		return nil, err
	}
	item, err := decodeHyperdrive(env)
	if err != nil {
		return nil, err
	}
	return &GetResult[HyperdriveConfig]{Item: item, RawBody: raw}, nil
}

// UpdateHyperdriveConfig patches a configuration (PATCH, idempotent).
func (c *Client) UpdateHyperdriveConfig(ctx context.Context, accountID, configID string, w HyperdriveWrite) (*GetResult[HyperdriveConfig], error) {
	if w.Name == nil && len(w.Origin) == 0 && len(w.Caching) == 0 && w.OriginConnectionLimit == nil {
		return nil, errors.Usage("nothing to update; pass at least one of --name, --origin, --caching, --origin-connection-limit")
	}
	body, err := w.body()
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "PATCH", hyperdriveConfigPath(accountID, configID), nil, body, "application/json")
	if err != nil {
		return nil, err
	}
	item, err := decodeHyperdrive(env)
	if err != nil {
		return nil, err
	}
	return &GetResult[HyperdriveConfig]{Item: item, RawBody: raw}, nil
}

// DeleteHyperdriveConfig deletes a configuration (DELETE, idempotent).
func (c *Client) DeleteHyperdriveConfig(ctx context.Context, accountID, configID string) error {
	_, _, err := c.requestJSON(ctx, "DELETE", hyperdriveConfigPath(accountID, configID), nil, nil, "")
	return err
}
