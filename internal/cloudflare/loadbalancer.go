package cloudflare

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/pagination"
)

// LoadBalancerMonitorTypeValues are the accepted monitor probe types.
var LoadBalancerMonitorTypeValues = []string{"http", "https", "tcp", "udp_icmp", "icmp_ping", "smtp"}

// lbBase returns the account-or-zone prefix used by load balancer endpoints.
func lbBase(accountID, zoneID string) (string, error) {
	switch {
	case accountID != "" && zoneID != "":
		return "", errors.Usage("account and zone scope are mutually exclusive")
	case accountID != "":
		return "/accounts/" + url.PathEscape(accountID), nil
	case zoneID != "":
		return "/zones/" + url.PathEscape(zoneID), nil
	default:
		return "", errors.Usage("either an account or a zone is required")
	}
}

func loadBalancersPath(accountID, zoneID, lbID string) (string, error) {
	base, err := lbBase(accountID, zoneID)
	if err != nil {
		return "", err
	}
	p := base + "/load_balancers"
	if lbID != "" {
		p += "/" + url.PathEscape(lbID)
	}
	return p, nil
}

func poolsPath(accountID, poolID, suffix string) string {
	p := "/accounts/" + url.PathEscape(accountID) + "/load_balancers/pools"
	if poolID != "" {
		p += "/" + url.PathEscape(poolID)
	}
	if suffix != "" {
		p += "/" + suffix
	}
	return p
}

func monitorsPath(accountID, monitorID string) string {
	p := "/accounts/" + url.PathEscape(accountID) + "/load_balancers/monitors"
	if monitorID != "" {
		p += "/" + url.PathEscape(monitorID)
	}
	return p
}

// mergePatch applies overrides with PATCH (partial update: only the provided
// fields change, so unmodeled fields are untouched by construction).
func mergePatch[T any](ctx context.Context, c *Client, path string, overrides map[string]any) (*GetResult[T], error) {
	if len(overrides) == 0 {
		return nil, errors.Usage("nothing to update")
	}
	payload, err := json.Marshal(overrides)
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "PATCH", path, nil, payload, "application/json")
	if err != nil {
		return nil, err
	}
	var item T
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding response", err)
	}
	return &GetResult[T]{Item: item, RawBody: raw}, nil
}

// ListLoadBalancers lists load balancers (account or zone scoped).
func (c *Client) ListLoadBalancers(ctx context.Context, accountID, zoneID string, pol pagination.Policy) (*ListResult[LoadBalancer], error) {
	path, err := loadBalancersPath(accountID, zoneID, "")
	if err != nil {
		return nil, err
	}
	return singlePageList[LoadBalancer](ctx, c, path, nil, pol)
}

// GetLoadBalancer fetches one load balancer.
func (c *Client) GetLoadBalancer(ctx context.Context, accountID, zoneID, lbID string) (*GetResult[LoadBalancer], error) {
	path, err := loadBalancersPath(accountID, zoneID, lbID)
	if err != nil {
		return nil, err
	}
	return accessGet[LoadBalancer](ctx, c, path)
}

// CreateLoadBalancer creates a load balancer (POST).
func (c *Client) CreateLoadBalancer(ctx context.Context, accountID, zoneID string, body map[string]any) (*GetResult[LoadBalancer], error) {
	path, err := loadBalancersPath(accountID, zoneID, "")
	if err != nil {
		return nil, err
	}
	if _, ok := body["name"]; !ok {
		return nil, errors.Usage("--name is required")
	}
	if _, ok := body["default_pools"]; !ok {
		return nil, errors.Usage("--default-pools is required")
	}
	if _, ok := body["fallback_pool"]; !ok {
		return nil, errors.Usage("--fallback-pool is required")
	}
	return accessCreate[LoadBalancer](ctx, c, path, body)
}

// UpdateLoadBalancer partially updates a load balancer (PATCH).
func (c *Client) UpdateLoadBalancer(ctx context.Context, accountID, zoneID, lbID string, overrides map[string]any) (*GetResult[LoadBalancer], error) {
	path, err := loadBalancersPath(accountID, zoneID, lbID)
	if err != nil {
		return nil, err
	}
	return mergePatch[LoadBalancer](ctx, c, path, overrides)
}

// DeleteLoadBalancer deletes a load balancer (DELETE, idempotent).
func (c *Client) DeleteLoadBalancer(ctx context.Context, accountID, zoneID, lbID string) error {
	path, err := loadBalancersPath(accountID, zoneID, lbID)
	if err != nil {
		return err
	}
	return accessDelete(ctx, c, path)
}

// ListLoadBalancerPools lists origin pools (not paginated).
func (c *Client) ListLoadBalancerPools(ctx context.Context, accountID, monitorID string, pol pagination.Policy) (*ListResult[LoadBalancerPool], error) {
	query := url.Values{}
	if monitorID != "" {
		query.Set("monitor", monitorID)
	}
	return singlePageList[LoadBalancerPool](ctx, c, poolsPath(accountID, "", ""), query, pol)
}

// GetLoadBalancerPool fetches one pool.
func (c *Client) GetLoadBalancerPool(ctx context.Context, accountID, poolID string) (*GetResult[LoadBalancerPool], error) {
	return accessGet[LoadBalancerPool](ctx, c, poolsPath(accountID, poolID, ""))
}

// CreateLoadBalancerPool creates a pool (POST).
func (c *Client) CreateLoadBalancerPool(ctx context.Context, accountID string, body map[string]any) (*GetResult[LoadBalancerPool], error) {
	if _, ok := body["name"]; !ok {
		return nil, errors.Usage("--name is required")
	}
	if _, ok := body["origins"]; !ok {
		return nil, errors.Usage("--origins is required")
	}
	return accessCreate[LoadBalancerPool](ctx, c, poolsPath(accountID, "", ""), body)
}

// UpdateLoadBalancerPool partially updates a pool (PATCH).
func (c *Client) UpdateLoadBalancerPool(ctx context.Context, accountID, poolID string, overrides map[string]any) (*GetResult[LoadBalancerPool], error) {
	return mergePatch[LoadBalancerPool](ctx, c, poolsPath(accountID, poolID, ""), overrides)
}

// DeleteLoadBalancerPool deletes a pool (DELETE, idempotent).
func (c *Client) DeleteLoadBalancerPool(ctx context.Context, accountID, poolID string) error {
	return accessDelete(ctx, c, poolsPath(accountID, poolID, ""))
}

// GetLoadBalancerPoolHealth reads the health of a pool's origins.
func (c *Client) GetLoadBalancerPoolHealth(ctx context.Context, accountID, poolID string) (*GetResult[json.RawMessage], error) {
	env, raw, err := c.requestJSON(ctx, "GET", poolsPath(accountID, poolID, "health"), nil, nil, "")
	if err != nil {
		return nil, err
	}
	return &GetResult[json.RawMessage]{Item: env.Result, RawBody: raw}, nil
}

// ListLoadBalancerMonitors lists monitors (not paginated).
func (c *Client) ListLoadBalancerMonitors(ctx context.Context, accountID string, pol pagination.Policy) (*ListResult[LoadBalancerMonitor], error) {
	return singlePageList[LoadBalancerMonitor](ctx, c, monitorsPath(accountID, ""), nil, pol)
}

// GetLoadBalancerMonitor fetches one monitor.
func (c *Client) GetLoadBalancerMonitor(ctx context.Context, accountID, monitorID string) (*GetResult[LoadBalancerMonitor], error) {
	return accessGet[LoadBalancerMonitor](ctx, c, monitorsPath(accountID, monitorID))
}

// CreateLoadBalancerMonitor creates a monitor (POST).
func (c *Client) CreateLoadBalancerMonitor(ctx context.Context, accountID string, body map[string]any) (*GetResult[LoadBalancerMonitor], error) {
	if _, ok := body["type"]; !ok {
		return nil, errors.Usage("--type is required")
	}
	return accessCreate[LoadBalancerMonitor](ctx, c, monitorsPath(accountID, ""), body)
}

// UpdateLoadBalancerMonitor partially updates a monitor (PATCH).
func (c *Client) UpdateLoadBalancerMonitor(ctx context.Context, accountID, monitorID string, overrides map[string]any) (*GetResult[LoadBalancerMonitor], error) {
	return mergePatch[LoadBalancerMonitor](ctx, c, monitorsPath(accountID, monitorID), overrides)
}

// DeleteLoadBalancerMonitor deletes a monitor (DELETE, idempotent).
func (c *Client) DeleteLoadBalancerMonitor(ctx context.Context, accountID, monitorID string) error {
	return accessDelete(ctx, c, monitorsPath(accountID, monitorID))
}

// ListLoadBalancerRegions lists regions. The API response is untyped, so the
// raw JSON objects are returned.
func (c *Client) ListLoadBalancerRegions(ctx context.Context, accountID string, pol pagination.Policy) (*ListResult[json.RawMessage], error) {
	return singlePageList[json.RawMessage](ctx, c, "/accounts/"+url.PathEscape(accountID)+"/load_balancers/regions", nil, pol)
}

// GetLoadBalancerRegion fetches one region (untyped response).
func (c *Client) GetLoadBalancerRegion(ctx context.Context, accountID, regionID string) (*GetResult[json.RawMessage], error) {
	env, raw, err := c.requestJSON(ctx, "GET", "/accounts/"+url.PathEscape(accountID)+"/load_balancers/regions/"+url.PathEscape(regionID), nil, nil, "")
	if err != nil {
		return nil, err
	}
	return &GetResult[json.RawMessage]{Item: env.Result, RawBody: raw}, nil
}
