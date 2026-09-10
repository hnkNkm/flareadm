package cloudflare

import (
	"context"
	"encoding/json"
	"net/url"
	"time"

	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/pagination"
)

// TunnelConfigSrcValues are the accepted tunnel configuration sources.
var TunnelConfigSrcValues = []string{"local", "cloudflare"}

func tunnelPath(accountID string) string {
	return "/accounts/" + url.PathEscape(accountID) + "/cfd_tunnel"
}

func tunnelItemPath(accountID, tunnelID, suffix string) string {
	p := tunnelPath(accountID) + "/" + url.PathEscape(tunnelID)
	if suffix != "" {
		p += "/" + suffix
	}
	return p
}

// cfTunnel mirrors the tunnel JSON shape.
type cfTunnel struct {
	ID              string             `json:"id"`
	Name            string             `json:"name"`
	Status          string             `json:"status"`
	TunType         string             `json:"tun_type"`
	ConfigSrc       string             `json:"config_src"`
	RemoteConfig    bool               `json:"remote_config"`
	Connections     []TunnelConnection `json:"connections"`
	CreatedAt       time.Time          `json:"created_at"`
	DeletedAt       time.Time          `json:"deleted_at"`
	ConnsActiveAt   time.Time          `json:"conns_active_at"`
	ConnsInactiveAt time.Time          `json:"conns_inactive_at"`
}

func convertTunnel(cf cfTunnel) Tunnel {
	out := Tunnel{
		ID: cf.ID, Name: cf.Name, Status: cf.Status, Type: cf.TunType,
		ConfigSrc: cf.ConfigSrc, RemoteConfig: cf.RemoteConfig, Connections: cf.Connections,
	}
	if !cf.CreatedAt.IsZero() {
		out.CreatedAt = cf.CreatedAt.UTC().Format(time.RFC3339)
	}
	if !cf.DeletedAt.IsZero() {
		out.DeletedAt = cf.DeletedAt.UTC().Format(time.RFC3339)
	}
	if !cf.ConnsActiveAt.IsZero() {
		out.ConnsActiveAt = cf.ConnsActiveAt.UTC().Format(time.RFC3339)
	}
	if !cf.ConnsInactiveAt.IsZero() {
		out.ConnsInactiveAt = cf.ConnsInactiveAt.UTC().Format(time.RFC3339)
	}
	return out
}

// TunnelQuery carries the supported tunnel list filters.
type TunnelQuery struct {
	Name      string
	Status    string
	UUID      string
	IsDeleted bool
}

// ListTunnels lists cloudflared tunnels (page pagination).
func (c *Client) ListTunnels(ctx context.Context, accountID string, q TunnelQuery, pol pagination.Policy) (*ListResult[Tunnel], error) {
	query := url.Values{}
	if q.Name != "" {
		query.Set("name", q.Name)
	}
	if q.Status != "" {
		query.Set("status", q.Status)
	}
	if q.UUID != "" {
		query.Set("uuid", q.UUID)
	}
	if q.IsDeleted {
		query.Set("is_deleted", "true")
	}
	lq := listQuery{path: tunnelPath(accountID), q: query, pol: pol}
	if c.raw {
		return rawList[Tunnel](ctx, c, lq)
	}
	return listMapped[cfTunnel, Tunnel](ctx, c, lq, convertTunnel)
}

// GetTunnel fetches one tunnel.
func (c *Client) GetTunnel(ctx context.Context, accountID, tunnelID string) (*GetResult[Tunnel], error) {
	env, raw, err := c.requestJSON(ctx, "GET", tunnelItemPath(accountID, tunnelID, ""), nil, nil, "")
	if err != nil {
		return nil, err
	}
	var cf cfTunnel
	if err := decodeResult(env, &cf); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding tunnel response", err)
	}
	return &GetResult[Tunnel]{Item: convertTunnel(cf), RawBody: raw}, nil
}

// TunnelWrite is the create/update model. TunnelSecret carries a credential
// supplied via @file; it is nil when not provided.
type TunnelWrite struct {
	Name         *string
	ConfigSrc    *string
	TunnelSecret *string
}

func (w TunnelWrite) body() ([]byte, error) {
	body := map[string]any{}
	if w.Name != nil {
		body["name"] = *w.Name
	}
	if w.ConfigSrc != nil {
		body["config_src"] = *w.ConfigSrc
	}
	if w.TunnelSecret != nil {
		body["tunnel_secret"] = *w.TunnelSecret
	}
	if len(body) == 0 {
		return nil, errors.Usage("nothing to write")
	}
	return json.Marshal(body)
}

// CreateTunnel creates a tunnel (POST; never auto-retried).
func (c *Client) CreateTunnel(ctx context.Context, accountID string, w TunnelWrite) (*GetResult[Tunnel], error) {
	if w.Name == nil || *w.Name == "" {
		return nil, errors.Usage("--name is required")
	}
	body, err := w.body()
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "POST", tunnelPath(accountID), nil, body, "application/json")
	if err != nil {
		return nil, err
	}
	var cf cfTunnel
	if err := decodeResult(env, &cf); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding tunnel response", err)
	}
	return &GetResult[Tunnel]{Item: convertTunnel(cf), RawBody: raw}, nil
}

// UpdateTunnel patches a tunnel (PATCH, idempotent).
func (c *Client) UpdateTunnel(ctx context.Context, accountID, tunnelID string, w TunnelWrite) (*GetResult[Tunnel], error) {
	if w.Name == nil && w.TunnelSecret == nil {
		return nil, errors.Usage("nothing to update; pass at least one of --name, --tunnel-secret")
	}
	body, err := w.body()
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "PATCH", tunnelItemPath(accountID, tunnelID, ""), nil, body, "application/json")
	if err != nil {
		return nil, err
	}
	var cf cfTunnel
	if err := decodeResult(env, &cf); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding tunnel response", err)
	}
	return &GetResult[Tunnel]{Item: convertTunnel(cf), RawBody: raw}, nil
}

// DeleteTunnel deletes a tunnel (DELETE, idempotent).
func (c *Client) DeleteTunnel(ctx context.Context, accountID, tunnelID string) error {
	_, _, err := c.requestJSON(ctx, "DELETE", tunnelItemPath(accountID, tunnelID, ""), nil, nil, "")
	return err
}

// GetTunnelToken returns the tunnel token (a credential; callers must
// register it with ProtectSecret and print it only on explicit request).
func (c *Client) GetTunnelToken(ctx context.Context, accountID, tunnelID string) (*GetResult[string], error) {
	env, raw, err := c.requestJSON(ctx, "GET", tunnelItemPath(accountID, tunnelID, "token"), nil, nil, "")
	if err != nil {
		return nil, err
	}
	var token string
	if err := decodeResult(env, &token); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding tunnel token response", err)
	}
	return &GetResult[string]{Item: token, RawBody: raw}, nil
}

// ListTunnelConnections lists the active connector connections of a tunnel
// (single page: the endpoint is not paginated).
func (c *Client) ListTunnelConnections(ctx context.Context, accountID, tunnelID string) (*ListResult[TunnelConnection], error) {
	env, raw, err := c.requestJSON(ctx, "GET", tunnelItemPath(accountID, tunnelID, "connections"), nil, nil, "")
	if err != nil {
		return nil, err
	}
	if c.raw {
		return &ListResult[TunnelConnection]{RawBody: raw}, nil
	}
	var items []TunnelConnection
	if err := decodeResult(env, &items); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding tunnel connections", err)
	}
	return &ListResult[TunnelConnection]{Items: items}, nil
}

// DeleteTunnelConnection removes one connector connection by client id.
func (c *Client) DeleteTunnelConnection(ctx context.Context, accountID, tunnelID, clientID string) error {
	query := url.Values{}
	query.Set("client_id", clientID)
	_, _, err := c.requestJSON(ctx, "DELETE", tunnelItemPath(accountID, tunnelID, "connections"), query, nil, "")
	return err
}

// GetTunnelConfiguration reads the remote tunnel configuration.
func (c *Client) GetTunnelConfiguration(ctx context.Context, accountID, tunnelID string) (*GetResult[TunnelConfiguration], error) {
	env, raw, err := c.requestJSON(ctx, "GET", tunnelItemPath(accountID, tunnelID, "configurations"), nil, nil, "")
	if err != nil {
		return nil, err
	}
	var item TunnelConfiguration
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding tunnel configuration", err)
	}
	return &GetResult[TunnelConfiguration]{Item: item, RawBody: raw}, nil
}

// UpdateTunnelConfiguration replaces the remote tunnel configuration. The
// config payload is passed verbatim so unknown fields survive.
func (c *Client) UpdateTunnelConfiguration(ctx context.Context, accountID, tunnelID string, config json.RawMessage) (*GetResult[TunnelConfiguration], error) {
	if len(config) == 0 {
		return nil, errors.Usage("--config is required (JSON object from @file)")
	}
	body, err := json.Marshal(map[string]any{"config": config})
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "PUT", tunnelItemPath(accountID, tunnelID, "configurations"), nil, body, "application/json")
	if err != nil {
		return nil, err
	}
	var item TunnelConfiguration
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding tunnel configuration", err)
	}
	return &GetResult[TunnelConfiguration]{Item: item, RawBody: raw}, nil
}

// ---- private network routes (teamnet) -------------------------------------

func routePath(accountID, routeID string) string {
	p := "/accounts/" + url.PathEscape(accountID) + "/teamnet/routes"
	if routeID != "" {
		p += "/" + url.PathEscape(routeID)
	}
	return p
}

// TunnelRouteQuery carries the supported route list filters.
type TunnelRouteQuery struct {
	NetworkSubset string
	TunnelID      string
	Comment       string
	IsDeleted     bool
}

// ListTunnelRoutes lists private network routes (page pagination).
func (c *Client) ListTunnelRoutes(ctx context.Context, accountID string, q TunnelRouteQuery, pol pagination.Policy) (*ListResult[TunnelRoute], error) {
	query := url.Values{}
	if q.NetworkSubset != "" {
		query.Set("network_subset", q.NetworkSubset)
	}
	if q.TunnelID != "" {
		query.Set("tunnel_id", q.TunnelID)
	}
	if q.Comment != "" {
		query.Set("comment", q.Comment)
	}
	if q.IsDeleted {
		query.Set("is_deleted", "true")
	}
	lq := listQuery{path: routePath(accountID, ""), q: query, pol: pol}
	if c.raw {
		return rawList[TunnelRoute](ctx, c, lq)
	}
	return listTyped[TunnelRoute](ctx, c, lq)
}

// GetTunnelRoute fetches one route.
func (c *Client) GetTunnelRoute(ctx context.Context, accountID, routeID string) (*GetResult[TunnelRoute], error) {
	env, raw, err := c.requestJSON(ctx, "GET", routePath(accountID, routeID), nil, nil, "")
	if err != nil {
		return nil, err
	}
	var item TunnelRoute
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding route response", err)
	}
	return &GetResult[TunnelRoute]{Item: item, RawBody: raw}, nil
}

// TunnelRouteWrite is the create model.
type TunnelRouteWrite struct {
	Network          string
	TunnelID         string
	Comment          string
	VirtualNetworkID string
}

// CreateTunnelRoute creates a private network route (POST).
func (c *Client) CreateTunnelRoute(ctx context.Context, accountID string, w TunnelRouteWrite) (*GetResult[TunnelRoute], error) {
	if w.Network == "" {
		return nil, errors.Usage("--network is required")
	}
	if w.TunnelID == "" {
		return nil, errors.Usage("--tunnel-id is required")
	}
	body := map[string]any{"network": w.Network, "tunnel_id": w.TunnelID}
	if w.Comment != "" {
		body["comment"] = w.Comment
	}
	if w.VirtualNetworkID != "" {
		body["virtual_network_id"] = w.VirtualNetworkID
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	env, respRaw, err := c.requestJSON(ctx, "POST", routePath(accountID, ""), nil, raw, "application/json")
	if err != nil {
		return nil, err
	}
	var item TunnelRoute
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding route response", err)
	}
	return &GetResult[TunnelRoute]{Item: item, RawBody: respRaw}, nil
}

// TunnelRouteEdit carries the update overrides (PATCH).
type TunnelRouteEdit struct {
	Network          *string
	TunnelID         *string
	Comment          *string
	VirtualNetworkID *string
}

// UpdateTunnelRoute patches a route (idempotent).
func (c *Client) UpdateTunnelRoute(ctx context.Context, accountID, routeID string, up TunnelRouteEdit) (*GetResult[TunnelRoute], error) {
	body := map[string]any{}
	if up.Network != nil {
		body["network"] = *up.Network
	}
	if up.TunnelID != nil {
		body["tunnel_id"] = *up.TunnelID
	}
	if up.Comment != nil {
		body["comment"] = *up.Comment
	}
	if up.VirtualNetworkID != nil {
		body["virtual_network_id"] = *up.VirtualNetworkID
	}
	if len(body) == 0 {
		return nil, errors.Usage("nothing to update; pass at least one of --network, --tunnel-id, --comment, --virtual-network-id")
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	env, respRaw, err := c.requestJSON(ctx, "PATCH", routePath(accountID, routeID), nil, raw, "application/json")
	if err != nil {
		return nil, err
	}
	var item TunnelRoute
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding route response", err)
	}
	return &GetResult[TunnelRoute]{Item: item, RawBody: respRaw}, nil
}

// DeleteTunnelRoute deletes a route (DELETE, idempotent).
func (c *Client) DeleteTunnelRoute(ctx context.Context, accountID, routeID string) error {
	_, _, err := c.requestJSON(ctx, "DELETE", routePath(accountID, routeID), nil, nil, "")
	return err
}

// ---- Zero Trust organization ----------------------------------------------

func organizationPath(accountID string) string {
	return "/accounts/" + url.PathEscape(accountID) + "/access/organizations"
}

// GetZeroTrustOrganization reads the account Zero Trust organization.
func (c *Client) GetZeroTrustOrganization(ctx context.Context, accountID string) (*GetResult[ZeroTrustOrganization], error) {
	env, raw, err := c.requestJSON(ctx, "GET", organizationPath(accountID), nil, nil, "")
	if err != nil {
		return nil, err
	}
	var item ZeroTrustOrganization
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding organization response", err)
	}
	return &GetResult[ZeroTrustOrganization]{Item: item, RawBody: raw}, nil
}

// UpdateZeroTrustOrganization applies the overrides onto the current
// organization (read-modify-PUT) so unmapped fields are preserved.
func (c *Client) UpdateZeroTrustOrganization(ctx context.Context, accountID string, overrides map[string]any) (*GetResult[ZeroTrustOrganization], error) {
	if len(overrides) == 0 {
		return nil, errors.Usage("nothing to update; pass at least one organization field")
	}
	env, _, err := c.requestJSON(ctx, "GET", organizationPath(accountID), nil, nil, "")
	if err != nil {
		return nil, err
	}
	var current map[string]any
	if err := json.Unmarshal(env.Result, &current); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding existing organization", err)
	}
	for k, v := range overrides {
		current[k] = v
	}
	body, err := json.Marshal(current)
	if err != nil {
		return nil, err
	}
	putEnv, raw, err := c.requestJSON(ctx, "PUT", organizationPath(accountID), nil, body, "application/json")
	if err != nil {
		return nil, err
	}
	var item ZeroTrustOrganization
	if err := decodeResult(putEnv, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding organization response", err)
	}
	return &GetResult[ZeroTrustOrganization]{Item: item, RawBody: raw}, nil
}
