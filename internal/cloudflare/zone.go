package cloudflare

import (
	"context"
	"net/url"
	"time"

	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/pagination"
)

// ZoneListQuery carries the supported server-side zone filters.
type ZoneListQuery struct {
	Name      string // exact zone name
	Status    string // initializing|pending|active|moved|deleted|deactivated
	Type      string // full|partial
	AccountID string // account.id filter; only applied when explicitly requested
}

// ListZones lists zones with server-side filtering and pagination.
func (c *Client) ListZones(ctx context.Context, q ZoneListQuery, pol pagination.Policy) (*ListResult[Zone], error) {
	query := url.Values{}
	if q.Name != "" {
		query.Set("name", q.Name)
	}
	if q.Status != "" {
		query.Set("status", q.Status)
	}
	if q.Type != "" {
		query.Set("type", q.Type)
	}
	if q.AccountID != "" {
		query.Set("account.id", q.AccountID)
	}
	lq := listQuery{path: "/zones", q: query, pol: pol}
	if c.raw {
		return rawList[Zone](ctx, c, lq)
	}
	return listMapped[cfZone, Zone](ctx, c, lq, convertZone)
}

// convertZone maps the Cloudflare-shaped zone into the normalized model.
func convertZone(cf cfZone) Zone {
	z := Zone{
		ID:                  cf.ID,
		Name:                cf.Name,
		Status:              cf.Status,
		Paused:              cf.Paused,
		Type:                cf.Type,
		AccountID:           cf.Account.ID,
		AccountName:         cf.Account.Name,
		NameServers:         cf.NameServers,
		OriginalNameServers: cf.OriginalNameServers,
	}
	if !cf.CreatedOn.IsZero() {
		z.CreatedOn = cf.CreatedOn.UTC().Format(time.RFC3339)
	}
	if !cf.ModifiedOn.IsZero() {
		z.ModifiedOn = cf.ModifiedOn.UTC().Format(time.RFC3339)
	}
	return z
}

// GetZone fetches one zone by ID.
func (c *Client) GetZone(ctx context.Context, zoneID string) (*GetResult[Zone], error) {
	if !validID(zoneID) {
		return nil, errors.Usage("invalid zone id %q (expected a 32-character hex id)", zoneID)
	}
	env, raw, err := c.requestJSON(ctx, "GET", "/zones/"+url.PathEscape(zoneID), nil, nil, "")
	if err != nil {
		return nil, err
	}
	item, err := decodeZone(env)
	if err != nil {
		return nil, err
	}
	return &GetResult[Zone]{Item: item, RawBody: raw}, nil
}

// decodeZone decodes a single-zone envelope into the normalized model.
func decodeZone(env envelope) (Zone, error) {
	var cf cfZone
	if err := decodeResult(env, &cf); err != nil {
		return Zone{}, errors.Wrap(errors.CodeUnclassified, "decoding zone response", err)
	}
	return convertZone(cf), nil
}

// cfZone mirrors the Cloudflare zone JSON shape for the fields FlareADM
// normalizes (the account object is nested upstream).
type cfZone struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Paused  bool   `json:"paused"`
	Type    string `json:"type"`
	Account struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"account"`
	NameServers         []string  `json:"name_servers"`
	OriginalNameServers []string  `json:"original_name_servers"`
	CreatedOn           time.Time `json:"created_on"`
	ModifiedOn          time.Time `json:"modified_on"`
}
