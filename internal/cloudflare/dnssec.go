package cloudflare

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/hnkNkm/flareadm/internal/errors"
)

// DNSSEC statuses accepted by SetDNSSECStatus.
const (
	DNSSECStatusActive   = "active"
	DNSSECStatusDisabled = "disabled"
)

// dnssecPath builds /zones/{zone}/dnssec.
func dnssecPath(zoneID string) string {
	return "/zones/" + url.PathEscape(zoneID) + "/dnssec"
}

// GetDNSSEC returns the DNSSEC status of a zone.
func (c *Client) GetDNSSEC(ctx context.Context, zoneID string) (*GetResult[DNSSEC], error) {
	env, raw, err := c.requestJSON(ctx, "GET", dnssecPath(zoneID), nil, nil, "")
	if err != nil {
		return nil, err
	}
	var item DNSSEC
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding dnssec response", err)
	}
	return &GetResult[DNSSEC]{Item: item, RawBody: raw}, nil
}

// SetDNSSECStatus enables or disables DNSSEC for a zone (PATCH).
func (c *Client) SetDNSSECStatus(ctx context.Context, zoneID, status string) (*GetResult[DNSSEC], error) {
	if status != DNSSECStatusActive && status != DNSSECStatusDisabled {
		return nil, errors.Usage("invalid dnssec status %q (supported: active, disabled)", status)
	}
	body, err := json.Marshal(map[string]string{"status": status})
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "PATCH", dnssecPath(zoneID), nil, body, "application/json")
	if err != nil {
		return nil, err
	}
	var item DNSSEC
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding dnssec response", err)
	}
	return &GetResult[DNSSEC]{Item: item, RawBody: raw}, nil
}
