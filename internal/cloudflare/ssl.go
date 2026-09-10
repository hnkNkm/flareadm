package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/pagination"
)

// SSLSettingsIDs are the zone settings that make up the SSL/TLS surface
// exposed by `ssl setting` (Cloudflare zone settings endpoints).
var SSLSettingsIDs = []string{
	"always_use_https",
	"automatic_https_rewrites",
	"min_tls_version",
	"opportunistic_encryption",
	"ssl",
	"tls_1_3",
}

// SSLSettingsAllowed maps each setting id to its accepted values, used for
// client-side validation of `ssl setting update`.
var SSLSettingsAllowed = map[string][]string{
	"always_use_https":         {"on", "off"},
	"automatic_https_rewrites": {"on", "off"},
	"min_tls_version":          {"1.0", "1.1", "1.2", "1.3"},
	"opportunistic_encryption": {"on", "off"},
	"ssl":                      {"off", "flexible", "full", "strict"},
	"tls_1_3":                  {"on", "off"},
}

// cfSetting mirrors the zone setting JSON shape (the value may be a string,
// a boolean or an object depending on the setting).
type cfSetting struct {
	ID         string          `json:"id"`
	Value      json.RawMessage `json:"value"`
	Editable   bool            `json:"editable"`
	ModifiedOn time.Time       `json:"modified_on"`
}

// settingValueString renders a setting value as text: strings verbatim,
// other JSON compactly.
func settingValueString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return string(raw)
	}
	return buf.String()
}

func convertSetting(cf cfSetting) SSLSetting {
	out := SSLSetting{ID: cf.ID, Value: settingValueString(cf.Value), Editable: cf.Editable}
	if !cf.ModifiedOn.IsZero() {
		out.ModifiedOn = cf.ModifiedOn.UTC().Format(time.RFC3339)
	}
	return out
}

// ListSSLSettings reads the SSL/TLS zone settings. When name is non-empty
// only that setting is fetched.
func (c *Client) ListSSLSettings(ctx context.Context, zoneID, name string) (*ListResult[SSLSetting], error) {
	ids := SSLSettingsIDs
	if name != "" {
		if !containsString(SSLSettingsIDs, name) {
			return nil, errors.Usage("unknown SSL setting %q (supported: %s)", name, joinSorted(SSLSettingsIDs))
		}
		ids = []string{name}
	}
	items := make([]SSLSetting, 0, len(ids))
	var bodies [][]byte
	for _, id := range ids {
		env, raw, err := c.requestJSON(ctx, "GET", zoneSettingPath(zoneID, id), nil, nil, "")
		if err != nil {
			return nil, err
		}
		var cf cfSetting
		if err := decodeResult(env, &cf); err != nil {
			return nil, errors.Wrap(errors.CodeUnclassified, "decoding SSL setting response", err)
		}
		items = append(items, convertSetting(cf))
		bodies = append(bodies, raw)
	}
	if c.raw {
		merged, err := mergeSingleResults(bodies)
		if err != nil {
			return nil, err
		}
		return &ListResult[SSLSetting]{RawBody: merged}, nil
	}
	return &ListResult[SSLSetting]{Items: items}, nil
}

// UpdateSSLSettings patches the given setting id -> value pairs (sorted for
// determinism). If a later patch fails after earlier ones were applied the
// error carries exit code 9 (partial failure).
func (c *Client) UpdateSSLSettings(ctx context.Context, zoneID string, values map[string]string) (*ListResult[SSLSetting], error) {
	ids := make([]string, 0, len(values))
	for id := range values {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	items := make([]SSLSetting, 0, len(ids))
	var bodies [][]byte
	for i, id := range ids {
		allowed, ok := SSLSettingsAllowed[id]
		if !ok {
			return nil, errors.Usage("unknown SSL setting %q (supported: %s)", id, joinSorted(SSLSettingsIDs))
		}
		if !containsString(allowed, values[id]) {
			return nil, errors.Usage("invalid value %q for SSL setting %s (supported: %s)", values[id], id, joinSorted(allowed))
		}
		body, err := json.Marshal(map[string]string{"value": values[id]})
		if err != nil {
			return nil, err
		}
		env, raw, err := c.requestJSON(ctx, "PATCH", zoneSettingPath(zoneID, id), nil, body, "application/json")
		if err != nil {
			if i > 0 {
				return nil, errors.Wrap(errors.CodePartial,
					fmt.Sprintf("partially applied: %d of %d SSL settings were updated before %s failed", i, len(ids), id), err)
			}
			return nil, err
		}
		var cf cfSetting
		if err := decodeResult(env, &cf); err != nil {
			return nil, errors.Wrap(errors.CodeUnclassified, "decoding SSL setting response", err)
		}
		items = append(items, convertSetting(cf))
		bodies = append(bodies, raw)
	}
	if c.raw {
		merged, err := mergeSingleResults(bodies)
		if err != nil {
			return nil, err
		}
		return &ListResult[SSLSetting]{RawBody: merged}, nil
	}
	return &ListResult[SSLSetting]{Items: items}, nil
}

// zoneSettingPath builds /zones/{zone}/settings/{setting}.
func zoneSettingPath(zoneID, setting string) string {
	return "/zones/" + url.PathEscape(zoneID) + "/settings/" + url.PathEscape(setting)
}

// GetUniversalSSL reads the zone Universal SSL setting.
func (c *Client) GetUniversalSSL(ctx context.Context, zoneID string) (*GetResult[UniversalSSL], error) {
	env, raw, err := c.requestJSON(ctx, "GET", universalSSLPath(zoneID), nil, nil, "")
	if err != nil {
		return nil, err
	}
	var item UniversalSSL
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding Universal SSL response", err)
	}
	return &GetResult[UniversalSSL]{Item: item, RawBody: raw}, nil
}

// SetUniversalSSL enables or disables Universal SSL for the zone.
func (c *Client) SetUniversalSSL(ctx context.Context, zoneID string, enabled bool) (*GetResult[UniversalSSL], error) {
	body, err := json.Marshal(map[string]bool{"enabled": enabled})
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "PATCH", universalSSLPath(zoneID), nil, body, "application/json")
	if err != nil {
		return nil, err
	}
	var item UniversalSSL
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding Universal SSL response", err)
	}
	return &GetResult[UniversalSSL]{Item: item, RawBody: raw}, nil
}

func universalSSLPath(zoneID string) string {
	return "/zones/" + url.PathEscape(zoneID) + "/ssl/universal/settings"
}

// CertificatePackQuery carries the supported certificate pack filters.
type CertificatePackQuery struct {
	Status string // pass-through (the SDK only enumerates "all")
	Deploy string // staging|production
}

// ListCertificatePacks lists zone certificate packs.
func (c *Client) ListCertificatePacks(ctx context.Context, zoneID string, q CertificatePackQuery, pol pagination.Policy) (*ListResult[CertificatePack], error) {
	query := url.Values{}
	if q.Status != "" {
		query.Set("status", q.Status)
	}
	if q.Deploy != "" {
		query.Set("deploy", q.Deploy)
	}
	lq := listQuery{path: "/zones/" + url.PathEscape(zoneID) + "/ssl/certificate_packs", q: query, pol: pol}
	if c.raw {
		return rawList[CertificatePack](ctx, c, lq)
	}
	return listTyped[CertificatePack](ctx, c, lq)
}

// GetCertificatePack fetches one certificate pack.
func (c *Client) GetCertificatePack(ctx context.Context, zoneID, packID string) (*GetResult[CertificatePack], error) {
	path := "/zones/" + url.PathEscape(zoneID) + "/ssl/certificate_packs/" + url.PathEscape(packID)
	env, raw, err := c.requestJSON(ctx, "GET", path, nil, nil, "")
	if err != nil {
		return nil, err
	}
	var item CertificatePack
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding certificate pack response", err)
	}
	return &GetResult[CertificatePack]{Item: item, RawBody: raw}, nil
}

// mergeSingleResults combines raw single-object API responses into one
// Cloudflare-shaped envelope; a single body is returned byte-for-byte.
func mergeSingleResults(bodies [][]byte) ([]byte, error) {
	if len(bodies) == 0 {
		return nil, nil
	}
	if len(bodies) == 1 {
		return bodies[0], nil
	}
	out := rawListEnvelope{Success: true, Errors: []json.RawMessage{}, Messages: []json.RawMessage{}}
	for _, body := range bodies {
		var env envelope
		if err := json.Unmarshal(body, &env); err != nil {
			return nil, err
		}
		if len(env.Result) > 0 {
			out.Result = append(out.Result, env.Result)
		}
	}
	return json.MarshalIndent(out, "", "  ")
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// joinSorted renders candidate values deterministically for error messages.
func joinSorted(list []string) string {
	sorted := append([]string(nil), list...)
	sort.Strings(sorted)
	return strings.Join(sorted, ", ")
}
