package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/url"

	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/pagination"
)

// RecordListQuery carries the supported server-side DNS record filters.
type RecordListQuery struct {
	Name    string // exact record name
	Type    string // record type (A, AAAA, ...)
	Content string // exact content match
}

// ListRecords lists DNS records of a zone.
func (c *Client) ListRecords(ctx context.Context, zoneID string, q RecordListQuery, pol pagination.Policy) (*ListResult[DNSRecord], error) {
	query := url.Values{}
	if q.Name != "" {
		query.Set("name", q.Name)
	}
	if q.Type != "" {
		query.Set("type", q.Type)
	}
	if q.Content != "" {
		query.Set("content", q.Content)
	}
	lq := listQuery{path: "/zones/" + url.PathEscape(zoneID) + "/dns_records", q: query, pol: pol}
	if c.raw {
		return rawList[DNSRecord](ctx, c, lq)
	}
	return listTyped[DNSRecord](ctx, c, lq)
}

// GetRecord fetches one DNS record.
func (c *Client) GetRecord(ctx context.Context, zoneID, recordID string) (*GetResult[DNSRecord], error) {
	env, raw, err := c.requestJSON(ctx, "GET", recordPath(zoneID, recordID), nil, nil, "")
	if err != nil {
		return nil, err
	}
	item, err := decodeRecord(env)
	if err != nil {
		return nil, err
	}
	return &GetResult[DNSRecord]{Item: item, RawBody: raw}, nil
}

// recordPath builds /zones/{zone}/dns_records[/{record}].
func recordPath(zoneID, recordID string) string {
	p := "/zones/" + url.PathEscape(zoneID) + "/dns_records"
	if recordID != "" {
		p += "/" + url.PathEscape(recordID)
	}
	return p
}

// decodeRecord decodes one record envelope into the normalized model.
func decodeRecord(env envelope) (DNSRecord, error) {
	var r DNSRecord
	if err := decodeResult(env, &r); err != nil {
		return DNSRecord{}, errors.Wrap(errors.CodeUnclassified, "decoding DNS record response", err)
	}
	normalizeRecord(&r)
	return r, nil
}

// normalizeRecord post-processes a decoded record.
func normalizeRecord(r *DNSRecord) {
	// Records without data (A, TXT, ...) should not surface "data": {}.
	if len(r.Data) == 0 || string(r.Data) == "{}" || string(r.Data) == "null" {
		r.Data = nil
	}
	if r.Tags == nil {
		r.Tags = []string{}
	}
}

// RecordWrite is the full write model for record create/update. Proxied and
// Priority are pointers so "unset" is distinguishable from an explicit
// value.
type RecordWrite struct {
	Name     string
	Type     string
	Content  string
	TTL      float64
	Proxied  *bool
	Priority *float64
	Comment  *string
}

// proxiableTypes are the record types that accept the proxied flag.
var proxiableTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true}

// wireRecord is the JSON body sent to the API.
type wireRecord struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Content  string   `json:"content,omitempty"`
	TTL      float64  `json:"ttl"`
	Proxied  *bool    `json:"proxied,omitempty"`
	Priority *float64 `json:"priority,omitempty"`
	Comment  *string  `json:"comment,omitempty"`
}

// marshalRecordWrite validates and serializes a record write body.
func marshalRecordWrite(rw RecordWrite) ([]byte, error) {
	if rw.Name == "" {
		return nil, errors.Usage("record name is required")
	}
	if rw.Type == "" {
		return nil, errors.Usage("record type is required")
	}
	if rw.Content == "" {
		return nil, errors.Usage("record content is required")
	}
	if rw.TTL <= 0 {
		return nil, errors.Usage("record ttl must be 1 (automatic) or between 60 and 86400")
	}
	w := wireRecord{Name: rw.Name, Type: rw.Type, Content: rw.Content, TTL: rw.TTL}
	if proxiableTypes[rw.Type] && rw.Proxied != nil {
		w.Proxied = rw.Proxied
	}
	if rw.Priority != nil && *rw.Priority > 0 {
		w.Priority = rw.Priority
	}
	if rw.Comment != nil && *rw.Comment != "" {
		w.Comment = rw.Comment
	}
	return json.Marshal(w)
}

// CreateRecord creates a DNS record (POST; never automatically retried).
func (c *Client) CreateRecord(ctx context.Context, zoneID string, rw RecordWrite) (*GetResult[DNSRecord], error) {
	body, err := marshalRecordWrite(rw)
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "POST", recordPath(zoneID, ""), nil, body, "application/json")
	if err != nil {
		return nil, err
	}
	item, err := decodeRecord(env)
	if err != nil {
		return nil, err
	}
	return &GetResult[DNSRecord]{Item: item, RawBody: raw}, nil
}

// UpdateRecord overwrites a DNS record (PUT, idempotent).
func (c *Client) UpdateRecord(ctx context.Context, zoneID, recordID string, rw RecordWrite) (*GetResult[DNSRecord], error) {
	body, err := marshalRecordWrite(rw)
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "PUT", recordPath(zoneID, recordID), nil, body, "application/json")
	if err != nil {
		return nil, err
	}
	item, err := decodeRecord(env)
	if err != nil {
		return nil, err
	}
	return &GetResult[DNSRecord]{Item: item, RawBody: raw}, nil
}

// DeleteRecord deletes a DNS record (DELETE, idempotent).
func (c *Client) DeleteRecord(ctx context.Context, zoneID, recordID string) error {
	_, _, err := c.requestJSON(ctx, "DELETE", recordPath(zoneID, recordID), nil, nil, "")
	return err
}

// ExportRecords returns the zone's records as BIND zone text.
func (c *Client) ExportRecords(ctx context.Context, zoneID string) ([]byte, error) {
	return c.do(ctx, "GET", recordPath(zoneID, "")+"/export", nil, nil, "")
}

// ImportRecords uploads a BIND zone file (multipart, POST). proxied, when
// non-nil, requests proxying for proxiable imported records. The file part
// follows the shape of the generated SDK's import request (a multipart
// "file" field carrying the BIND text).
func (c *Client) ImportRecords(ctx context.Context, zoneID string, file []byte, proxied *bool) (*ImportResult, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField("file", string(file)); err != nil {
		return nil, err
	}
	if proxied != nil {
		v := "false"
		if *proxied {
			v = "true"
		}
		if err := w.WriteField("proxied", v); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}

	env, _, err := c.requestJSON(ctx, "POST", recordPath(zoneID, "")+"/import", nil, buf.Bytes(), w.FormDataContentType())
	if err != nil {
		return nil, err
	}
	var res ImportResult
	if err := decodeResult(env, &res); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding import response", err)
	}
	return &res, nil
}

// ProxiableType reports whether t accepts the proxied flag.
func ProxiableType(t string) bool { return proxiableTypes[t] }
