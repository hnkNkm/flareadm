package cloudflare

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/pagination"
)

// CertificateQuery carries the supported custom certificate filters.
type CertificateQuery struct {
	Status string // active|expired|deleted|pending|initializing
}

// CertificateCreateParams is the write model for uploading a custom
// certificate.
type CertificateCreateParams struct {
	Certificate  string // PEM bundle
	PrivateKey   string // PEM private key (never logged or echoed)
	BundleMethod string // ubiquitous|optimal|force
	Deploy       string // staging|production
	Type         string // legacy_custom|sni_custom
}

// customCertificatePath builds /zones/{zone}/certificates[/{id}].
func customCertificatePath(zoneID, certID string) string {
	p := "/zones/" + url.PathEscape(zoneID) + "/certificates"
	if certID != "" {
		p += "/" + url.PathEscape(certID)
	}
	return p
}

// ListCertificates lists zone custom certificates.
func (c *Client) ListCertificates(ctx context.Context, zoneID string, q CertificateQuery, pol pagination.Policy) (*ListResult[Certificate], error) {
	query := url.Values{}
	if q.Status != "" {
		query.Set("status", q.Status)
	}
	lq := listQuery{path: customCertificatePath(zoneID, ""), q: query, pol: pol}
	if c.raw {
		return rawList[Certificate](ctx, c, lq)
	}
	return listTyped[Certificate](ctx, c, lq)
}

// GetCertificate fetches one zone custom certificate.
func (c *Client) GetCertificate(ctx context.Context, zoneID, certID string) (*GetResult[Certificate], error) {
	env, raw, err := c.requestJSON(ctx, "GET", customCertificatePath(zoneID, certID), nil, nil, "")
	if err != nil {
		return nil, err
	}
	var item Certificate
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding certificate response", err)
	}
	return &GetResult[Certificate]{Item: item, RawBody: raw}, nil
}

// CreateCertificate uploads a custom certificate (POST; never automatically
// retried).
func (c *Client) CreateCertificate(ctx context.Context, zoneID string, p CertificateCreateParams) (*GetResult[Certificate], error) {
	if p.Certificate == "" {
		return nil, errors.Usage("a certificate PEM is required (--certificate)")
	}
	body := map[string]any{"certificate": p.Certificate}
	if p.PrivateKey != "" {
		body["private_key"] = p.PrivateKey
	}
	if p.BundleMethod != "" {
		body["bundle_method"] = p.BundleMethod
	}
	if p.Deploy != "" {
		body["deploy"] = p.Deploy
	}
	if p.Type != "" {
		body["type"] = p.Type
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	env, respRaw, err := c.requestJSON(ctx, "POST", customCertificatePath(zoneID, ""), nil, raw, "application/json")
	if err != nil {
		return nil, err
	}
	var item Certificate
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding certificate response", err)
	}
	return &GetResult[Certificate]{Item: item, RawBody: respRaw}, nil
}

// DeleteCertificate deletes a zone custom certificate (DELETE, idempotent).
func (c *Client) DeleteCertificate(ctx context.Context, zoneID, certID string) error {
	_, _, err := c.requestJSON(ctx, "DELETE", customCertificatePath(zoneID, certID), nil, nil, "")
	return err
}
