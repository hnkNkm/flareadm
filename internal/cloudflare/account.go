package cloudflare

import (
	"context"
	"net/url"

	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/pagination"
)

// ListAccounts lists the accounts accessible to the current API token.
func (c *Client) ListAccounts(ctx context.Context, pol pagination.Policy) (*ListResult[Account], error) {
	lq := listQuery{path: "/accounts", q: url.Values{}, pol: pol}
	if c.raw {
		return rawList[Account](ctx, c, lq)
	}
	return listTyped[Account](ctx, c, lq)
}

// GetAccount fetches one account by ID.
func (c *Client) GetAccount(ctx context.Context, id string) (*GetResult[Account], error) {
	if !validID(id) {
		return nil, errors.Usage("invalid account id %q (expected a 32-character hex id)", id)
	}
	env, raw, err := c.requestJSON(ctx, "GET", "/accounts/"+url.PathEscape(id), nil, nil, "")
	if err != nil {
		return nil, err
	}
	var item Account
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding account response", err)
	}
	return &GetResult[Account]{Item: item, RawBody: raw}, nil
}

// ValidID is the exported form of validID (used by the resolver).
func ValidID(s string) bool { return validID(s) }

// validID reports whether s looks like a Cloudflare resource identifier
// (32 lowercase hex characters). Used to distinguish IDs from names and to
// fail fast on clearly malformed identifiers.
func validID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}
