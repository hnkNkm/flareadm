package cloudflare

import (
	"context"

	"github.com/hnkNkm/flareadm/internal/errors"
)

// UserDetails calls GET /user, the identity call that works for both API
// tokens and OAuth access tokens. OAuth credentials cannot use
// GET /user/tokens/verify: that endpoint verifies an API token object and
// returns its id/status, which an OAuth access token does not have
// (docs/oauth.md §5 Q4).
func (c *Client) UserDetails(ctx context.Context) (*GetResult[UserDetails], error) {
	env, raw, err := c.requestJSON(ctx, "GET", "/user", nil, nil, "")
	if err != nil {
		return nil, err
	}
	var item UserDetails
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding user details response", err)
	}
	return &GetResult[UserDetails]{Item: item, RawBody: raw}, nil
}
