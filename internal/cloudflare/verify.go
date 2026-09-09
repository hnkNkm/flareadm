package cloudflare

import (
	"context"

	"github.com/hnkNkm/flareadm/internal/errors"
)

// VerifyToken calls GET /user/tokens/verify with the configured token and
// returns the verification result. An invalid token surfaces as an
// authentication failure (exit 3).
func (c *Client) VerifyToken(ctx context.Context) (*GetResult[Verification], error) {
	env, raw, err := c.requestJSON(ctx, "GET", "/user/tokens/verify", nil, nil, "")
	if err != nil {
		return nil, err
	}
	var item Verification
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding token verification response", err)
	}
	return &GetResult[Verification]{Item: item, RawBody: raw}, nil
}
