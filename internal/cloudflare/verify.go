package cloudflare

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/hnkNkm/flareadm/internal/errors"
)

// VerifyToken calls GET /user/tokens/verify with the configured token and
// returns the verification result. An invalid token surfaces as an
// authentication failure (exit 3).
func (c *Client) VerifyToken(ctx context.Context) (*GetResult[Verification], error) {
	return c.verifyTokenAt(ctx, "/user/tokens/verify")
}

// VerifyAccountToken calls GET /accounts/{account_id}/tokens/verify.
//
// Account-owned API tokens cannot be verified by the user-scoped endpoint: that
// one answers HTTP 401 "Invalid API Token" for them, which says nothing about
// the credential's validity. The account-scoped endpoint verifies exactly those
// tokens and also reports their expiry.
func (c *Client) VerifyAccountToken(ctx context.Context, accountID string) (*GetResult[Verification], error) {
	if accountID == "" {
		return nil, errors.Usage("an account id is required to verify an account-owned token")
	}
	return c.verifyTokenAt(ctx, "/accounts/"+url.PathEscape(accountID)+"/tokens/verify")
}

// verifyTokenAt performs one token-verification request and decodes the result.
func (c *Client) verifyTokenAt(ctx context.Context, path string) (*GetResult[Verification], error) {
	env, raw, err := c.requestJSON(ctx, "GET", path, nil, nil, "")
	if err != nil {
		return nil, err
	}
	var item Verification
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding token verification response", err)
	}
	// The server's own message text ("This API Token is valid and active") is
	// informational: it belongs in --verbose/--debug diagnostics, never in the
	// machine-readable output.
	c.logVerifyMessages(path, env)
	return &GetResult[Verification]{Item: item, RawBody: raw}, nil
}

// logVerifyMessages writes the first envelope message to stderr, but only when
// verbose or debug diagnostics are enabled.
func (c *Client) logVerifyMessages(path string, env envelope) {
	if c == nil || c.log == nil || len(env.Messages) == 0 {
		return
	}
	var message struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(env.Messages[0], &message); err != nil || message.Message == "" {
		return
	}
	if c.log.DebugEnabled() {
		c.log.Debugf("GET %s: %s", path, message.Message)
		return
	}
	c.log.Infof("GET %s: %s", path, message.Message)
}
