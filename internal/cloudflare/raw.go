package cloudflare

import (
	"context"
	"strings"
)

// Request issues an arbitrary Cloudflare API request (the `api request`
// escape hatch). The response body is returned verbatim; errors are mapped
// through the standard exit-code machinery. contentType is inferred by the
// caller; it defaults to application/json when body is non-empty and
// contentType is "".
func (c *Client) Request(ctx context.Context, method, path string, body []byte, contentType string) ([]byte, error) {
	return c.do(ctx, method, path, nil, body, contentType)
}

// RequestContentType sniffs the content type for an api request body:
// JSON-looking payloads are sent as application/json, everything else as
// text/plain. An empty body carries no content type.
func RequestContentType(body []byte) string {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return ""
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		return "application/json"
	}
	return "text/plain"
}
