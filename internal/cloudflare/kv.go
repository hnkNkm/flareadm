package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/url"
	"strconv"

	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/pagination"
)

// KVNamespacesPath builds /accounts/{account}/storage/kv/namespaces.
func kvNamespacesPath(accountID string) string {
	return "/accounts/" + url.PathEscape(accountID) + "/storage/kv/namespaces"
}

// kvNamespacePath builds .../namespaces/{namespace_id} (optionally + suffix).
func kvNamespacePath(accountID, namespaceID, suffix string) string {
	p := kvNamespacesPath(accountID) + "/" + url.PathEscape(namespaceID)
	if suffix != "" {
		p += "/" + suffix
	}
	return p
}

// ListKVNamespaces lists Workers KV namespaces (page pagination).
func (c *Client) ListKVNamespaces(ctx context.Context, accountID string, pol pagination.Policy) (*ListResult[KVNamespace], error) {
	lq := listQuery{path: kvNamespacesPath(accountID), q: url.Values{}, pol: pol}
	if c.raw {
		return rawList[KVNamespace](ctx, c, lq)
	}
	return listTyped[KVNamespace](ctx, c, lq)
}

// GetKVNamespace fetches one namespace.
func (c *Client) GetKVNamespace(ctx context.Context, accountID, namespaceID string) (*GetResult[KVNamespace], error) {
	env, raw, err := c.requestJSON(ctx, "GET", kvNamespacePath(accountID, namespaceID, ""), nil, nil, "")
	if err != nil {
		return nil, err
	}
	var item KVNamespace
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding KV namespace response", err)
	}
	return &GetResult[KVNamespace]{Item: item, RawBody: raw}, nil
}

// KVNamespaceCreateParams is the write model for namespace creation.
type KVNamespaceCreateParams struct {
	Title        string
	Jurisdiction string
}

// CreateKVNamespace creates a namespace (POST; never automatically retried).
func (c *Client) CreateKVNamespace(ctx context.Context, accountID string, p KVNamespaceCreateParams) (*GetResult[KVNamespace], error) {
	if p.Title == "" {
		return nil, errors.Usage("--title is required")
	}
	body := map[string]any{"title": p.Title}
	if p.Jurisdiction != "" {
		body["jurisdiction"] = p.Jurisdiction
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	env, respRaw, err := c.requestJSON(ctx, "POST", kvNamespacesPath(accountID), nil, raw, "application/json")
	if err != nil {
		return nil, err
	}
	var item KVNamespace
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding KV namespace response", err)
	}
	return &GetResult[KVNamespace]{Item: item, RawBody: respRaw}, nil
}

// DeleteKVNamespace deletes a namespace (DELETE, idempotent).
func (c *Client) DeleteKVNamespace(ctx context.Context, accountID, namespaceID string) error {
	_, _, err := c.requestJSON(ctx, "DELETE", kvNamespacePath(accountID, namespaceID, ""), nil, nil, "")
	return err
}

// KVKeyQuery carries the supported key list filters.
type KVKeyQuery struct {
	Prefix string
}

// ListKVKeys lists the keys of a namespace (cursor pagination). Values are
// never fetched here.
func (c *Client) ListKVKeys(ctx context.Context, accountID, namespaceID string, q KVKeyQuery, pol pagination.Policy) (*ListResult[KVKey], error) {
	if err := pol.Validate(); err != nil {
		return nil, errors.Usage("%s", err.Error())
	}
	limit := pageSize(pol)
	path := kvNamespacePath(accountID, namespaceID, "keys")

	var (
		items   []KVKey
		rawKeys []json.RawMessage
		bodies  [][]byte
		cursor  string
	)
	count := func() int {
		if c.raw {
			return len(rawKeys)
		}
		return len(items)
	}

	for {
		query := url.Values{}
		query.Set("limit", strconv.Itoa(limit))
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		if q.Prefix != "" {
			query.Set("prefix", q.Prefix)
		}
		env, raw, err := c.requestJSON(ctx, "GET", path, query, nil, "")
		if err != nil {
			return nil, err
		}
		bodies = append(bodies, raw)
		var page struct {
			Result []json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, errors.Wrap(errors.CodeUnclassified, "decoding KV key list page", err)
		}
		for _, itemRaw := range page.Result {
			if c.raw {
				rawKeys = append(rawKeys, itemRaw)
				continue
			}
			var k KVKey
			if err := json.Unmarshal(itemRaw, &k); err != nil {
				return nil, errors.Wrap(errors.CodeUnclassified, "decoding KV key", err)
			}
			items = append(items, k)
		}
		cursor = nextCursor(env.ResultInfo)
		if pol.NoPaginate || cursor == "" || (pol.MaxItems > 0 && count() >= pol.MaxItems) || len(page.Result) == 0 {
			break
		}
	}

	if pol.MaxItems > 0 {
		if c.raw && len(rawKeys) > pol.MaxItems {
			rawKeys = rawKeys[:pol.MaxItems]
		}
		if !c.raw && len(items) > pol.MaxItems {
			items = items[:pol.MaxItems]
		}
	}
	if c.raw {
		if len(bodies) == 1 && pol.MaxItems == 0 {
			return &ListResult[KVKey]{RawBody: bodies[0]}, nil
		}
		merged, err := json.Marshal(map[string]any{
			"success":  true,
			"errors":   []any{},
			"messages": []any{},
			"result":   rawKeys,
			"result_info": map[string]any{
				"count": len(rawKeys),
			},
		})
		if err != nil {
			return nil, err
		}
		return &ListResult[KVKey]{RawBody: merged}, nil
	}
	return &ListResult[KVKey]{Items: items}, nil
}

// GetKVValue reads a key's value as raw bytes (may be binary).
func (c *Client) GetKVValue(ctx context.Context, accountID, namespaceID, key string) ([]byte, error) {
	return c.do(ctx, "GET", kvNamespacePath(accountID, namespaceID, "values/"+url.PathEscape(key)), nil, nil, "")
}

// KVPutParams is the write model for a key value.
type KVPutParams struct {
	Value         []byte
	Metadata      json.RawMessage
	Expiration    int64
	ExpirationTTL int64
}

// PutKVValue writes a key value (PUT multipart; idempotent).
func (c *Client) PutKVValue(ctx context.Context, accountID, namespaceID, key string, p KVPutParams) error {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("value", "value")
	if err != nil {
		return err
	}
	if _, err := part.Write(p.Value); err != nil {
		return err
	}
	if len(p.Metadata) > 0 {
		if err := w.WriteField("metadata", string(p.Metadata)); err != nil {
			return err
		}
	}
	if err := w.Close(); err != nil {
		return err
	}
	query := url.Values{}
	if p.Expiration > 0 {
		query.Set("expiration", strconv.FormatInt(p.Expiration, 10))
	}
	if p.ExpirationTTL > 0 {
		query.Set("expiration_ttl", strconv.FormatInt(p.ExpirationTTL, 10))
	}
	_, err = c.do(ctx, "PUT", kvNamespacePath(accountID, namespaceID, "values/"+url.PathEscape(key)), query, buf.Bytes(), w.FormDataContentType())
	return err
}

// DeleteKVKey deletes a key (DELETE, idempotent).
func (c *Client) DeleteKVKey(ctx context.Context, accountID, namespaceID, key string) error {
	_, err := c.do(ctx, "DELETE", kvNamespacePath(accountID, namespaceID, "values/"+url.PathEscape(key)), nil, nil, "")
	return err
}
