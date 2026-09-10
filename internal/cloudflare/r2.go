package cloudflare

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"

	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/pagination"
)

// R2LocationHints are the accepted bucket location hints.
var R2LocationHints = []string{"apac", "eeur", "enam", "weur", "wnam", "oc"}

// R2StorageClasses are the accepted bucket storage classes.
var R2StorageClasses = []string{"Standard", "InfrequentAccess"}

// R2Jurisdictions are the accepted jurisdiction values (sent as the
// cf-r2-jurisdiction header).
var R2Jurisdictions = []string{"default", "eu", "us", "fedramp"}

// R2BucketQuery carries the supported bucket list filters.
type R2BucketQuery struct {
	NameContains string
	Order        string
	Direction    string
	Jurisdiction string
}

// R2BucketCreateParams is the write model for bucket creation.
type R2BucketCreateParams struct {
	Name         string
	LocationHint string
	StorageClass string
	Jurisdiction string
}

// r2BucketsPath builds /accounts/{account}/r2/buckets[/{name}].
func r2BucketsPath(accountID, bucketName string) string {
	p := "/accounts/" + url.PathEscape(accountID) + "/r2/buckets"
	if bucketName != "" {
		p += "/" + url.PathEscape(bucketName)
	}
	return p
}

func r2Headers(jurisdiction string) map[string]string {
	if jurisdiction == "" {
		return nil
	}
	return map[string]string{"cf-r2-jurisdiction": jurisdiction}
}

// ListR2Buckets lists R2 buckets with cursor pagination.
func (c *Client) ListR2Buckets(ctx context.Context, accountID string, q R2BucketQuery, pol pagination.Policy) (*ListResult[R2Bucket], error) {
	if err := pol.Validate(); err != nil {
		return nil, errors.Usage("%s", err.Error())
	}
	perPage := pageSize(pol)
	headers := r2Headers(q.Jurisdiction)

	var (
		items      []R2Bucket
		rawBuckets []json.RawMessage
		bodies     [][]byte
		cursor     string
	)
	count := func() int {
		if c.raw {
			return len(rawBuckets)
		}
		return len(items)
	}

	for {
		query := url.Values{}
		query.Set("per_page", strconv.Itoa(perPage))
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		if q.NameContains != "" {
			query.Set("name_contains", q.NameContains)
		}
		if q.Order != "" {
			query.Set("order", q.Order)
		}
		if q.Direction != "" {
			query.Set("direction", q.Direction)
		}
		env, raw, err := c.requestJSONHeaders(ctx, "GET", r2BucketsPath(accountID, ""), query, nil, "", headers)
		if err != nil {
			return nil, err
		}
		bodies = append(bodies, raw)
		var page struct {
			Result struct {
				Buckets []json.RawMessage `json:"buckets"`
			} `json:"result"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, errors.Wrap(errors.CodeUnclassified, "decoding R2 bucket list page", err)
		}
		for _, itemRaw := range page.Result.Buckets {
			var b R2Bucket
			if err := json.Unmarshal(itemRaw, &b); err != nil {
				return nil, errors.Wrap(errors.CodeUnclassified, "decoding R2 bucket", err)
			}
			if c.raw {
				rawBuckets = append(rawBuckets, itemRaw)
			} else {
				items = append(items, b)
			}
		}
		cursor = nextCursor(env.ResultInfo)
		if pol.NoPaginate || cursor == "" || (pol.MaxItems > 0 && count() >= pol.MaxItems) || len(page.Result.Buckets) == 0 {
			break
		}
	}

	if pol.MaxItems > 0 {
		if c.raw && len(rawBuckets) > pol.MaxItems {
			rawBuckets = rawBuckets[:pol.MaxItems]
		}
		if !c.raw && len(items) > pol.MaxItems {
			items = items[:pol.MaxItems]
		}
	}
	if c.raw {
		exact := len(bodies) == 1 && pol.MaxItems == 0
		if exact {
			return &ListResult[R2Bucket]{RawBody: bodies[0]}, nil
		}
		merged, err := json.Marshal(map[string]any{
			"success":  true,
			"errors":   []any{},
			"messages": []any{},
			"result":   map[string]any{"buckets": rawBuckets},
			"result_info": map[string]any{
				"count":    len(rawBuckets),
				"per_page": perPage,
				"cursor":   "",
			},
		})
		if err != nil {
			return nil, err
		}
		return &ListResult[R2Bucket]{RawBody: merged}, nil
	}
	return &ListResult[R2Bucket]{Items: items}, nil
}

// GetR2Bucket fetches one bucket.
func (c *Client) GetR2Bucket(ctx context.Context, accountID, bucketName, jurisdiction string) (*GetResult[R2Bucket], error) {
	env, raw, err := c.requestJSONHeaders(ctx, "GET", r2BucketsPath(accountID, bucketName), nil, nil, "", r2Headers(jurisdiction))
	if err != nil {
		return nil, err
	}
	var item R2Bucket
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding R2 bucket response", err)
	}
	return &GetResult[R2Bucket]{Item: item, RawBody: raw}, nil
}

// CreateR2Bucket creates a bucket (POST; never automatically retried).
func (c *Client) CreateR2Bucket(ctx context.Context, accountID string, p R2BucketCreateParams) (*GetResult[R2Bucket], error) {
	if p.Name == "" {
		return nil, errors.Usage("--name is required")
	}
	body := map[string]any{"name": p.Name}
	if p.LocationHint != "" {
		body["locationHint"] = p.LocationHint
	}
	if p.StorageClass != "" {
		body["storageClass"] = p.StorageClass
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	env, respRaw, err := c.requestJSONHeaders(ctx, "POST", r2BucketsPath(accountID, ""), nil, raw, "application/json", r2Headers(p.Jurisdiction))
	if err != nil {
		return nil, err
	}
	var item R2Bucket
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding R2 bucket response", err)
	}
	return &GetResult[R2Bucket]{Item: item, RawBody: respRaw}, nil
}

// DeleteR2Bucket deletes a bucket (DELETE, idempotent).
func (c *Client) DeleteR2Bucket(ctx context.Context, accountID, bucketName, jurisdiction string) error {
	_, _, err := c.requestJSONHeaders(ctx, "DELETE", r2BucketsPath(accountID, bucketName), nil, nil, "", r2Headers(jurisdiction))
	return err
}
