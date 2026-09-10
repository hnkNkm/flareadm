package cloudflare

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"time"

	"github.com/hnkNkm/flareadm/internal/errors"
)

func vectorizeIndexesPath(accountID string) string {
	return "/accounts/" + url.PathEscape(accountID) + "/vectorize/v2/indexes"
}

func vectorizeIndexPath(accountID, indexName, suffix string) string {
	p := vectorizeIndexesPath(accountID) + "/" + url.PathEscape(indexName)
	if suffix != "" {
		p += "/" + suffix
	}
	return p
}

// cfVectorizeIndex mirrors the Vectorize index JSON shape.
type cfVectorizeIndex struct {
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Config      *VectorizeIndexConfig `json:"config"`
	CreatedOn   time.Time             `json:"created_on"`
	ModifiedOn  time.Time             `json:"modified_on"`
}

func convertVectorizeIndex(cf cfVectorizeIndex) VectorizeIndex {
	out := VectorizeIndex{Name: cf.Name, Description: cf.Description, Config: cf.Config}
	if !cf.CreatedOn.IsZero() {
		out.CreatedOn = cf.CreatedOn.UTC().Format(time.RFC3339)
	}
	if !cf.ModifiedOn.IsZero() {
		out.ModifiedOn = cf.ModifiedOn.UTC().Format(time.RFC3339)
	}
	return out
}

// ListVectorizeIndexes lists indexes (single page: the endpoint is not
// paginated).
func (c *Client) ListVectorizeIndexes(ctx context.Context, accountID string) (*ListResult[VectorizeIndex], error) {
	env, raw, err := c.requestJSON(ctx, "GET", vectorizeIndexesPath(accountID), nil, nil, "")
	if err != nil {
		return nil, err
	}
	if c.raw {
		return &ListResult[VectorizeIndex]{RawBody: raw}, nil
	}
	var rawItems []json.RawMessage
	if err := decodeResult(env, &rawItems); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding Vectorize index list", err)
	}
	items := make([]VectorizeIndex, 0, len(rawItems))
	for _, item := range rawItems {
		var cf cfVectorizeIndex
		if err := json.Unmarshal(item, &cf); err != nil {
			return nil, errors.Wrap(errors.CodeUnclassified, "decoding Vectorize index", err)
		}
		items = append(items, convertVectorizeIndex(cf))
	}
	return &ListResult[VectorizeIndex]{Items: items}, nil
}

// GetVectorizeIndex fetches one index.
func (c *Client) GetVectorizeIndex(ctx context.Context, accountID, indexName string) (*GetResult[VectorizeIndex], error) {
	env, raw, err := c.requestJSON(ctx, "GET", vectorizeIndexPath(accountID, indexName, ""), nil, nil, "")
	if err != nil {
		return nil, err
	}
	var cf cfVectorizeIndex
	if err := decodeResult(env, &cf); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding Vectorize index response", err)
	}
	return &GetResult[VectorizeIndex]{Item: convertVectorizeIndex(cf), RawBody: raw}, nil
}

// VectorizeIndexWrite is the create model: either dimensions+metric or a
// preset.
type VectorizeIndexWrite struct {
	Name        string
	Description string
	Dimensions  int64
	Metric      string
	Preset      string
}

// CreateVectorizeIndex creates an index (POST; never auto-retried).
func (c *Client) CreateVectorizeIndex(ctx context.Context, accountID string, w VectorizeIndexWrite) (*GetResult[VectorizeIndex], error) {
	if w.Name == "" {
		return nil, errors.Usage("--name is required")
	}
	config := map[string]any{}
	switch {
	case w.Preset != "" && (w.Dimensions != 0 || w.Metric != ""):
		return nil, errors.Usage("--preset is mutually exclusive with --dimensions/--metric")
	case w.Preset != "":
		config["preset"] = w.Preset
	case w.Dimensions > 0 && w.Metric != "":
		config["dimensions"] = w.Dimensions
		config["metric"] = w.Metric
	default:
		return nil, errors.Usage("pass --dimensions and --metric, or --preset")
	}
	body := map[string]any{"name": w.Name, "config": config}
	if w.Description != "" {
		body["description"] = w.Description
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	env, respRaw, err := c.requestJSON(ctx, "POST", vectorizeIndexesPath(accountID), nil, raw, "application/json")
	if err != nil {
		return nil, err
	}
	var cf cfVectorizeIndex
	if err := decodeResult(env, &cf); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding Vectorize index response", err)
	}
	return &GetResult[VectorizeIndex]{Item: convertVectorizeIndex(cf), RawBody: respRaw}, nil
}

// DeleteVectorizeIndex deletes an index (DELETE, idempotent).
func (c *Client) DeleteVectorizeIndex(ctx context.Context, accountID, indexName string) error {
	_, _, err := c.requestJSON(ctx, "DELETE", vectorizeIndexPath(accountID, indexName, ""), nil, nil, "")
	return err
}

// VectorizeIndexInfo reads index statistics.
func (c *Client) VectorizeIndexInfo(ctx context.Context, accountID, indexName string) (*GetResult[VectorizeInfo], error) {
	env, raw, err := c.requestJSON(ctx, "GET", vectorizeIndexPath(accountID, indexName, "info"), nil, nil, "")
	if err != nil {
		return nil, err
	}
	var item VectorizeInfo
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding Vectorize info response", err)
	}
	return &GetResult[VectorizeInfo]{Item: item, RawBody: raw}, nil
}

// ---- vector operations ----------------------------------------------------

// VectorizeMutationParams is the raw NDJSON payload for insert/upsert.
type VectorizeMutationParams struct {
	Payload            []byte
	UnparsableBehavior string // error|discard
}

func vectorizeMutationPath(accountID, indexName, op string) string {
	return vectorizeIndexPath(accountID, indexName, op)
}

// InsertVectors inserts vectors (POST NDJSON; never auto-retried).
func (c *Client) InsertVectors(ctx context.Context, accountID, indexName string, p VectorizeMutationParams) (*GetResult[VectorizeMutation], error) {
	return c.vectorizeMutation(ctx, accountID, indexName, "insert", p)
}

// UpsertVectors upserts vectors (POST NDJSON; idempotent).
func (c *Client) UpsertVectors(ctx context.Context, accountID, indexName string, p VectorizeMutationParams) (*GetResult[VectorizeMutation], error) {
	return c.vectorizeMutation(ctx, accountID, indexName, "upsert", p)
}

func (c *Client) vectorizeMutation(ctx context.Context, accountID, indexName, op string, p VectorizeMutationParams) (*GetResult[VectorizeMutation], error) {
	if len(p.Payload) == 0 {
		return nil, errors.Usage("--vectors is required (NDJSON lines from @file)")
	}
	query := url.Values{}
	if p.UnparsableBehavior != "" {
		query.Set("unparsable-behavior", p.UnparsableBehavior)
	}
	env, raw, err := c.requestJSON(ctx, "POST", vectorizeMutationPath(accountID, indexName, op), query, p.Payload, "application/x-ndjson")
	if err != nil {
		return nil, err
	}
	var item VectorizeMutation
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding Vectorize mutation response", err)
	}
	return &GetResult[VectorizeMutation]{Item: item, RawBody: raw}, nil
}

// VectorizeQueryParams is the vector query model.
type VectorizeQueryParams struct {
	Vector         json.RawMessage // JSON array of floats
	TopK           int64
	ReturnValues   bool
	ReturnMetadata string // none|indexed|all
	Filter         json.RawMessage
}

// QueryVectors runs a similarity query (POST; never auto-retried).
func (c *Client) QueryVectors(ctx context.Context, accountID, indexName string, p VectorizeQueryParams) (*GetResult[VectorizeQueryResult], error) {
	if len(p.Vector) == 0 {
		return nil, errors.Usage("--vector is required (JSON array of numbers, or @file)")
	}
	body := map[string]any{"vector": p.Vector}
	if p.TopK > 0 {
		body["topK"] = p.TopK
	}
	if p.ReturnValues {
		body["returnValues"] = true
	}
	if p.ReturnMetadata != "" {
		body["returnMetadata"] = p.ReturnMetadata
	}
	if len(p.Filter) > 0 {
		body["filter"] = p.Filter
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	env, respRaw, err := c.requestJSON(ctx, "POST", vectorizeIndexPath(accountID, indexName, "query"), nil, raw, "application/json")
	if err != nil {
		return nil, err
	}
	var item VectorizeQueryResult
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding Vectorize query response", err)
	}
	return &GetResult[VectorizeQueryResult]{Item: item, RawBody: respRaw}, nil
}

// GetVectorsByIDs fetches vectors by id (POST get_by_ids).
func (c *Client) GetVectorsByIDs(ctx context.Context, accountID, indexName string, ids []string) (*GetResult[VectorizeVectorsResult], error) {
	return c.vectorizeByIDs(ctx, accountID, indexName, "get_by_ids", ids)
}

// DeleteVectorsByIDs deletes vectors by id (POST delete_by_ids).
func (c *Client) DeleteVectorsByIDs(ctx context.Context, accountID, indexName string, ids []string) (*GetResult[VectorizeMutation], error) {
	if len(ids) == 0 {
		return nil, errors.Usage("pass at least one --id")
	}
	raw, err := json.Marshal(map[string]any{"ids": ids})
	if err != nil {
		return nil, err
	}
	env, respRaw, err := c.requestJSON(ctx, "POST", vectorizeIndexPath(accountID, indexName, "delete_by_ids"), nil, raw, "application/json")
	if err != nil {
		return nil, err
	}
	var item VectorizeMutation
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding Vectorize delete response", err)
	}
	return &GetResult[VectorizeMutation]{Item: item, RawBody: respRaw}, nil
}

func (c *Client) vectorizeByIDs(ctx context.Context, accountID, indexName, op string, ids []string) (*GetResult[VectorizeVectorsResult], error) {
	if len(ids) == 0 {
		return nil, errors.Usage("pass at least one --id")
	}
	raw, err := json.Marshal(map[string]any{"ids": ids})
	if err != nil {
		return nil, err
	}
	env, respRaw, err := c.requestJSON(ctx, "POST", vectorizeIndexPath(accountID, indexName, op), nil, raw, "application/json")
	if err != nil {
		return nil, err
	}
	var item VectorizeVectorsResult
	if err := decodeResult(env, &item); err != nil {
		// Some deployments return a bare array.
		var arr []json.RawMessage
		if err2 := decodeResult(env, &arr); err2 != nil {
			return nil, errors.Wrap(errors.CodeUnclassified, "decoding Vectorize vectors response", err)
		}
		item = VectorizeVectorsResult{Vectors: arr}
	}
	return &GetResult[VectorizeVectorsResult]{Item: item, RawBody: respRaw}, nil
}

// ListVectors lists vector ids (POST list; cursor pagination is manual).
func (c *Client) ListVectors(ctx context.Context, accountID, indexName string, count int64, cursor string) (*GetResult[VectorizeVectorsResult], error) {
	query := url.Values{}
	if count > 0 {
		query.Set("count", strconv.FormatInt(count, 10))
	}
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	env, raw, err := c.requestJSON(ctx, "GET", vectorizeIndexPath(accountID, indexName, "list"), query, nil, "")
	if err != nil {
		return nil, err
	}
	var item VectorizeVectorsResult
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding Vectorize list response", err)
	}
	return &GetResult[VectorizeVectorsResult]{Item: item, RawBody: raw}, nil
}

// ---- metadata indexes -----------------------------------------------------

// ListVectorizeMetadataIndexes lists metadata indexes of an index.
func (c *Client) ListVectorizeMetadataIndexes(ctx context.Context, accountID, indexName string) (*ListResult[VectorizeMetadataIndex], error) {
	env, raw, err := c.requestJSON(ctx, "GET", vectorizeIndexPath(accountID, indexName, "metadata_index/list"), nil, nil, "")
	if err != nil {
		return nil, err
	}
	if c.raw {
		return &ListResult[VectorizeMetadataIndex]{RawBody: raw}, nil
	}
	var items []VectorizeMetadataIndex
	if err := decodeResult(env, &items); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding metadata index list", err)
	}
	return &ListResult[VectorizeMetadataIndex]{Items: items}, nil
}

// CreateVectorizeMetadataIndex creates a metadata index (POST).
func (c *Client) CreateVectorizeMetadataIndex(ctx context.Context, accountID, indexName, property, indexType string) (*GetResult[VectorizeMutation], error) {
	if property == "" {
		return nil, errors.Usage("--property is required")
	}
	if indexType == "" {
		return nil, errors.Usage("--type is required (string, number, boolean)")
	}
	raw, err := json.Marshal(map[string]any{"propertyName": property, "indexType": indexType})
	if err != nil {
		return nil, err
	}
	env, respRaw, err := c.requestJSON(ctx, "POST", vectorizeIndexPath(accountID, indexName, "metadata_index/create"), nil, raw, "application/json")
	if err != nil {
		return nil, err
	}
	var item VectorizeMutation
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding metadata index response", err)
	}
	return &GetResult[VectorizeMutation]{Item: item, RawBody: respRaw}, nil
}

// DeleteVectorizeMetadataIndex deletes a metadata index (POST metadata_index/delete).
func (c *Client) DeleteVectorizeMetadataIndex(ctx context.Context, accountID, indexName, property string) (*GetResult[VectorizeMutation], error) {
	if property == "" {
		return nil, errors.Usage("--property is required")
	}
	raw, err := json.Marshal(map[string]any{"propertyName": property})
	if err != nil {
		return nil, err
	}
	env, respRaw, err := c.requestJSON(ctx, "POST", vectorizeIndexPath(accountID, indexName, "metadata_index/delete"), nil, raw, "application/json")
	if err != nil {
		return nil, err
	}
	var item VectorizeMutation
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding metadata index response", err)
	}
	return &GetResult[VectorizeMutation]{Item: item, RawBody: respRaw}, nil
}
