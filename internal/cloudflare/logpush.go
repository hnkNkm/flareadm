package cloudflare

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"

	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/pagination"
)

// logpushBase returns the account-or-zone prefix used by Logpush endpoints.
func logpushBase(accountID, zoneID string) (string, error) {
	switch {
	case accountID != "" && zoneID != "":
		return "", errors.Usage("account and zone scope are mutually exclusive")
	case accountID != "":
		return "/accounts/" + url.PathEscape(accountID), nil
	case zoneID != "":
		return "/zones/" + url.PathEscape(zoneID), nil
	default:
		return "", errors.Usage("either an account or a zone is required")
	}
}

func logpushJobsPath(accountID, zoneID string, jobID int64) (string, error) {
	base, err := logpushBase(accountID, zoneID)
	if err != nil {
		return "", err
	}
	p := base + "/logpush/jobs"
	if jobID != 0 {
		p += "/" + strconv.FormatInt(jobID, 10)
	}
	return p, nil
}

// ListLogpushJobs lists Logpush jobs (the endpoint is not paginated).
func (c *Client) ListLogpushJobs(ctx context.Context, accountID, zoneID string, pol pagination.Policy) (*ListResult[LogpushJob], error) {
	path, err := logpushJobsPath(accountID, zoneID, 0)
	if err != nil {
		return nil, err
	}
	return singlePageList[LogpushJob](ctx, c, path, nil, pol)
}

// GetLogpushJob fetches one job.
func (c *Client) GetLogpushJob(ctx context.Context, accountID, zoneID string, jobID int64) (*GetResult[LogpushJob], error) {
	path, err := logpushJobsPath(accountID, zoneID, jobID)
	if err != nil {
		return nil, err
	}
	return accessGet[LogpushJob](ctx, c, path)
}

// CreateLogpushJob creates a job (POST).
func (c *Client) CreateLogpushJob(ctx context.Context, accountID, zoneID string, body map[string]any) (*GetResult[LogpushJob], error) {
	path, err := logpushJobsPath(accountID, zoneID, 0)
	if err != nil {
		return nil, err
	}
	if _, ok := body["destination_conf"]; !ok {
		return nil, errors.Usage("--destination-conf is required")
	}
	if _, ok := body["dataset"]; !ok {
		return nil, errors.Usage("--dataset is required")
	}
	return accessCreate[LogpushJob](ctx, c, path, body)
}

// UpdateLogpushJob patches a job by read-modify-PUT.
func (c *Client) UpdateLogpushJob(ctx context.Context, accountID, zoneID string, jobID int64, overrides map[string]any) (*GetResult[LogpushJob], error) {
	path, err := logpushJobsPath(accountID, zoneID, jobID)
	if err != nil {
		return nil, err
	}
	return accessMergeUpdate[LogpushJob](ctx, c, path, overrides)
}

// DeleteLogpushJob deletes a job (DELETE, idempotent).
func (c *Client) DeleteLogpushJob(ctx context.Context, accountID, zoneID string, jobID int64) error {
	path, err := logpushJobsPath(accountID, zoneID, jobID)
	if err != nil {
		return err
	}
	return accessDelete(ctx, c, path)
}

// ListLogpushDatasetFields lists the fields of a Logpush dataset.
func (c *Client) ListLogpushDatasetFields(ctx context.Context, accountID, zoneID, dataset string) (map[string]string, []byte, error) {
	base, err := logpushBase(accountID, zoneID)
	if err != nil {
		return nil, nil, err
	}
	env, raw, err := c.requestJSON(ctx, "GET", base+"/logpush/datasets/"+url.PathEscape(dataset)+"/fields", nil, nil, "")
	if err != nil {
		return nil, nil, err
	}
	fields := map[string]string{}
	if err := decodeResult(env, &fields); err != nil {
		return nil, nil, errors.Wrap(errors.CodeUnclassified, "decoding dataset fields", err)
	}
	return fields, raw, nil
}

// ListLogpushDatasetJobs lists the jobs of a Logpush dataset (not paginated).
func (c *Client) ListLogpushDatasetJobs(ctx context.Context, accountID, zoneID, dataset string, pol pagination.Policy) (*ListResult[LogpushJob], error) {
	base, err := logpushBase(accountID, zoneID)
	if err != nil {
		return nil, err
	}
	return singlePageList[LogpushJob](ctx, c, base+"/logpush/datasets/"+url.PathEscape(dataset)+"/jobs", nil, pol)
}

func logpushTransformerPath(accountID string, transformerID int64, suffix string) string {
	p := "/accounts/" + url.PathEscape(accountID) + "/logpush/transformers"
	if transformerID != 0 {
		p += "/" + strconv.FormatInt(transformerID, 10)
	}
	if suffix != "" {
		p += "/" + suffix
	}
	return p
}

// ListLogpushTransformers lists transformers (not paginated).
func (c *Client) ListLogpushTransformers(ctx context.Context, accountID string, pol pagination.Policy) (*ListResult[LogpushTransformer], error) {
	return singlePageList[LogpushTransformer](ctx, c, logpushTransformerPath(accountID, 0, ""), nil, pol)
}

// GetLogpushTransformer fetches one transformer.
func (c *Client) GetLogpushTransformer(ctx context.Context, accountID string, transformerID int64) (*GetResult[LogpushTransformer], error) {
	return accessGet[LogpushTransformer](ctx, c, logpushTransformerPath(accountID, transformerID, ""))
}

// CreateLogpushTransformer creates a transformer (POST).
func (c *Client) CreateLogpushTransformer(ctx context.Context, accountID string, body map[string]any) (*GetResult[LogpushTransformer], error) {
	if _, ok := body["name"]; !ok {
		return nil, errors.Usage("--name is required")
	}
	if _, ok := body["code"]; !ok {
		return nil, errors.Usage("--code is required")
	}
	return accessCreate[LogpushTransformer](ctx, c, logpushTransformerPath(accountID, 0, ""), body)
}

// UpdateLogpushTransformer patches a transformer by read-modify-PUT.
func (c *Client) UpdateLogpushTransformer(ctx context.Context, accountID string, transformerID int64, overrides map[string]any) (*GetResult[LogpushTransformer], error) {
	return accessMergeUpdate[LogpushTransformer](ctx, c, logpushTransformerPath(accountID, transformerID, ""), overrides)
}

// DeleteLogpushTransformer deletes a transformer (DELETE, idempotent).
func (c *Client) DeleteLogpushTransformer(ctx context.Context, accountID string, transformerID int64) error {
	return accessDelete(ctx, c, logpushTransformerPath(accountID, transformerID, ""))
}

// GetLogpushTransformerContent fetches the transformer's JavaScript code.
func (c *Client) GetLogpushTransformerContent(ctx context.Context, accountID string, transformerID int64) (string, []byte, error) {
	env, raw, err := c.requestJSON(ctx, "GET", logpushTransformerPath(accountID, transformerID, "content"), nil, nil, "")
	if err != nil {
		return "", nil, err
	}
	var result struct {
		Content string `json:"content"`
	}
	if err := decodeResult(env, &result); err != nil {
		return "", nil, errors.Wrap(errors.CodeUnclassified, "decoding transformer content", err)
	}
	return result.Content, raw, nil
}

// ListLogpushTransformerVersions lists the versions of a transformer.
func (c *Client) ListLogpushTransformerVersions(ctx context.Context, accountID string, transformerID int64, pol pagination.Policy) (*ListResult[json.RawMessage], error) {
	return singlePageList[json.RawMessage](ctx, c, logpushTransformerPath(accountID, transformerID, "versions"), nil, pol)
}
