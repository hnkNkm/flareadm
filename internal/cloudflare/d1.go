package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/pagination"
)

// D1LocationHints are the accepted primary location hints.
var D1LocationHints = []string{"wnam", "enam", "weur", "eeur", "apac", "oc"}

// D1Jurisdictions are the accepted jurisdiction values.
var D1Jurisdictions = []string{"eu", "fedramp", "us"}

// D1ReadReplicationModes are the accepted read replication modes.
var D1ReadReplicationModes = []string{"auto", "disabled"}

// D1ImportActions are the accepted import step actions.
var D1ImportActions = []string{"init", "ingest", "poll"}

// d1DatabasePath builds /accounts/{account}/d1/database[/{id}[/suffix]].
func d1DatabasePath(accountID, databaseID, suffix string) string {
	p := "/accounts/" + url.PathEscape(accountID) + "/d1/database"
	if databaseID != "" {
		p += "/" + url.PathEscape(databaseID)
	}
	if suffix != "" {
		p += "/" + suffix
	}
	return p
}

// cfD1Database mirrors the D1 database JSON shape.
type cfD1Database struct {
	UUID            string          `json:"uuid"`
	Name            string          `json:"name"`
	Version         string          `json:"version"`
	NumTables       float64         `json:"num_tables"`
	FileSize        float64         `json:"file_size"`
	Jurisdiction    string          `json:"jurisdiction"`
	ReadReplication json.RawMessage `json:"read_replication"`
	CreatedAt       time.Time       `json:"created_at"`
}

func convertD1Database(cf cfD1Database) D1Database {
	out := D1Database{
		UUID: cf.UUID, Name: cf.Name, Version: cf.Version,
		NumTables: cf.NumTables, FileSize: cf.FileSize, Jurisdiction: cf.Jurisdiction,
	}
	if len(cf.ReadReplication) > 0 && string(cf.ReadReplication) != "null" {
		out.ReadReplication = cf.ReadReplication
	}
	if !cf.CreatedAt.IsZero() {
		out.CreatedAt = cf.CreatedAt.UTC().Format(time.RFC3339)
	}
	return out
}

func decodeD1Database(env envelope) (D1Database, error) {
	var cf cfD1Database
	if err := decodeResult(env, &cf); err != nil {
		return D1Database{}, errors.Wrap(errors.CodeUnclassified, "decoding D1 database response", err)
	}
	return convertD1Database(cf), nil
}

// D1Query carries the paginated database list parameters.
type D1ListQuery struct {
	Name string
}

// ListD1Databases lists D1 databases of an account (page pagination).
func (c *Client) ListD1Databases(ctx context.Context, accountID string, q D1ListQuery, pol pagination.Policy) (*ListResult[D1Database], error) {
	query := url.Values{}
	if q.Name != "" {
		query.Set("name", q.Name)
	}
	lq := listQuery{path: d1DatabasePath(accountID, "", ""), q: query, pol: pol}
	if c.raw {
		return rawList[D1Database](ctx, c, lq)
	}
	return listMapped[cfD1Database, D1Database](ctx, c, lq, convertD1Database)
}

// GetD1Database fetches one database.
func (c *Client) GetD1Database(ctx context.Context, accountID, databaseID string) (*GetResult[D1Database], error) {
	env, raw, err := c.requestJSON(ctx, "GET", d1DatabasePath(accountID, databaseID, ""), nil, nil, "")
	if err != nil {
		return nil, err
	}
	item, err := decodeD1Database(env)
	if err != nil {
		return nil, err
	}
	return &GetResult[D1Database]{Item: item, RawBody: raw}, nil
}

// D1DatabaseCreateParams is the write model for database creation.
type D1DatabaseCreateParams struct {
	Name                string
	PrimaryLocationHint string
	Jurisdiction        string
	ReadReplicationMode string
}

// CreateD1Database creates a database (POST; never automatically retried).
func (c *Client) CreateD1Database(ctx context.Context, accountID string, p D1DatabaseCreateParams) (*GetResult[D1Database], error) {
	if p.Name == "" {
		return nil, errors.Usage("--name is required")
	}
	body := map[string]any{"name": p.Name}
	if p.PrimaryLocationHint != "" {
		body["primary_location_hint"] = p.PrimaryLocationHint
	}
	if p.Jurisdiction != "" {
		body["jurisdiction"] = p.Jurisdiction
	}
	if p.ReadReplicationMode != "" {
		body["read_replication"] = map[string]any{"mode": p.ReadReplicationMode}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	env, respRaw, err := c.requestJSON(ctx, "POST", d1DatabasePath(accountID, "", ""), nil, raw, "application/json")
	if err != nil {
		return nil, err
	}
	item, err := decodeD1Database(env)
	if err != nil {
		return nil, err
	}
	return &GetResult[D1Database]{Item: item, RawBody: respRaw}, nil
}

// UpdateD1ReadReplication updates the read replication mode (PATCH).
func (c *Client) UpdateD1ReadReplication(ctx context.Context, accountID, databaseID, mode string) (*GetResult[D1Database], error) {
	body, err := json.Marshal(map[string]any{"read_replication": map[string]any{"mode": mode}})
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "PATCH", d1DatabasePath(accountID, databaseID, ""), nil, body, "application/json")
	if err != nil {
		return nil, err
	}
	item, err := decodeD1Database(env)
	if err != nil {
		return nil, err
	}
	return &GetResult[D1Database]{Item: item, RawBody: raw}, nil
}

// DeleteD1Database deletes a database (DELETE, idempotent).
func (c *Client) DeleteD1Database(ctx context.Context, accountID, databaseID string) error {
	_, _, err := c.requestJSON(ctx, "DELETE", d1DatabasePath(accountID, databaseID, ""), nil, nil, "")
	return err
}

// D1QueryRequest carries one D1 SQL invocation (query or raw).
type D1QueryRequest struct {
	SQL    string
	Params json.RawMessage // JSON array or object
	Batch  json.RawMessage // JSON array of statements
}

func (r D1QueryRequest) body() ([]byte, error) {
	if r.SQL == "" && len(r.Batch) == 0 {
		return nil, errors.Usage("--sql is required (or --batch @file)")
	}
	body := map[string]any{}
	if r.SQL != "" {
		body["sql"] = r.SQL
	}
	if len(r.Params) > 0 {
		body["params"] = r.Params
	}
	if len(r.Batch) > 0 {
		body["batch"] = r.Batch
	}
	return json.Marshal(body)
}

// QueryD1 runs SQL and returns object-shaped rows.
func (c *Client) QueryD1(ctx context.Context, accountID, databaseID string, req D1QueryRequest) (*GetResult[[]D1StatementResult], error) {
	body, err := req.body()
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "POST", d1DatabasePath(accountID, databaseID, "query"), nil, body, "application/json")
	if err != nil {
		return nil, err
	}
	var items []D1StatementResult
	if err := decodeResult(env, &items); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding D1 query results", err)
	}
	return &GetResult[[]D1StatementResult]{Item: items, RawBody: raw}, nil
}

// RawD1 runs SQL and returns positional rows.
func (c *Client) RawD1(ctx context.Context, accountID, databaseID string, req D1QueryRequest) (*GetResult[[]D1RawStatementResult], error) {
	body, err := req.body()
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "POST", d1DatabasePath(accountID, databaseID, "raw"), nil, body, "application/json")
	if err != nil {
		return nil, err
	}
	var items []D1RawStatementResult
	if err := decodeResult(env, &items); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding D1 raw results", err)
	}
	return &GetResult[[]D1RawStatementResult]{Item: items, RawBody: raw}, nil
}

// D1ExportParams is the export request model.
type D1ExportParams struct {
	OutputFormat    string // "polling" (the only accepted value today)
	CurrentBookmark string
	DumpOptions     json.RawMessage
}

// ExportD1 starts a D1 export job and returns the download location.
func (c *Client) ExportD1(ctx context.Context, accountID, databaseID string, p D1ExportParams) (*GetResult[D1ExportResult], error) {
	if p.OutputFormat == "" {
		p.OutputFormat = "polling"
	}
	body := map[string]any{"output_format": p.OutputFormat}
	if p.CurrentBookmark != "" {
		body["current_bookmark"] = p.CurrentBookmark
	}
	if len(p.DumpOptions) > 0 {
		body["dump_options"] = p.DumpOptions
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	env, respRaw, err := c.requestJSON(ctx, "POST", d1DatabasePath(accountID, databaseID, "export"), nil, raw, "application/json")
	if err != nil {
		return nil, err
	}
	item, err := decodeD1Export(env, respRaw)
	if err != nil {
		return nil, err
	}
	return &GetResult[D1ExportResult]{Item: item, RawBody: respRaw}, nil
}

// decodeD1Export accepts both the enveloped and the flat job response shape.
func decodeD1Export(env envelope, raw []byte) (D1ExportResult, error) {
	var out D1ExportResult
	var cf struct {
		Status     string   `json:"status"`
		AtBookmark string   `json:"at_bookmark"`
		Error      string   `json:"error"`
		Messages   []string `json:"messages"`
		Result     struct {
			Filename  string `json:"filename"`
			SignedURL string `json:"signed_url"`
		} `json:"result"`
	}
	if len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, &cf); err == nil && (cf.Status != "" || cf.Result.SignedURL != "") {
			out = D1ExportResult{
				Status: cf.Status, AtBookmark: cf.AtBookmark, Filename: cf.Result.Filename,
				SignedURL: cf.Result.SignedURL, Messages: cf.Messages, Error: cf.Error,
			}
			return out, nil
		}
	}
	if err := json.Unmarshal(raw, &cf); err != nil {
		return out, errors.Wrap(errors.CodeUnclassified, "decoding D1 export response", err)
	}
	out = D1ExportResult{
		Status: cf.Status, AtBookmark: cf.AtBookmark, Filename: cf.Result.Filename,
		SignedURL: cf.Result.SignedURL, Messages: cf.Messages, Error: cf.Error,
	}
	return out, nil
}

// D1ImportStepParams is one import step invocation.
type D1ImportStepParams struct {
	Action          string // init|ingest|poll
	Filename        string
	Etag            string
	CurrentBookmark string
}

// ImportD1Step runs one step of the D1 import protocol.
func (c *Client) ImportD1Step(ctx context.Context, accountID, databaseID string, p D1ImportStepParams) (*GetResult[D1ImportResult], error) {
	if !containsString(D1ImportActions, p.Action) {
		return nil, errors.Usage("invalid --action %q (supported: init, ingest, poll)", p.Action)
	}
	body := map[string]any{"action": p.Action}
	if p.Filename != "" {
		body["filename"] = p.Filename
	}
	if p.Etag != "" {
		body["etag"] = p.Etag
	}
	if p.CurrentBookmark != "" {
		body["current_bookmark"] = p.CurrentBookmark
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	env, respRaw, err := c.requestJSON(ctx, "POST", d1DatabasePath(accountID, databaseID, "import"), nil, raw, "application/json")
	if err != nil {
		return nil, err
	}
	item, err := decodeD1Import(env, respRaw)
	if err != nil {
		return nil, err
	}
	return &GetResult[D1ImportResult]{Item: item, RawBody: respRaw}, nil
}

// decodeD1Import accepts both the enveloped and the flat job response shape.
func decodeD1Import(env envelope, raw []byte) (D1ImportResult, error) {
	var out D1ImportResult
	var cf struct {
		Status    string   `json:"status"`
		Filename  string   `json:"filename"`
		UploadURL string   `json:"upload_url"`
		Error     string   `json:"error"`
		Messages  []string `json:"messages"`
		Result    struct {
			FinalBookmark string  `json:"final_bookmark"`
			NumQueries    float64 `json:"num_queries"`
		} `json:"result"`
	}
	if len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, &cf); err == nil && (cf.Status != "" || cf.UploadURL != "") {
			return D1ImportResult{
				Status: cf.Status, Filename: cf.Filename, UploadURL: cf.UploadURL,
				FinalBookmark: cf.Result.FinalBookmark, NumQueries: cf.Result.NumQueries,
				Messages: cf.Messages, Error: cf.Error,
			}, nil
		}
	}
	if err := json.Unmarshal(raw, &cf); err != nil {
		return out, errors.Wrap(errors.CodeUnclassified, "decoding D1 import response", err)
	}
	out = D1ImportResult{
		Status: cf.Status, Filename: cf.Filename, UploadURL: cf.UploadURL,
		FinalBookmark: cf.Result.FinalBookmark, NumQueries: cf.Result.NumQueries,
		Messages: cf.Messages, Error: cf.Error,
	}
	return out, nil
}

// UploadD1File uploads the dump/SQL bytes to the signed upload URL returned
// by the import init step. The signed URL carries its own authorization, so
// the Cloudflare token is NOT attached.
func UploadD1File(ctx context.Context, uploadURL string, data []byte) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, uploadURL, bytes.NewReader(data))
	if err != nil {
		return "", errors.Wrap(errors.CodeInvalid, "invalid upload URL", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", errors.FromTransport(err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return "", errors.FromAPIFailure(resp.StatusCode, 0, "file upload failed", http.MethodPut, "upload_url")
	}
	return resp.Header.Get("ETag"), nil
}

// D1BookmarkAt reads a time-travel bookmark (optionally at a timestamp).
func (c *Client) D1BookmarkAt(ctx context.Context, accountID, databaseID string, at *time.Time) (*GetResult[D1Bookmark], error) {
	query := url.Values{}
	if at != nil {
		query.Set("timestamp", at.UTC().Format(time.RFC3339))
	}
	env, raw, err := c.requestJSON(ctx, "GET", d1DatabasePath(accountID, databaseID, "time_travel/bookmark"), query, nil, "")
	if err != nil {
		return nil, err
	}
	var item D1Bookmark
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding D1 bookmark response", err)
	}
	return &GetResult[D1Bookmark]{Item: item, RawBody: raw}, nil
}

// D1RestoreParams selects the restore point (bookmark or timestamp).
type D1RestoreParams struct {
	Bookmark string
	At       *time.Time
}

// RestoreD1 restores a database to a bookmark or timestamp.
func (c *Client) RestoreD1(ctx context.Context, accountID, databaseID string, p D1RestoreParams) (*GetResult[D1RestoreResult], error) {
	if p.Bookmark == "" && p.At == nil {
		return nil, errors.Usage("--bookmark or --timestamp is required")
	}
	if p.Bookmark != "" && p.At != nil {
		return nil, errors.Usage("--bookmark and --timestamp are mutually exclusive")
	}
	query := url.Values{}
	if p.Bookmark != "" {
		query.Set("bookmark", p.Bookmark)
	}
	if p.At != nil {
		query.Set("timestamp", p.At.UTC().Format(time.RFC3339))
	}
	env, raw, err := c.requestJSON(ctx, "POST", d1DatabasePath(accountID, databaseID, "time_travel/restore"), query, nil, "")
	if err != nil {
		return nil, err
	}
	var item D1RestoreResult
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding D1 restore response", err)
	}
	return &GetResult[D1RestoreResult]{Item: item, RawBody: raw}, nil
}
