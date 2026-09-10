package cloudflare

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/hnkNkm/flareadm/internal/errors"
)

// AnalyticsQueryKind is one of the REST analytics query endpoints.
type AnalyticsQueryKind string

// Supported analytics query kinds.
const (
	AnalyticsSummary    AnalyticsQueryKind = "summary"
	AnalyticsTimeseries AnalyticsQueryKind = "timeseries"
	AnalyticsTopN       AnalyticsQueryKind = "top-n"
)

// AnalyticsQuery runs a structured analytics query. The query object is sent
// verbatim: the API expects filters, from, groupBy, stats and to (plus n and
// orderBy for top-n, and optionally resolution for timeseries).
func (c *Client) AnalyticsQuery(ctx context.Context, accountID, dataset string, kind AnalyticsQueryKind, query map[string]any) (*GetResult[json.RawMessage], []byte, error) {
	switch kind {
	case AnalyticsSummary, AnalyticsTimeseries, AnalyticsTopN:
	default:
		return nil, nil, errors.Usage("unsupported analytics query kind %q", string(kind))
	}
	if len(query) == 0 {
		return nil, nil, errors.Usage("--query is required")
	}
	payload, err := json.Marshal(query)
	if err != nil {
		return nil, nil, err
	}
	path := "/accounts/" + url.PathEscape(accountID) + "/analytics/query/" + url.PathEscape(dataset) + "/" + string(kind)
	env, raw, err := c.requestJSON(ctx, "POST", path, nil, payload, "application/json")
	if err != nil {
		return nil, nil, err
	}
	return &GetResult[json.RawMessage]{Item: env.Result, RawBody: raw}, raw, nil
}

// LogsExplorerSQL runs a Log Explorer SQL query. The SQL text is the request
// body (text/plain); the response is a single page of row objects.
func (c *Client) LogsExplorerSQL(ctx context.Context, accountID, zoneID, sql string) (*ListResult[json.RawMessage], error) {
	if sql == "" {
		return nil, errors.Usage("--sql is required")
	}
	base, err := logpushBase(accountID, zoneID)
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "POST", base+"/logs/explorer/query/sql", nil, []byte(sql), "text/plain")
	if err != nil {
		return nil, err
	}
	if c.raw {
		return &ListResult[json.RawMessage]{RawBody: raw}, nil
	}
	var rows []json.RawMessage
	if err := decodeResult(env, &rows); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding query rows", err)
	}
	return &ListResult[json.RawMessage]{Items: rows}, nil
}
