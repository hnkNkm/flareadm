package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/option"

	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/logging"
	"github.com/hnkNkm/flareadm/internal/pagination"
	"github.com/hnkNkm/flareadm/internal/retry"
	"github.com/hnkNkm/flareadm/internal/version"
)

// DefaultEndpoint is the Cloudflare v4 REST API base URL.
const DefaultEndpoint = "https://api.cloudflare.com/client/v4/"

// Options configure a Client.
type Options struct {
	Token          string
	Endpoint       string        // base URL, may be empty (DefaultEndpoint)
	Timeout        time.Duration // per-attempt timeout (--timeout)
	MaxAttempts    int           // total retry attempts incl. first; <=0 default
	RetryBaseDelay time.Duration
	RetryMaxDelay  time.Duration
	RawMode        bool // --raw: services return raw API bodies
	Policy         pagination.Policy
	Logger         *logging.Logger
}

// Client is the FlareADM Cloudflare adapter. All requests — first-class
// service calls and the api request escape hatch — flow through the same
// SDK transport, retry middleware and error normalization.
type Client struct {
	sdk    *cloudflare.Client
	raw    bool
	policy pagination.Policy
	log    *logging.Logger
}

// New constructs the adapter over the cloudflare-go SDK. The SDK's built-in
// retry loop is disabled (WithMaxRetries(0)); FlareADM's centralized retry
// policy runs as middleware so every request shares identical semantics.
func New(o Options) (*Client, error) {
	if o.Token == "" {
		return nil, errors.New(errors.CodeAuth, "no API token provided")
	}
	endpoint := o.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}

	rt := http.DefaultTransport.(*http.Transport).Clone()
	rt.ResponseHeaderTimeout = 30 * time.Second
	httpClient := &http.Client{Transport: rt}

	sdkClient := cloudflare.NewClient(
		option.WithAPIToken(o.Token),
		option.WithBaseURL(endpoint),
		option.WithHTTPClient(httpClient),
		option.WithMaxRetries(0),
		option.WithHeader("User-Agent", "flareadm/"+version.String()),
		option.WithMiddleware(retry.New(retry.Config{
			MaxAttempts:    o.MaxAttempts,
			BaseDelay:      o.RetryBaseDelay,
			MaxDelay:       o.RetryMaxDelay,
			AttemptTimeout: o.Timeout,
			Logger:         o.Logger,
		})),
		option.WithMiddleware(debugMiddleware(o.Logger)),
	)

	return &Client{sdk: sdkClient, raw: o.RawMode, policy: o.Policy, log: o.Logger}, nil
}

// RawMode reports whether --raw output mode is active.
func (c *Client) RawMode() bool { return c.raw }

// debugMiddleware logs one line per HTTP attempt (request line and outcome).
// Headers and bodies are never logged, so the Authorization header cannot
// leak into debug output.
func debugMiddleware(l *logging.Logger) retry.Middleware {
	return func(req *http.Request, next retry.Next) (*http.Response, error) {
		if l == nil || !l.DebugEnabled() {
			return next(req)
		}
		start := time.Now()
		res, err := next(req)
		if err != nil {
			l.Debugf("%s %s failed after %s: %v", req.Method, req.URL, time.Since(start).Round(time.Millisecond), err)
			return res, err
		}
		l.Debugf("%s %s -> %d in %s", req.Method, req.URL, res.StatusCode, time.Since(start).Round(time.Millisecond))
		return res, nil
	}
}

// do issues one HTTP request through the SDK transport and returns the raw
// response body. API failures (HTTP >= 400) surface as FlareADM ExitErrors
// with mapped exit codes.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body []byte, contentType string) ([]byte, error) {
	if !strings.HasPrefix(path, "/") {
		return nil, errors.Usage("API path %q must start with '/'", path)
	}
	reqURL := path
	if len(query) > 0 {
		reqURL += "?" + query.Encode()
	}

	var opts []option.RequestOption
	dst := new([]byte)
	if body != nil {
		ct := contentType
		if ct == "" {
			ct = "application/json"
		}
		opts = append(opts, option.WithRequestBody(ct, body))
	}
	err := c.sdk.Execute(ctx, method, reqURL, nil, dst, opts...)
	if err != nil {
		return nil, c.mapError(err, method, reqURL)
	}
	return *dst, nil
}

// requestJSON performs a request whose response carries the Cloudflare JSON
// envelope ({success,errors,messages,result[,_result_info]}). It returns the
// envelope plus the raw body bytes (used by --raw mode).
func (c *Client) requestJSON(ctx context.Context, method, path string, query url.Values, body []byte, contentType string) (envelope, []byte, error) {
	raw, err := c.do(ctx, method, path, query, body, contentType)
	if err != nil {
		return envelope{}, nil, err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return envelope{}, nil, errors.Wrap(errors.CodeUnclassified,
			fmt.Sprintf("decoding Cloudflare response for %s %s", method, path), err)
	}
	if !env.Success && len(env.Errors) > 0 {
		return env, raw, c.envelopeError(method, path, env)
	}
	return env, raw, nil
}

// envelopeError maps a 2xx response whose envelope reports success=false.
// Legacy Cloudflare endpoints report failures this way; the application
// error code decides the exit code.
func (c *Client) envelopeError(method, path string, env envelope) error {
	code := errors.CodeConflict
	for _, e := range env.Errors {
		if e.Code == errors.APIErrorCodeAuth {
			code = errors.CodeAuth
			break
		}
	}
	msgs := make([]string, 0, len(env.Errors))
	for _, e := range env.Errors {
		msgs = append(msgs, fmt.Sprintf("%s (code %d)", e.Message, e.Code))
	}
	return errors.New(code, "%s %s failed: API reported failure: %s", method, path, strings.Join(msgs, "; "))
}

// mapError converts SDK/transport errors into FlareADM ExitErrors.
func (c *Client) mapError(err error, method, reqURL string) error {
	if err == nil {
		return nil
	}
	var apiErr *cloudflare.Error
	if stderrors.As(err, &apiErr) {
		var code int64
		msg := ""
		if len(apiErr.Errors) > 0 {
			code = apiErr.Errors[0].Code
			msg = apiErr.Errors[0].Message
		}
		return errors.FromAPIFailure(apiErr.StatusCode, code, msg, method, reqURL)
	}
	return errors.FromTransport(err)
}

// ---- shared list plumbing ------------------------------------------------

// listQuery is one base query shared by every page of a list fetch.
type listQuery struct {
	path string
	q    url.Values
	pol  pagination.Policy
}

// pageSize returns the effective per-page size for the policy.
func pageSize(pol pagination.Policy) int {
	if pol.PageSize <= 0 {
		return pagination.DefaultPageSize
	}
	return pol.PageSize
}

// fetchPages iterates the pagination policy over a GET list endpoint.
// fetch decodes one page; page bodies are stashed for --raw merging.
func fetchPages[T any](ctx context.Context, c *Client, lq listQuery, fetch func(ctx context.Context, page int, env envelope) ([]T, error)) ([]T, [][]byte, error) {
	if err := lq.pol.Validate(); err != nil {
		return nil, nil, errors.Usage("%s", err.Error())
	}
	perPage := pageSize(lq.pol)
	var pageBodies [][]byte

	items, _, err := pagination.Collect(ctx, lq.pol, func(ctx context.Context, pageNum int) ([]T, error) {
		q := cloneValues(lq.q)
		q.Set("page", strconv.Itoa(pageNum))
		q.Set("per_page", strconv.Itoa(perPage))
		env, raw, err := c.requestJSON(ctx, "GET", lq.path, q, nil, "")
		if err != nil {
			return nil, err
		}
		pageBodies = append(pageBodies, raw)
		return fetch(ctx, pageNum, env)
	})
	if err != nil {
		return nil, pageBodies, err
	}
	return items, pageBodies, nil
}

// listTyped collects typed items from a paginated GET endpoint.
func listTyped[T any](ctx context.Context, c *Client, lq listQuery) (*ListResult[T], error) {
	items, _, err := fetchPages(ctx, c, lq, func(_ context.Context, _ int, env envelope) ([]T, error) {
		var page []T
		if err := decodeResult(env, &page); err != nil {
			return nil, err
		}
		return page, nil
	})
	if err != nil {
		return nil, err
	}
	return &ListResult[T]{Items: items}, nil
}

// listMapped collects items decoded as the Cloudflare-shaped source type S
// and converts them into the normalized model type T per item.
func listMapped[S any, T any](ctx context.Context, c *Client, lq listQuery, convert func(S) T) (*ListResult[T], error) {
	items, _, err := fetchPages(ctx, c, lq, func(_ context.Context, _ int, env envelope) ([]S, error) {
		var page []S
		if err := decodeResult(env, &page); err != nil {
			return nil, err
		}
		return page, nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]T, len(items))
	for i, it := range items {
		out[i] = convert(it)
	}
	return &ListResult[T]{Items: out}, nil
}

// rawList collects raw page bodies from a paginated GET endpoint in --raw
// mode and returns a typed ListResult whose RawBody holds the closest raw
// representation of the Cloudflare API response.
func rawList[T any](ctx context.Context, c *Client, lq listQuery) (*ListResult[T], error) {
	items, pageBodies, err := fetchPages(ctx, c, lq, func(_ context.Context, _ int, env envelope) ([]json.RawMessage, error) {
		var page []json.RawMessage
		if err := decodeResult(env, &page); err != nil {
			return nil, err
		}
		return page, nil
	})
	if err != nil {
		return nil, err
	}
	body, err := c.rawListBody(pageBodies, len(items), lq.pol)
	if err != nil {
		return nil, err
	}
	return &ListResult[T]{RawBody: body}, nil
}

// rawListBody picks the closest raw representation: the original single
// page body when nothing was truncated, otherwise a merged envelope.
func (c *Client) rawListBody(pageBodies [][]byte, itemCount int, pol pagination.Policy) ([]byte, error) {
	if len(pageBodies) == 0 {
		return nil, nil
	}
	if len(pageBodies) == 1 && pol.MaxItems == 0 {
		return pageBodies[0], nil
	}
	out := rawListEnvelope{Success: true, Errors: []json.RawMessage{}, Messages: []json.RawMessage{}}
	for _, body := range pageBodies {
		var page rawListEnvelope
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, err
		}
		out.Errors = append(out.Errors, page.Errors...)
		out.Messages = append(out.Messages, page.Messages...)
		out.Result = append(out.Result, page.Result...)
	}
	if pol.MaxItems > 0 && len(out.Result) > itemCount {
		out.Result = out.Result[:itemCount]
	}
	out.ResultInfo = &resultInfo{
		Page:       1,
		PerPage:    int64(pageSize(pol)),
		Count:      int64(len(out.Result)),
		TotalCount: int64(len(out.Result)),
		TotalPages: 1,
	}
	return json.MarshalIndent(out, "", "  ")
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vals := range v {
		out[k] = append([]string(nil), vals...)
	}
	return out
}

// decodeResult decodes an envelope result into out (pointer to value or
// slice). A null/absent result decodes as a no-op.
func decodeResult(env envelope, out any) error {
	if len(env.Result) == 0 || string(bytes.TrimSpace(env.Result)) == "null" {
		return nil
	}
	return json.Unmarshal(env.Result, out)
}

// rawListEnvelope mirrors the list envelope for raw-mode merging.
type rawListEnvelope struct {
	Success    bool              `json:"success"`
	Errors     []json.RawMessage `json:"errors"`
	Messages   []json.RawMessage `json:"messages"`
	Result     []json.RawMessage `json:"result"`
	ResultInfo *resultInfo       `json:"result_info"`
}
