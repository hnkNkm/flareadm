// Package retry implements FlareADM's centralized HTTP retry policy
// (docs/cli.md):
//
//   - honor Retry-After (delta-seconds and HTTP-date forms; Retry-After-Ms
//     is also recognized);
//   - retry HTTP 429 and transient 5xx (500, 502, 503, 504 and the
//     Cloudflare edge codes 520-524, 527);
//   - exponential backoff with full jitter between attempts;
//   - only idempotent methods (GET, HEAD, OPTIONS, PUT, DELETE) are
//     retried: unsafe mutations (POST, PATCH, ...) are never retried after
//     a response, because a replayed request could be applied twice;
//   - every retry decision and wait is reported through the debug logger;
//   - each attempt carries its own timeout when configured;
//   - if the context expires while waiting, the last response (if any) is
//     returned so exit-code mapping reflects the API status.
//
// The middleware wraps the cloudflare-go SDK transport so every request —
// typed service calls and the api request escape hatch alike — shares the
// exact same policy.
package retry

import (
	"context"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/hnkNkm/flareadm/internal/logging"
)

// cancelOnCloseBody ties a per-attempt context's cancellation to the
// response body lifecycle, so reading the body after this middleware returns
// can never observe a canceled context.
type cancelOnCloseBody struct {
	io.ReadCloser
	once   sync.Once
	cancel context.CancelFunc
}

func (b *cancelOnCloseBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.cancel)
	return err
}

// DefaultMaxAttempts is the total number of attempts for one logical
// request (1 initial + 3 retries).
const DefaultMaxAttempts = 4

// DefaultBaseDelay is the backoff base, doubled per retry, capped at
// DefaultMaxDelay, jittered down to zero (full jitter).
const DefaultBaseDelay = 500 * time.Millisecond

// DefaultMaxDelay caps the exponential backoff.
const DefaultMaxDelay = 8 * time.Second

// Config controls one middleware instance.
type Config struct {
	MaxAttempts    int             // total attempts incl. the first; <=0 means DefaultMaxAttempts
	BaseDelay      time.Duration   // <=0 means DefaultBaseDelay
	MaxDelay       time.Duration   // <=0 means DefaultMaxDelay
	AttemptTimeout time.Duration   // per-attempt timeout; 0 = none
	Logger         *logging.Logger // debug sink for retry decisions
}

// Next is the remainder of the middleware chain (SDK-compatible shape).
type Next = func(*http.Request) (*http.Response, error)

// Middleware is an SDK middleware: it intercepts one logical request and may
// re-invoke next for retries.
type Middleware = func(*http.Request, Next) (*http.Response, error)

// transient5xx lists the statuses eligible for retry.
var transient5xx = map[int]bool{
	500: true, 502: true, 503: true, 504: true,
	520: true, 521: true, 522: true, 523: true, 524: true, 527: true,
}

// idempotentMethods never cause duplicate work when replayed.
var idempotentMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
	http.MethodPut:     true,
	http.MethodDelete:  true,
}

// New returns a retrying middleware honoring cfg.
func New(cfg Config) Middleware {
	maxAttempts := cfg.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = DefaultMaxAttempts
	}
	base := cfg.BaseDelay
	if base <= 0 {
		base = DefaultBaseDelay
	}
	maxDelay := cfg.MaxDelay
	if maxDelay <= 0 {
		maxDelay = DefaultMaxDelay
	}

	return func(req *http.Request, next Next) (*http.Response, error) {
		idempotent := idempotentMethods[req.Method]
		var lastRes *http.Response
		var lastErr error

		for attempt := 1; attempt <= maxAttempts; attempt++ {
			attemptReq := req
			if attempt > 1 {
				// Replayed attempts need a fresh body reader. Requests with
				// a body that cannot be replayed are never retried;
				// body-less requests replay freely.
				if req.Body != nil && req.GetBody == nil {
					logf(cfg.Logger, "%s %s: cannot retry: request body is not replayable", req.Method, req.URL)
					return lastRes, lastErr
				}
				attemptReq = req.Clone(req.Context())
				if req.Body != nil {
					body, err := req.GetBody()
					if err != nil {
						if lastErr == nil {
							lastErr = err
						}
						return lastRes, lastErr
					}
					attemptReq.Body = body
				}
			}
			var attemptCancel context.CancelFunc
			if cfg.AttemptTimeout > 0 {
				ctx, cancel := context.WithTimeout(attemptReq.Context(), cfg.AttemptTimeout)
				attemptCancel = cancel
				attemptReq = attemptReq.Clone(ctx)
			}

			res, err := next(attemptReq)
			if err != nil {
				if attemptCancel != nil {
					attemptCancel()
				}
				lastErr = err
				if !idempotent {
					logf(cfg.Logger, "%s %s: transport error, not retrying unsafe method: %v", req.Method, req.URL, err)
					return nil, err
				}
				if attempt >= maxAttempts {
					return nil, err
				}
				logf(cfg.Logger, "%s %s: transport error (attempt %d/%d), retrying: %v", req.Method, req.URL, attempt, maxAttempts, err)
				if !sleep(req.Context(), cfg.Logger, backoff(attempt, base, maxDelay, nil)) {
					return nil, lastErr
				}
				continue
			}

			// The per-attempt context must outlive this middleware call:
			// the caller still has to read the response body. Cancel it
			// when the body is closed instead.
			if attemptCancel != nil {
				res.Body = &cancelOnCloseBody{ReadCloser: res.Body, cancel: attemptCancel}
				attemptCancel = nil
			}

			lastRes = res
			if res.StatusCode != http.StatusTooManyRequests && !transient5xx[res.StatusCode] {
				return res, nil
			}
			if !idempotent {
				logf(cfg.Logger, "%s %s: HTTP %d, not retrying unsafe method", req.Method, req.URL, res.StatusCode)
				return res, nil
			}
			if attempt >= maxAttempts {
				return res, nil
			}

			wait := backoff(attempt, base, maxDelay, res)
			logf(cfg.Logger, "%s %s: HTTP %d (attempt %d/%d), retrying in %s", req.Method, req.URL, res.StatusCode, attempt, maxAttempts, wait.Round(time.Millisecond))
			// Drain and close so the connection can be reused; headers are
			// already available to the caller if this was the last attempt.
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
			if !sleep(req.Context(), cfg.Logger, wait) {
				// Context expired while waiting: surface the last response
				// so exit-code mapping reflects the API status.
				return lastRes, nil
			}
		}
		if lastRes != nil {
			return lastRes, nil
		}
		return nil, lastErr
	}
}

func logf(l *logging.Logger, format string, args ...any) {
	if l != nil {
		l.Debugf(format, args...)
	}
}

// backoff computes the wait before the next attempt: Retry-After wins when
// present, otherwise exponential backoff with full jitter.
func backoff(attempt int, base, max time.Duration, res *http.Response) time.Duration {
	if res != nil {
		if d, ok := retryAfter(res); ok {
			return d
		}
	}
	exp := base << (attempt - 1)
	if exp <= 0 || exp > max {
		exp = max
	}
	return time.Duration(rand.Int64N(int64(exp)))
}

// retryAfter parses Retry-After-Ms / Retry-After (seconds or HTTP-date).
func retryAfter(res *http.Response) (time.Duration, bool) {
	for _, spec := range []struct {
		header string
		unit   time.Duration
	}{
		{"Retry-After-Ms", time.Millisecond},
		{"Retry-After", time.Second},
	} {
		v := res.Header.Get(spec.header)
		if v == "" {
			continue
		}
		if n, err := strconv.ParseFloat(v, 64); err == nil && n >= 0 {
			return time.Duration(n * float64(spec.unit)), true
		}
		if t, err := http.ParseTime(v); err == nil {
			if d := time.Until(t); d > 0 {
				return d, true
			}
			return 0, true
		}
	}
	return 0, false
}

// sleep waits for d or until ctx is done. It reports false when ctx expired.
func sleep(ctx context.Context, l *logging.Logger, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		if l != nil {
			l.Debugf("retry wait interrupted: %v", ctx.Err())
		}
		return false
	case <-t.C:
		return true
	}
}
