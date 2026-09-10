package retry

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func runWithServer(t *testing.T, handler http.HandlerFunc, mw Middleware, method string, body io.Reader) (*http.Response, error) {
	t.Helper()
	srv := httptest.NewServer(handler)
	defer srv.Close()
	req, err := http.NewRequest(method, srv.URL, body)
	if err != nil {
		t.Fatal(err)
	}
	return mw(req, func(r *http.Request) (*http.Response, error) {
		return http.DefaultTransport.RoundTrip(r)
	})
}

func TestRetryAfterHonored(t *testing.T) {
	var hits int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
	mw := New(Config{MaxAttempts: 4, BaseDelay: time.Millisecond})
	start := time.Now()
	res, err := runWithServer(t, handler, mw, http.MethodGet, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if atomic.LoadInt32(&hits) != 2 {
		t.Fatalf("hits = %d, want 2", hits)
	}
	if elapsed := time.Since(start); elapsed < time.Second {
		t.Fatalf("Retry-After not honored: elapsed %s", elapsed)
	}
}

func TestRetryAfterHTTPDate(t *testing.T) {
	var hits int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			w.Header().Set("Retry-After", time.Now().Add(500*time.Millisecond).UTC().Format(http.TimeFormat))
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
	mw := New(Config{MaxAttempts: 4, BaseDelay: time.Millisecond})
	res, err := runWithServer(t, handler, mw, http.MethodGet, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK || atomic.LoadInt32(&hits) != 2 {
		t.Fatalf("status=%d hits=%d", res.StatusCode, hits)
	}
}

func Test5xxRetriedWithBackoff(t *testing.T) {
	var hits int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
	mw := New(Config{MaxAttempts: 4, BaseDelay: 2 * time.Millisecond, MaxDelay: 8 * time.Millisecond})
	res, err := runWithServer(t, handler, mw, http.MethodGet, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if atomic.LoadInt32(&hits) != 3 {
		t.Fatalf("hits = %d, want 3", hits)
	}
}

func TestNonRetryableStatusNotRetried(t *testing.T) {
	var hits int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusBadRequest)
	}
	mw := New(Config{MaxAttempts: 4})
	res, err := runWithServer(t, handler, mw, http.MethodGet, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("hits = %d, want 1", hits)
	}
}

func TestUnsafeMutationNeverRetried(t *testing.T) {
	var hits int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
	}
	for _, method := range []string{http.MethodPost, http.MethodPatch} {
		hits = 0
		mw := New(Config{MaxAttempts: 4, BaseDelay: time.Millisecond})
		res, err := runWithServer(t, handler, mw, method, nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if atomic.LoadInt32(&hits) != 1 {
			t.Fatalf("%s retried: hits = %d", method, hits)
		}
	}
}

func TestIdempotentMutationsRetried(t *testing.T) {
	var hits int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
	mw := New(Config{MaxAttempts: 4, BaseDelay: time.Millisecond})
	res, err := runWithServer(t, handler, mw, http.MethodPut, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK || atomic.LoadInt32(&hits) != 2 {
		t.Fatalf("PUT not retried: status=%d hits=%d", res.StatusCode, hits)
	}
}

func TestRetriesExhaustedReturnsLastResponse(t *testing.T) {
	var hits int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusTooManyRequests)
	}
	mw := New(Config{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: 2 * time.Millisecond})
	res, err := runWithServer(t, handler, mw, http.MethodGet, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if atomic.LoadInt32(&hits) != 3 {
		t.Fatalf("hits = %d, want 3", hits)
	}
}

func TestContextCancellationStopsRetry(t *testing.T) {
	var hits int32
	// The context is canceled as soon as the first 429 arrives; the retry
	// wait must abort instead of sleeping 30s.
	ctx, cancelRetry := context.WithCancel(context.Background())
	defer cancelRetry()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		// Cancel shortly after the response is delivered; the pending
		// retry wait must abort instead of sleeping 30s.
		go func() {
			time.Sleep(20 * time.Millisecond)
			cancelRetry()
		}()
	}))
	defer srv.Close()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	mw := New(Config{MaxAttempts: 4, BaseDelay: time.Millisecond})
	start := time.Now()
	res, err := mw(req, func(r *http.Request) (*http.Response, error) {
		return http.DefaultTransport.RoundTrip(r)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("retry wait was not aborted by context: %s", elapsed)
	}
	// The last response surfaces so exit-code mapping reflects the 429.
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("hits = %d, want 1", hits)
	}
}

func TestAttemptTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	mw := New(Config{MaxAttempts: 1, AttemptTimeout: 50 * time.Millisecond})
	_, err := mw(req, func(r *http.Request) (*http.Response, error) {
		return http.DefaultTransport.RoundTrip(r)
	})
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

// TestResponseBodyReadableAfterMiddlewareReturns proves the per-attempt
// context is not cancelled when the middleware returns: the caller still has
// to read the body (previously this failed intermittently with
// "error reading response body: context canceled").
func TestResponseBodyReadableAfterMiddlewareReturns(t *testing.T) {
	readBody := func(t *testing.T, method string, handler http.HandlerFunc, cfg Config) string {
		t.Helper()
		res, err := runWithServer(t, handler, New(cfg), method, nil)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer func() { _ = res.Body.Close() }()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("reading body: %v", err)
		}
		return string(body)
	}
	// The handler flushes headers immediately, then sends the body after a
	// delay, so the middleware has already returned when the body arrives.
	delayed := func(status int, payload string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			time.Sleep(60 * time.Millisecond)
			_, _ = io.WriteString(w, payload)
		}
	}
	cfg := Config{MaxAttempts: 3, BaseDelay: time.Millisecond, AttemptTimeout: 5 * time.Second}

	t.Run("non-retryable", func(t *testing.T) {
		if got := readBody(t, http.MethodGet, delayed(http.StatusOK, "payload-ok"), cfg); got != "payload-ok" {
			t.Fatalf("body = %q", got)
		}
	})
	t.Run("unsafe method non-retried", func(t *testing.T) {
		if got := readBody(t, http.MethodPost, delayed(http.StatusOK, "payload-post"), cfg); got != "payload-post" {
			t.Fatalf("body = %q", got)
		}
	})
	t.Run("retryable then success", func(t *testing.T) {
		var hits int32
		handler := func(w http.ResponseWriter, r *http.Request) {
			if atomic.AddInt32(&hits, 1) == 1 {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			time.Sleep(60 * time.Millisecond)
			_, _ = io.WriteString(w, "payload-after-retry")
		}
		if got := readBody(t, http.MethodGet, handler, cfg); got != "payload-after-retry" {
			t.Fatalf("body = %q", got)
		}
		if atomic.LoadInt32(&hits) != 2 {
			t.Fatalf("hits = %d, want 2", hits)
		}
	})
}
