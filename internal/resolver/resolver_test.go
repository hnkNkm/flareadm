package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/config"
	"github.com/hnkNkm/flareadm/internal/errors"
)

// fakeCF serves account/zone list endpoints.
type fakeCF struct {
	t        *testing.T
	mux      *http.ServeMux
	srv      *httptest.Server
	requests []string // request paths+queries seen
}

func newFake(t *testing.T) *fakeCF {
	f := &fakeCF{t: t, mux: http.NewServeMux()}
	f.srv = httptest.NewServer(f.mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCF) handle(path string, fn http.HandlerFunc) {
	f.mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		f.requests = append(f.requests, r.URL.Path+"?"+r.URL.RawQuery)
		fn(w, r)
	})
}

func envBody(result any) string {
	b, _ := json.Marshal(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": result})
	return string(b)
}

func (f *fakeCF) client() *cloudflare.Client {
	c, err := cloudflare.New(cloudflare.Options{
		Token:          "test-token",
		Endpoint:       f.srv.URL,
		RetryBaseDelay: time.Millisecond,
		RetryMaxDelay:  8 * time.Millisecond,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

func TestAccountExplicitFlagWins(t *testing.T) {
	f := newFake(t)
	f.handle("/accounts", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, envBody([]any{}))
	})
	ref, err := Account(context.Background(), f.client(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		&config.Profile{AccountID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if ref.ID != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || ref.Source != "--account-id" {
		t.Fatalf("ref = %+v", ref)
	}
	if len(f.requests) != 0 {
		t.Fatal("explicit flag must not hit the network")
	}
}

func TestAccountProfileThenEnv(t *testing.T) {
	f := newFake(t)
	f.handle("/accounts", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, envBody([]any{}))
	})
	// profile wins over env
	ref, err := Account(context.Background(), f.client(), "",
		&config.Profile{AccountID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		func(string) string { return "cccccccccccccccccccccccccccccccc" })
	if err != nil {
		t.Fatal(err)
	}
	if ref.ID != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" || ref.Source != "profile account_id" {
		t.Fatalf("ref = %+v", ref)
	}
	// env wins when profile has none
	ref, err = Account(context.Background(), f.client(), "", nil,
		func(string) string { return "cccccccccccccccccccccccccccccccc" })
	if err != nil {
		t.Fatal(err)
	}
	if ref.ID != "cccccccccccccccccccccccccccccccc" || ref.Source != AccountEnvVar {
		t.Fatalf("ref = %+v", ref)
	}
}

func TestAccountDiscoverySingle(t *testing.T) {
	f := newFake(t)
	f.handle("/accounts", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") != "1" {
			_, _ = fmt.Fprint(w, envBody([]any{}))
			return
		}
		_, _ = fmt.Fprint(w, envBody([]map[string]any{{"id": "dddddddddddddddddddddddddddddddd", "name": "only"}}))
	})
	ref, err := Account(context.Background(), f.client(), "", nil, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if ref.ID != "dddddddddddddddddddddddddddddddd" || ref.Name != "only" || ref.Source != "account discovery" {
		t.Fatalf("ref = %+v", ref)
	}
}

func TestAccountDiscoveryAmbiguous(t *testing.T) {
	f := newFake(t)
	f.handle("/accounts", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, envBody([]map[string]any{
			{"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "name": "one"},
			{"id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "name": "two"},
		}))
	})
	_, err := Account(context.Background(), f.client(), "", nil, func(string) string { return "" })
	if err == nil {
		t.Fatal("ambiguous accounts must fail")
	}
	if errors.CodeOf(err) != errors.CodeInvalid {
		t.Fatalf("exit = %d, want 2", errors.CodeOf(err))
	}
	if !strings.Contains(err.Error(), "one (aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)") {
		t.Fatalf("error should list accounts: %v", err)
	}
}

func TestAccountDiscoveryNone(t *testing.T) {
	f := newFake(t)
	f.handle("/accounts", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, envBody([]any{}))
	})
	_, err := Account(context.Background(), f.client(), "", nil, func(string) string { return "" })
	if errors.CodeOf(err) != errors.CodePermission {
		t.Fatalf("exit = %d, want 4", errors.CodeOf(err))
	}
}

func TestZoneResolveIDPassthrough(t *testing.T) {
	f := newFake(t)
	c := f.client()
	z := NewZone(c)
	id, err := z.Resolve(context.Background(), "023e105f4ecef8ad9ca31a8372d0c353")
	if err != nil {
		t.Fatal(err)
	}
	if id != "023e105f4ecef8ad9ca31a8372d0c353" {
		t.Fatalf("id = %q", id)
	}
	if len(f.requests) != 0 {
		t.Fatal("id passthrough must not hit the network")
	}
}

func TestZoneResolveByName(t *testing.T) {
	f := newFake(t)
	f.handle("/zones", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("name"); got != "example.com" {
			t.Errorf("name query = %q", got)
		}
		if r.URL.Query().Get("page") != "1" {
			_, _ = fmt.Fprint(w, envBody([]any{}))
			return
		}
		_, _ = fmt.Fprint(w, envBody([]map[string]any{
			{"id": "023e105f4ecef8ad9ca31a8372d0c353", "name": "example.com", "status": "active"},
		}))
	})
	z := NewZone(f.client())
	id, err := z.Resolve(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if id != "023e105f4ecef8ad9ca31a8372d0c353" {
		t.Fatalf("id = %q", id)
	}
	// Second resolution for the same name must be served from cache.
	f.requests = nil
	if _, err := z.Resolve(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if len(f.requests) != 0 {
		t.Fatalf("cache miss: %d requests", len(f.requests))
	}
}

func TestZoneResolveNotFound(t *testing.T) {
	f := newFake(t)
	f.handle("/zones", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, envBody([]any{}))
	})
	z := NewZone(f.client())
	_, err := z.Resolve(context.Background(), "nope.example")
	if errors.CodeOf(err) != errors.CodeNotFound {
		t.Fatalf("exit = %d, want 5 (%v)", errors.CodeOf(err), err)
	}
}

func TestZoneResolveAmbiguous(t *testing.T) {
	f := newFake(t)
	f.handle("/zones", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, envBody([]map[string]any{
			{"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "name": "dup.example", "status": "active"},
			{"id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "name": "dup.example", "status": "pending"},
		}))
	})
	z := NewZone(f.client())
	_, err := z.Resolve(context.Background(), "dup.example")
	if errors.CodeOf(err) != errors.CodeInvalid {
		t.Fatalf("exit = %d, want 2 (%v)", errors.CodeOf(err), err)
	}
}

func TestZoneResolveEmpty(t *testing.T) {
	z := NewZone(nil)
	if _, err := z.Resolve(context.Background(), ""); errors.CodeOf(err) != errors.CodeInvalid {
		t.Fatalf("empty ref should be a usage error")
	}
}
