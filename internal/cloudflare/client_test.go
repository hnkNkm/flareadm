package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/logging"
	"github.com/hnkNkm/flareadm/internal/pagination"
)

// fakeAPI serves canned Cloudflare responses and records requests.
type fakeAPI struct {
	t      *testing.T
	mux    *http.ServeMux
	srv    *httptest.Server
	reqs   []*http.Request
	authOK string // expected Authorization value; empty = don't check
}

func newFake(t *testing.T) *fakeAPI {
	f := &fakeAPI{t: t, mux: http.NewServeMux()}
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) handle(pattern string, fn func(w http.ResponseWriter, r *http.Request)) {
	f.mux.HandleFunc(pattern, fn)
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.reqs = append(f.reqs, r)
	if f.authOK != "" {
		if got := r.Header.Get("Authorization"); got != f.authOK {
			http.Error(w, fmt.Sprintf("bad authorization %q", got), http.StatusUnauthorized)
			return
		}
	}
	f.mux.ServeHTTP(w, r)
}

func (f *fakeAPI) count() int { return len(f.reqs) }

func envBody(t *testing.T, result any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"success":  true,
		"errors":   []any{},
		"messages": []any{},
		"result":   result,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func errorEnvelope(status int, code int64, message string) (int, string) {
	b, _ := json.Marshal(map[string]any{
		"success":  false,
		"errors":   []any{map[string]any{"code": code, "message": message}},
		"messages": []any{},
		"result":   nil,
	})
	return status, string(b)
}

func newClient(t *testing.T, f *fakeAPI, opts ...func(*Options)) *Client {
	o := Options{
		Token:          "test-token",
		Endpoint:       f.srv.URL,
		RetryBaseDelay: time.Millisecond,
		RetryMaxDelay:  8 * time.Millisecond,
	}
	for _, fn := range opts {
		fn(&o)
	}
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestListAccountsNormalized(t *testing.T) {
	f := newFake(t)
	f.authOK = "Bearer test-token"
	f.handle("/accounts", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") != "1" {
			_, _ = fmt.Fprint(w, envBody(t, []any{})) // real APIs return empty pages past the end
			return
		}
		_, _ = fmt.Fprint(w, envBody(t, []map[string]any{
			{"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "name": "acct1", "type": "standard"},
		}))
	})
	c := newClient(t, f)
	res, err := c.ListAccounts(context.Background(), pagination.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 1 || res.Items[0].ID != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || res.Items[0].Name != "acct1" {
		t.Fatalf("items = %+v", res.Items)
	}
	if q := f.reqs[0].URL.Query(); q.Get("per_page") != "100" || q.Get("page") != "1" {
		t.Fatalf("query = %v", q)
	}
	if f.count() != 2 {
		t.Fatalf("requests = %d, want 2 (page 1 + terminating empty page)", f.count())
	}
}

func TestListZonesQueryParams(t *testing.T) {
	f := newFake(t)
	f.handle("/zones", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("name") != "example.com" || q.Get("status") != "active" ||
			q.Get("type") != "full" || q.Get("account.id") != "acct1234567890abcdef1234567890ab" {
			t.Errorf("unexpected query: %v", q)
		}
		_, _ = fmt.Fprint(w, envBody(t, []any{}))
	})
	c := newClient(t, f)
	if _, err := c.ListZones(context.Background(), ZoneListQuery{
		Name: "example.com", Status: "active", Type: "full", AccountID: "acct1234567890abcdef1234567890ab",
	}, pagination.Policy{}); err != nil {
		t.Fatal(err)
	}
}

func TestListZonesAccountNestedNormalization(t *testing.T) {
	f := newFake(t)
	f.handle("/zones", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") != "1" {
			_, _ = fmt.Fprint(w, envBody(t, []any{}))
			return
		}
		_, _ = fmt.Fprint(w, envBody(t, []map[string]any{
			{
				"id": "023e105f4ecef8ad9ca31a8372d0c353", "name": "example.com", "status": "active",
				"paused": false, "type": "full",
				"account":      map[string]any{"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "name": "acct1"},
				"name_servers": []string{"ns1.cloudflare.com"},
				"created_on":   "2024-01-01T00:00:00Z", "modified_on": "2024-01-02T00:00:00Z",
			},
		}))
	})
	c := newClient(t, f)
	res, err := c.ListZones(context.Background(), ZoneListQuery{}, pagination.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	z := res.Items[0]
	if z.AccountID != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || z.AccountName != "acct1" {
		t.Fatalf("account flattening failed: %+v", z)
	}
	if z.ID != "023e105f4ecef8ad9ca31a8372d0c353" || z.Name != "example.com" || z.Status != "active" {
		t.Fatalf("zone = %+v", z)
	}
	if z.CreatedOn != "2024-01-01T00:00:00Z" {
		t.Fatalf("created_on = %q", z.CreatedOn)
	}
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		name   string
		status int
		code   int64
		want   int
	}{
		{"invalid token", 400, 1000, errors.CodeAuth},
		{"unauthorized", 401, 1000, errors.CodeAuth},
		{"forbidden", 403, 9109, errors.CodePermission},
		{"not found", 404, 7000, errors.CodeNotFound},
		{"conflict", 409, 81044, errors.CodeConflict},
		{"rate limited", 429, 0, errors.CodeRateLimit},
		{"bad request", 400, 1004, errors.CodeInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.handle("/zones", func(w http.ResponseWriter, r *http.Request) {
				status, body := errorEnvelope(tc.status, tc.code, "api says no")
				w.WriteHeader(status)
				_, _ = fmt.Fprint(w, body)
			})
			c := newClient(t, f)
			_, err := c.ListZones(context.Background(), ZoneListQuery{}, pagination.Policy{})
			if err == nil {
				t.Fatal("expected error")
			}
			if errors.CodeOf(err) != tc.want {
				t.Fatalf("exit code = %d, want %d (%v)", errors.CodeOf(err), tc.want, err)
			}
		})
	}
}

func TestEnvelopeSuccessFalseOn200(t *testing.T) {
	f := newFake(t)
	f.handle("/user/tokens/verify", func(w http.ResponseWriter, r *http.Request) {
		// Legacy-style failure with HTTP 200.
		_, _ = fmt.Fprint(w, `{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}],"messages":[],"result":null}`)
	})
	c := newClient(t, f)
	_, err := c.VerifyToken(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.CodeOf(err) != errors.CodeAuth {
		t.Fatalf("exit code = %d, want 3 (%v)", errors.CodeOf(err), err)
	}
}

func TestPaginationAcrossPages(t *testing.T) {
	f := newFake(t)
	var pages int32
	f.handle("/zones", func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		n := atomic.AddInt32(&pages, 1)
		_ = n
		switch page {
		case "1":
			_, _ = fmt.Fprint(w, envBody(t, []map[string]any{
				{"id": "0000000000000000000000000000000" + "1", "name": "z1.example", "status": "active"},
				{"id": "0000000000000000000000000000000" + "2", "name": "z2.example", "status": "active"},
			}))
		case "2":
			_, _ = fmt.Fprint(w, envBody(t, []map[string]any{
				{"id": "0000000000000000000000000000000" + "3", "name": "z3.example", "status": "active"},
			}))
		default:
			_, _ = fmt.Fprint(w, envBody(t, []any{}))
		}
	})
	c := newClient(t, f)
	res, err := c.ListZones(context.Background(), ZoneListQuery{}, pagination.Policy{PageSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 3 {
		t.Fatalf("items = %d, want 3", len(res.Items))
	}
	if got := atomic.LoadInt32(&pages); got != 3 {
		t.Fatalf("pages fetched = %d, want 3 (2 + terminating empty page)", got)
	}
}

func TestNoPaginateSinglePage(t *testing.T) {
	f := newFake(t)
	f.handle("/zones", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") != "1" {
			t.Error("no-paginate must only request page 1")
		}
		_, _ = fmt.Fprint(w, envBody(t, []any{}))
	})
	c := newClient(t, f)
	if _, err := c.ListZones(context.Background(), ZoneListQuery{}, pagination.Policy{NoPaginate: true, PageSize: 2}); err != nil {
		t.Fatal(err)
	}
	if f.count() != 1 {
		t.Fatalf("requests = %d, want 1", f.count())
	}
}

func TestRawModeSinglePageByteFidelity(t *testing.T) {
	body := `{"success":true,"errors":[],"messages":[],"result":[{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"z.example"}],"result_info":{"page":1,"per_page":20,"count":1,"total_count":1,"total_pages":1}}`
	f := newFake(t)
	f.handle("/zones", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") != "1" {
			_, _ = fmt.Fprint(w, `{"success":true,"errors":[],"messages":[],"result":[]}`)
			return
		}
		_, _ = fmt.Fprint(w, body)
	})
	c := newClient(t, f, func(o *Options) { o.RawMode = true })
	res, err := c.ListZones(context.Background(), ZoneListQuery{}, pagination.Policy{NoPaginate: true})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.RawBody) != body {
		t.Fatalf("raw body differs:\n%s", res.RawBody)
	}
}

func TestRawModeMultiPageMerged(t *testing.T) {
	f := newFake(t)
	f.handle("/zones", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("page") {
		case "1":
			_, _ = fmt.Fprint(w, envBody(t, []map[string]any{{"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "name": "a.example", "status": "active"}}))
		case "2":
			_, _ = fmt.Fprint(w, envBody(t, []map[string]any{{"id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "name": "b.example", "status": "active"}}))
		default:
			_, _ = fmt.Fprint(w, envBody(t, []any{}))
		}
	})
	c := newClient(t, f, func(o *Options) { o.RawMode = true })
	res, err := c.ListZones(context.Background(), ZoneListQuery{}, pagination.Policy{PageSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Success bool `json:"success"`
		Result  []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(res.RawBody, &env); err != nil {
		t.Fatalf("merged raw is not JSON: %v", err)
	}
	if !env.Success || len(env.Result) != 2 || env.Result[1].ID != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("merged raw = %s", res.RawBody)
	}
}

func TestMaxItemsStopsFetching(t *testing.T) {
	f := newFake(t)
	f.handle("/zones", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, envBody(t, []map[string]any{{"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "name": "z", "status": "active"}}))
	})
	c := newClient(t, f)
	res, err := c.ListZones(context.Background(), ZoneListQuery{}, pagination.Policy{PageSize: 2, MaxItems: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 3 {
		t.Fatalf("items = %d, want 3", len(res.Items))
	}
	if f.count() != 3 {
		t.Fatalf("requests = %d, want 3", f.count())
	}
}

func TestGetRecordAndDelete(t *testing.T) {
	f := newFake(t)
	f.handle("/zones/023e105f4ecef8ad9ca31a8372d0c353/dns_records/11111111111111111111111111111111", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = fmt.Fprint(w, envBody(t, map[string]any{
				"id": "11111111111111111111111111111111", "zone_id": "023e105f4ecef8ad9ca31a8372d0c353",
				"zone_name": "example.com", "name": "api.example.com", "type": "A", "content": "192.0.2.10",
				"proxied": true, "proxiable": true, "ttl": 1, "comment": "", "tags": []string{},
			}))
		case http.MethodDelete:
			_, _ = fmt.Fprint(w, `{"result":{"id":"11111111111111111111111111111111"},"success":true,"errors":[],"messages":[]}`)
		}
	})
	c := newClient(t, f)
	zone := "023e105f4ecef8ad9ca31a8372d0c353"
	res, err := c.GetRecord(context.Background(), zone, "11111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	r := res.Item
	if r.Name != "api.example.com" || r.Type != "A" || r.Content != "192.0.2.10" || r.TTL != 1 || !r.Proxied {
		t.Fatalf("record = %+v", r)
	}
	if r.Data != nil {
		t.Fatalf("data should be normalized away, got %s", r.Data)
	}
	if err := c.DeleteRecord(context.Background(), zone, "11111111111111111111111111111111"); err != nil {
		t.Fatal(err)
	}
}

func TestCreateRecordBody(t *testing.T) {
	f := newFake(t)
	f.handle("/zones/023e105f4ecef8ad9ca31a8372d0c353/dns_records", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatalf("body not json: %v", err)
		}
		if m["name"] != "api.example.com" || m["type"] != "A" || m["content"] != "192.0.2.10" {
			t.Fatalf("body = %s", body)
		}
		if m["proxied"] != true || m["ttl"] != float64(1) {
			t.Fatalf("body = %s", body)
		}
		if _, ok := m["comment"]; ok {
			t.Fatalf("empty comment must be omitted: %s", body)
		}
		_, _ = fmt.Fprint(w, envBody(t, map[string]any{
			"id": "11111111111111111111111111111111", "zone_id": "023e105f4ecef8ad9ca31a8372d0c353",
			"name": "api.example.com", "type": "A", "content": "192.0.2.10", "ttl": 1, "proxied": true,
		}))
	})
	c := newClient(t, f)
	proxied := true
	_, err := c.CreateRecord(context.Background(), "023e105f4ecef8ad9ca31a8372d0c353", RecordWrite{
		Name: "api.example.com", Type: "A", Content: "192.0.2.10", TTL: 1, Proxied: &proxied,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateRecordValidation(t *testing.T) {
	for _, rw := range []RecordWrite{
		{Type: "A", Content: "1.2.3.4", TTL: 1},            // missing name
		{Name: "x", Content: "1.2.3.4", TTL: 1},            // missing type
		{Name: "x", Type: "A", TTL: 1},                     // missing content
		{Name: "x", Type: "A", Content: "1.2.3.4", TTL: 0}, // bad ttl
	} {
		if _, err := marshalRecordWrite(rw); err == nil {
			t.Errorf("expected validation error for %+v", rw)
		}
	}
}

func TestPurgeBody(t *testing.T) {
	f := newFake(t)
	f.handle("/zones/023e105f4ecef8ad9ca31a8372d0c353/purge_cache", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "purge_everything") == false || strings.Contains(string(body), "true") == false {
			t.Fatalf("purge body = %s", body)
		}
		_, _ = fmt.Fprint(w, envBody(t, map[string]any{"id": "purge-1"}))
	})
	c := newClient(t, f)
	res, err := c.PurgeCache(context.Background(), "023e105f4ecef8ad9ca31a8372d0c353", PurgeTargets{PurgeEverything: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Item.ID != "purge-1" {
		t.Fatalf("purge result = %+v", res.Item)
	}
}

func TestPurgeTargetValidation(t *testing.T) {
	if _, err := buildPurgeBody(PurgeTargets{}); err == nil {
		t.Error("empty purge must fail")
	}
	if _, err := buildPurgeBody(PurgeTargets{PurgeEverything: true, Files: []string{"https://x.example/a"}}); err == nil {
		t.Error("mixed purge targets must fail")
	}
	if _, err := buildPurgeBody(PurgeTargets{Files: []string{"https://x.example/a"}}); err != nil {
		t.Errorf("files purge should be valid: %v", err)
	}
}

func TestDNSSECEditBody(t *testing.T) {
	f := newFake(t)
	f.handle("/zones/023e105f4ecef8ad9ca31a8372d0c353/dnssec", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPatch || string(body) != `{"status":"active"}` {
			t.Fatalf("method=%s body=%s", r.Method, body)
		}
		_, _ = fmt.Fprint(w, envBody(t, map[string]any{
			"status": "active", "flags": 257, "algorithm": "13", "key_type": "ECDSAP256SHA256",
			"digests": []map[string]any{{"type": "SHA256", "algorithm": "13", "digest": "abc"}},
			"ds":      "dsss", "modified_on": "2024-01-01T00:00:00Z",
		}))
	})
	c := newClient(t, f)
	res, err := c.SetDNSSECStatus(context.Background(), "023e105f4ecef8ad9ca31a8372d0c353", DNSSECStatusActive)
	if err != nil {
		t.Fatal(err)
	}
	if res.Item.Status != "active" || res.Item.Algorithm != "13" || len(res.Item.Digests) != 1 {
		t.Fatalf("dnssec = %+v", res.Item)
	}
}

func TestDNSSECInvalidStatus(t *testing.T) {
	c := &Client{}
	if _, err := c.SetDNSSECStatus(context.Background(), "023e105f4ecef8ad9ca31a8372d0c353", "banana"); err == nil {
		t.Error("invalid status must fail")
	}
}

func TestImportMultipart(t *testing.T) {
	f := newFake(t)
	f.handle("/zones/023e105f4ecef8ad9ca31a8372d0c353/dns_records/import", func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "multipart/form-data") {
			t.Fatalf("content type = %q", ct)
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Fatalf("multipart parse: %v", err)
		}
		if got := r.FormValue("file"); got != "@\nzone example.com\n" {
			t.Fatalf("file part = %q", got)
		}
		_, _ = fmt.Fprint(w, envBody(t, map[string]any{"recs_added": 2, "total_records_parsed": 3}))
	})
	c := newClient(t, f)
	res, err := c.ImportRecords(context.Background(), "023e105f4ecef8ad9ca31a8372d0c353", []byte("@\nzone example.com\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.RecsAdded != 2 || res.TotalRecordsParsed != 3 {
		t.Fatalf("import = %+v", res)
	}
}

func TestExportText(t *testing.T) {
	f := newFake(t)
	f.handle("/zones/023e105f4ecef8ad9ca31a8372d0c353/dns_records/export", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/dns")
		_, _ = fmt.Fprint(w, "example.com.\t300\tIN\tA\t192.0.2.10\n")
	})
	c := newClient(t, f)
	body, err := c.ExportRecords(context.Background(), "023e105f4ecef8ad9ca31a8372d0c353")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "example.com.\t300\tIN\tA\t192.0.2.10\n" {
		t.Fatalf("export = %q", body)
	}
}

func TestVerifyToken(t *testing.T) {
	f := newFake(t)
	f.handle("/user/tokens/verify", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, envBody(t, map[string]any{"id": "tok-1", "status": "active"}))
	})
	c := newClient(t, f)
	res, err := c.VerifyToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Item.ID != "tok-1" || res.Item.Status != "active" {
		t.Fatalf("verify = %+v", res.Item)
	}
}

func TestRequestPassthrough(t *testing.T) {
	f := newFake(t)
	f.handle("/zones/example", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content type = %q", ct)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"x":1}` {
			t.Errorf("body = %s", body)
		}
		_, _ = fmt.Fprint(w, `{"success":true,"result":{"x":1}}`)
	})
	c := newClient(t, f)
	body, err := c.Request(context.Background(), http.MethodPost, "/zones/example", []byte(`{"x":1}`), "application/json")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"success":true,"result":{"x":1}}` {
		t.Fatalf("body = %s", body)
	}
}

func TestRequestContentTypeSniffing(t *testing.T) {
	cases := []struct{ body, want string }{
		{`{"a":1}`, "application/json"},
		{`[1,2]`, "application/json"},
		{`{ "a" : 1 }`, "application/json"},
		{`text`, "text/plain"},
		{``, ""},
	}
	for _, tc := range cases {
		if got := RequestContentType([]byte(tc.body)); got != tc.want {
			t.Errorf("RequestContentType(%q) = %q, want %q", tc.body, got, tc.want)
		}
	}
}

func TestGetAccountInvalidID(t *testing.T) {
	c := &Client{}
	if _, err := c.GetAccount(context.Background(), "not-an-id"); errors.CodeOf(err) != errors.CodeInvalid {
		t.Fatalf("expected usage error, got %v", err)
	}
}

func TestValidID(t *testing.T) {
	if !ValidID("023e105f4ecef8ad9ca31a8372d0c353") {
		t.Error("32-hex id should be valid")
	}
	if ValidID("023e105f4ecef8ad9ca31a8372d0c35") || ValidID("023e105f4ecef8ad9ca31a8372d0c35zz") || ValidID("") {
		t.Error("malformed ids should be invalid")
	}
}

func TestDebugLogsRedactToken(t *testing.T) {
	f := newFake(t)
	var logBuf strings.Builder
	logger := logging.New(&logBuf, "super-secret-token", false, true)
	f.handle("/zones", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, envBody(t, []any{}))
	})
	o := Options{Token: "super-secret-token", Endpoint: f.srv.URL, Logger: logger}
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListZones(context.Background(), ZoneListQuery{}, pagination.Policy{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logBuf.String(), "super-secret-token") {
		t.Fatalf("token leaked into debug logs:\n%s", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "GET") {
		t.Fatalf("expected request debug lines:\n%s", logBuf.String())
	}
}

func TestUnsafePOSTNotRetriedEndToEnd(t *testing.T) {
	// CreateRecord is a POST: an unsafe mutation must not be retried, so a
	// 429 surfaces immediately as a rate-limit error.
	var hits int32
	f := newFake(t)
	f.handle("/zones/023e105f4ecef8ad9ca31a8372d0c353/dns_records", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusTooManyRequests)
	})
	c := newClient(t, f, func(o *Options) { o.RetryBaseDelay = time.Millisecond })
	proxied := false
	_, err := c.CreateRecord(context.Background(), "023e105f4ecef8ad9ca31a8372d0c353", RecordWrite{
		Name: "x.example.com", Type: "A", Content: "1.2.3.4", TTL: 1, Proxied: &proxied,
	})
	if err == nil {
		t.Fatal("expected a rate-limit error")
	}
	if errors.CodeOf(err) != errors.CodeRateLimit {
		t.Fatalf("exit code = %d, want 7", errors.CodeOf(err))
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("POST was retried: hits = %d", hits)
	}
}

func TestIdempotentPUTRetriedEndToEnd(t *testing.T) {
	// UpdateRecord is a PUT (idempotent): the request body must be replayed
	// on the retry attempt.
	var hits int32
	f := newFake(t)
	f.handle("/zones/023e105f4ecef8ad9ca31a8372d0c353/dns_records/11111111111111111111111111111111", func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"name":"x.example.com"`) {
			t.Fatalf("retried body lost content: %s", body)
		}
		_, _ = fmt.Fprint(w, envBody(t, map[string]any{"id": "11111111111111111111111111111111"}))
	})
	c := newClient(t, f, func(o *Options) { o.RetryBaseDelay = time.Millisecond })
	proxied := false
	_, err := c.UpdateRecord(context.Background(), "023e105f4ecef8ad9ca31a8372d0c353",
		"11111111111111111111111111111111",
		RecordWrite{Name: "x.example.com", Type: "A", Content: "1.2.3.4", TTL: 1, Proxied: &proxied})
	if err != nil {
		t.Fatalf("PUT should have succeeded on retry: %v", err)
	}
	if atomic.LoadInt32(&hits) != 2 {
		t.Fatalf("hits = %d, want 2", hits)
	}
}
