// Package cmd integration tests: full command executions against a fake
// Cloudflare API server and an isolated config home. Tests never touch the
// live API.
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/hnkNkm/flareadm/internal/errors"
)

// cliResult captures one CLI execution.
type cliResult struct {
	code   int
	stdout string
	stderr string
}

// runCLI executes the CLI in-process with a non-interactive stdin.
func runCLI(t *testing.T, args ...string) cliResult {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Run(context.Background(), args, strings.NewReader(""), &out, &errOut)
	return cliResult{code: code, stdout: out.String(), stderr: errOut.String()}
}

// newHome isolates XDG_CONFIG_HOME and sets the API token.
func newHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)
	return home
}

func setToken(t *testing.T, token string) {
	t.Helper()
	t.Setenv("FLAREADM_API_TOKEN", token)
}

// ---- fake Cloudflare API ------------------------------------------------

// apiStub records requests and answers through per-test handlers.
type apiStub struct {
	t       *testing.T
	srv     *httptest.Server
	mu      sync.Mutex
	reqs    []recordedRequest
	handler http.HandlerFunc
}

type recordedRequest struct {
	Method string
	Path   string
	Query  string
	Body   string
	Auth   string
}

func (a *apiStub) requests() []recordedRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]recordedRequest(nil), a.reqs...)
}

func (a *apiStub) count() int { return len(a.requests()) }

func (a *apiStub) last() recordedRequest {
	reqs := a.requests()
	if len(reqs) == 0 {
		a.t.Fatal("no API request recorded")
	}
	return reqs[len(reqs)-1]
}

// newAPI starts a stub whose handler is a switch on method+path.
func newAPI(t *testing.T, handle func(method, path string, r recordedRequest) (int, string)) *apiStub {
	t.Helper()
	a := &apiStub{t: t}
	a.handler = func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec := recordedRequest{
			Method: r.Method,
			Path:   r.URL.Path,
			Query:  r.URL.RawQuery,
			Body:   string(body),
			Auth:   r.Header.Get("Authorization"),
		}
		a.mu.Lock()
		a.reqs = append(a.reqs, rec)
		a.mu.Unlock()
		status, resp := handle(r.Method, r.URL.Path, rec)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, resp)
	}
	a.srv = httptest.NewServer(http.HandlerFunc(a.handler))
	t.Cleanup(a.srv.Close)
	return a
}

// envelope builds a Cloudflare response envelope.
func envelope(result any) string {
	b, _ := json.Marshal(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": result})
	return string(b)
}

func apiErr(status int, code int64, message string) (int, string) {
	b, _ := json.Marshal(map[string]any{
		"success":  false,
		"errors":   []any{map[string]any{"code": code, "message": message}},
		"messages": []any{},
		"result":   nil,
	})
	return status, string(b)
}

const (
	zoneID    = "023e105f4ecef8ad9ca31a8372d0c353"
	recordID  = "11111111111111111111111111111111"
	accountID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func zoneJSON(id, name, status string) map[string]any {
	return map[string]any{
		"id": id, "name": name, "status": status, "paused": false, "type": "full",
		"account":    map[string]any{"id": accountID, "name": "acct"},
		"created_on": "2024-01-01T00:00:00Z", "modified_on": "2024-01-01T00:00:00Z",
	}
}

func recordJSON(id, name, typ, content string) map[string]any {
	return map[string]any{
		"id": id, "zone_id": zoneID, "zone_name": "example.com", "name": name,
		"type": typ, "content": content, "ttl": 1, "proxied": false, "proxiable": false,
		"comment": "", "tags": []string{},
	}
}

// defaultAPI handles the standard v0.1 endpoints.
func defaultAPI(t *testing.T) *apiStub {
	return newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		switch {
		case method == "GET" && path == "/zones":
			page := strings.Contains(r.Query, "page=2")
			if page {
				return 200, envelope([]any{})
			}
			if strings.Contains(r.Query, "name=example.com") {
				return 200, envelope([]any{zoneJSON(zoneID, "example.com", "active")})
			}
			return 200, envelope([]any{zoneJSON(zoneID, "example.com", "active")})
		case method == "GET" && path == "/zones/"+zoneID:
			return 200, envelope(zoneJSON(zoneID, "example.com", "active"))
		case path == "/zones/"+zoneID+"/dns_records":
			switch method {
			case "GET":
				if strings.Contains(r.Query, "page=2") {
					return 200, envelope([]any{})
				}
				return 200, envelope([]any{recordJSON(recordID, "api.example.com", "A", "192.0.2.10")})
			case "POST":
				return 200, envelope(recordJSON(recordID, "api.example.com", "A", "192.0.2.10"))
			}
		case path == "/zones/"+zoneID+"/dns_records/"+recordID:
			switch method {
			case "GET":
				return 200, envelope(recordJSON(recordID, "api.example.com", "A", "192.0.2.10"))
			case "DELETE":
				return 200, envelope(map[string]any{"id": recordID})
			case "PUT":
				return 200, envelope(recordJSON(recordID, "api.example.com", "A", "192.0.2.10"))
			}
		case method == "GET" && path == "/zones/"+zoneID+"/dns_records/export":
			return 200, "example.com.\t300\tIN\tA\t192.0.2.10\n"
		case method == "POST" && path == "/zones/"+zoneID+"/dns_records/import":
			return 200, envelope(map[string]any{"recs_added": 2, "total_records_parsed": 2})
		case method == "GET" && path == "/zones/"+zoneID+"/dnssec":
			return 200, envelope(map[string]any{"status": "active", "algorithm": "13", "key_type": "ECDSAP256SHA256"})
		case method == "PATCH" && path == "/zones/"+zoneID+"/dnssec":
			return 200, envelope(map[string]any{"status": "disabled", "algorithm": "13", "key_type": "ECDSAP256SHA256"})
		case method == "POST" && path == "/zones/"+zoneID+"/purge_cache":
			return 200, envelope(map[string]any{"id": "purge-1"})
		case method == "GET" && path == "/user/tokens/verify":
			return 200, envelope(map[string]any{"id": "token-1", "status": "active"})
		case method == "GET" && path == "/accounts":
			return 200, envelope([]map[string]any{{"id": accountID, "name": "acct", "type": "standard"}})
		case method == "GET" && path == "/accounts/"+accountID:
			return 200, envelope(map[string]any{"id": accountID, "name": "acct", "type": "standard"})
		}
		t.Logf("unhandled request: %s %s?%s", method, path, r.Query)
		s, b := apiErr(404, 7000, "unhandled stub path")
		return s, b
	})
}

func cfgPath() string { return filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "flareadm", "config.toml") }

// ---- local commands ------------------------------------------------------

func TestVersionLocalOnly(t *testing.T) {
	newHome(t)
	res := runCLI(t, "version")
	if res.code != 0 || res.stdout != "0.1.0\n" {
		t.Fatalf("code=%d stdout=%q", res.code, res.stdout)
	}
	if res.stderr != "" {
		t.Fatalf("stderr=%q", res.stderr)
	}
}

func TestHelpLocalOnly(t *testing.T) {
	newHome(t)
	for _, args := range [][]string{{"--help"}, {"configure", "--help"}, {"api", "request", "--help"}} {
		res := runCLI(t, args...)
		if res.code != 0 {
			t.Fatalf("%v: code=%d stderr=%q", args, res.code, res.stderr)
		}
		if !strings.Contains(res.stdout, "Usage:") {
			t.Fatalf("%v: no usage in output", args)
		}
	}
}

func TestVersionWorksWithBrokenConfig(t *testing.T) {
	home := newHome(t)
	_ = os.MkdirAll(filepath.Join(home, "flareadm"), 0o755)
	_ = os.WriteFile(filepath.Join(home, "flareadm", "config.toml"), []byte("not [ toml"), 0o600)
	res := runCLI(t, "version")
	if res.code != 0 {
		t.Fatalf("version must not depend on config: code=%d stderr=%q", res.code, res.stderr)
	}
}

func TestProfileListWithoutConfig(t *testing.T) {
	newHome(t)
	res := runCLI(t, "profile", "list")
	if res.code != 0 {
		t.Fatalf("profile list without config crashed: code=%d stderr=%q", res.code, res.stderr)
	}
}

func TestUnknownCommandAndFlagExitTwo(t *testing.T) {
	newHome(t)
	if res := runCLI(t, "frobnicate"); res.code != errors.CodeInvalid {
		t.Fatalf("unknown command code=%d", res.code)
	}
	if res := runCLI(t, "zone", "list", "--frob"); res.code != errors.CodeInvalid {
		t.Fatalf("unknown flag code=%d stderr=%q", res.code, res.stderr)
	}
}

func TestConfigureAndProfileLifecycle(t *testing.T) {
	api := defaultAPI(t)
	setToken(t, "zq9-secret-abc")
	newHome(t)

	// configure init writes the file.
	res := runCLI(t, "configure", "init")
	if res.code != 0 {
		t.Fatalf("init: code=%d stderr=%q", res.code, res.stderr)
	}
	data, err := os.ReadFile(cfgPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `[profile.default]`) {
		t.Fatalf("config = %s", data)
	}
	// init refuses to overwrite.
	if res := runCLI(t, "configure", "init"); res.code != errors.CodeConflict {
		t.Fatalf("second init: code=%d, want %d", res.code, errors.CodeConflict)
	}

	// set/get round trip on the active profile.
	if res := runCLI(t, "configure", "set", "account_id", accountID); res.code != 0 {
		t.Fatalf("set: %d %s", res.code, res.stderr)
	}
	if res := runCLI(t, "configure", "get", "account_id"); res.code != 0 || res.stdout != accountID+"\n" {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, "configure", "set", "api_token_env", "CF_PERSONAL_TOKEN"); res.code != 0 {
		t.Fatalf("set env: %d", res.code)
	}
	if res := runCLI(t, "configure", "get", "api_token_env"); res.stdout != "CF_PERSONAL_TOKEN\n" {
		t.Fatalf("get env: %q", res.stdout)
	}
	if res := runCLI(t, "configure", "set", "bogus_key", "x"); res.code != errors.CodeInvalid {
		t.Fatalf("invalid key code=%d", res.code)
	}

	// configure list shows keys with sources and never the token value.
	res = runCLI(t, "configure", "list", "--output", "json")
	if res.code != 0 {
		t.Fatalf("list: %d %s", res.code, res.stderr)
	}
	if strings.Contains(res.stdout, "zq9-secret-abc") {
		t.Fatalf("token leaked into configure list: %s", res.stdout)
	}
	var env struct {
		Data []map[string]string `json:"data"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &env); err != nil {
		t.Fatalf("list json: %v", err)
	}
	if len(env.Data) != 4 {
		t.Fatalf("rows = %d: %s", len(env.Data), res.stdout)
	}

	// profile create/update/get/delete.
	if res := runCLI(t, "profile", "create", "work", "--account-id", accountID, "--api-token-env", "TOK_WORK"); res.code != 0 {
		t.Fatalf("create: %d %s", res.code, res.stderr)
	}
	if res := runCLI(t, "profile", "create", "work"); res.code != errors.CodeConflict {
		t.Fatalf("duplicate create: %d", res.code)
	}
	if res := runCLI(t, "profile", "get", "work"); res.code != 0 || !strings.Contains(res.stdout, accountID) {
		t.Fatalf("get work: code=%d %q", res.code, res.stdout)
	}
	if res := runCLI(t, "profile", "update", "work", "--default-zone", "work.example"); res.code != 0 {
		t.Fatalf("update: %d", res.code)
	}
	if res := runCLI(t, "profile", "update", "work"); res.code != errors.CodeInvalid {
		t.Fatalf("empty update should be usage: %d", res.code)
	}
	if res := runCLI(t, "profile", "get", "missing"); res.code != errors.CodeNotFound {
		t.Fatalf("missing profile: %d", res.code)
	}
	if res := runCLI(t, "profile", "list"); res.code != 0 {
		t.Fatalf("list: %d", res.code)
	}

	// Profile delete without --yes must fail non-interactively (exit 2)...
	res = runCLI(t, "profile", "delete", "work")
	if res.code != errors.CodeInvalid {
		t.Fatalf("delete without --yes: code=%d", res.code)
	}
	// ...and the profile must still exist.
	if _, err := os.ReadFile(cfgPath()); err != nil {
		t.Fatal(err)
	}
	// dry-run previews and deletes nothing.
	if res := runCLI(t, "profile", "delete", "work", "--dry-run"); res.code != 0 || !strings.Contains(res.stdout, "Would delete") {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, "profile", "get", "work"); res.code != 0 {
		t.Fatalf("work should still exist after dry-run")
	}
	// --yes deletes for real.
	if res := runCLI(t, "profile", "delete", "work", "--yes"); res.code != 0 {
		t.Fatalf("delete --yes: code=%d stderr=%q", res.code, res.stderr)
	}
	if res := runCLI(t, "profile", "get", "work"); res.code != errors.CodeNotFound {
		t.Fatalf("work should be gone: %d", res.code)
	}

	if api.count() != 0 {
		t.Fatalf("local commands hit the network: %d requests", api.count())
	}
}

func TestActiveProfileSelectionViaEnv(t *testing.T) {
	newHome(t)
	res := runCLI(t, "configure", "set", "account_id", accountID, "--profile", "envprof")
	if res.code != 0 {
		t.Fatalf("set: %d", res.code)
	}
	t.Setenv("FLAREADM_PROFILE", "envprof")
	if res := runCLI(t, "configure", "get", "account_id"); res.stdout != accountID+"\n" {
		t.Fatalf("env profile selection failed: %q", res.stdout)
	}
}

// ---- API commands --------------------------------------------------------

func TestZoneListJSONEnvelope(t *testing.T) {
	api := defaultAPI(t)
	setToken(t, "tok")
	newHome(t)
	res := runCLI(t, "zone", "list", "--json", "--endpoint-url", api.srv.URL)
	if res.code != 0 {
		t.Fatalf("code=%d stderr=%q", res.code, res.stderr)
	}
	var env struct {
		Version string `json:"version"`
		Data    []struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"data"`
		Meta struct {
			Count int `json:"count"`
		} `json:"meta"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &env); err != nil {
		t.Fatalf("stdout not JSON: %v\n%s", err, res.stdout)
	}
	if env.Version != "v1" || env.Meta.Count != 1 || env.Data[0].Name != "example.com" {
		t.Fatalf("envelope = %+v", env)
	}
	if res.stderr != "" {
		t.Fatalf("stderr = %q", res.stderr)
	}
	if got := api.last().Auth; got != "Bearer tok" {
		t.Fatalf("authorization = %q", got)
	}
}

func TestZoneListTable(t *testing.T) {
	api := defaultAPI(t)
	setToken(t, "tok")
	newHome(t)
	res := runCLI(t, "zone", "list", "--endpoint-url", api.srv.URL)
	if res.code != 0 {
		t.Fatalf("code=%d", res.code)
	}
	if !strings.Contains(res.stdout, zoneID) || !strings.Contains(res.stdout, "example.com") || !strings.Contains(res.stdout, "active") {
		t.Fatalf("table output:\n%s", res.stdout)
	}
}

func TestZoneGetByNameResolution(t *testing.T) {
	api := defaultAPI(t)
	setToken(t, "tok")
	newHome(t)
	res := runCLI(t, "zone", "get", "example.com", "--json", "--endpoint-url", api.srv.URL)
	if res.code != 0 {
		t.Fatalf("code=%d stderr=%q", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, zoneID) {
		t.Fatalf("stdout = %s", res.stdout)
	}
	// name lookup: GET /zones?name=... then GET /zones/{id}
	reqs := api.requests()
	if len(reqs) != 3 || reqs[0].Path != "/zones" || !strings.Contains(reqs[0].Query, "page=1") ||
		reqs[1].Path != "/zones" || reqs[2].Path != "/zones/"+zoneID {
		t.Fatalf("requests = %+v", reqs)
	}
}

func TestZoneListPaginationFlags(t *testing.T) {
	api := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		if method == "GET" && path == "/zones" {
			page := 1
			_, _ = fmt.Sscanf(r.Query, "page=%d", &page)
			perPage := ""
			if q := strings.SplitN(r.Query, "&", 2); len(q) > 0 {
				for _, kv := range strings.Split(r.Query, "&") {
					if strings.HasPrefix(kv, "per_page=") {
						perPage = strings.TrimPrefix(kv, "per_page=")
					}
				}
			}
			t.Logf("handler page=%d per_page=%q", page, perPage)
			if perPage == "1" {
				// one item per page, three pages total
				if page > 3 {
					return 200, envelope([]any{})
				}
				return 200, envelope([]any{zoneJSON(fmt.Sprintf("%032d", page), fmt.Sprintf("z%d.example", page), "active")})
			}
			if page > 1 {
				t.Logf("server: page=%d returning empty result", page)
				return 200, envelope([]any{})
			}
			t.Logf("server: page=%d returning 2 zones", page)
			return 200, envelope([]any{zoneJSON(zoneID, "example.com", "active"), zoneJSON("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "two.example", "active")})
		}
		s, b := apiErr(404, 0, "nope")
		return s, b
	})
	setToken(t, "tok")
	newHome(t)

	// Auto-pagination: page 1 plus a terminating empty page.
	res := runCLI(t, "zone", "list", "--endpoint-url", api.srv.URL, "--debug")
	if res.code != 0 {
		t.Fatalf("auto: %d %s", res.code, res.stderr)
	}
	if api.count() != 2 {
		t.Fatalf("auto-pagination requests = %d, want 2: %+v\nstderr:\n%s", api.count(), api.requests(), res.stderr)
	}

	// --no-paginate: single request.
	res = runCLI(t, "zone", "list", "--no-paginate", "--endpoint-url", api.srv.URL)
	if res.code != 0 || api.count() != 3 {
		t.Fatalf("no-paginate: code=%d requests=%d", res.code, api.count())
	}

	// --max-items 1 stops after the first page.
	res = runCLI(t, "zone", "list", "--max-items", "1", "--json", "--endpoint-url", api.srv.URL)
	if res.code != 0 || api.count() != 4 {
		t.Fatalf("max-items: code=%d requests=%d", res.code, api.count())
	}
	var env struct {
		Meta struct {
			Count int `json:"count"`
		} `json:"meta"`
	}
	_ = json.Unmarshal([]byte(res.stdout), &env)
	if env.Meta.Count != 1 {
		t.Fatalf("max-items count = %d", env.Meta.Count)
	}

	// --page-size 1 walks three pages then a terminating empty one.
	api.mu.Lock()
	api.reqs = nil
	api.mu.Unlock()
	res = runCLI(t, "zone", "list", "--page-size", "1", "--json", "--endpoint-url", api.srv.URL)
	if res.code != 0 {
		t.Fatalf("page-size: %d %s", res.code, res.stderr)
	}
	if api.count() != 4 {
		t.Fatalf("page-size requests = %d, want 4", api.count())
	}
	_ = json.Unmarshal([]byte(res.stdout), &env)
	if env.Meta.Count != 3 {
		t.Fatalf("page-size count = %d", env.Meta.Count)
	}
}

func TestExitCodeMappingViaCLI(t *testing.T) {
	api := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		switch path {
		case "/zones/" + zoneID:
			return apiErr(404, 7000, "zone not found")
		case "/zones":
			return apiErr(403, 9109, "forbidden")
		case "/accounts":
			return apiErr(429, 0, "rate limited")
		}
		return 200, envelope([]any{})
	})
	setToken(t, "tok")
	newHome(t)
	cases := []struct {
		args []string
		want int
	}{
		{[]string{"zone", "get", zoneID, "--endpoint-url", api.srv.URL}, errors.CodeNotFound},
		{[]string{"zone", "list", "--endpoint-url", api.srv.URL}, errors.CodePermission},
		{[]string{"account", "list", "--endpoint-url", api.srv.URL}, errors.CodeRateLimit},
	}
	for _, tc := range cases {
		res := runCLI(t, tc.args...)
		if res.code != tc.want {
			t.Errorf("%v: code=%d want=%d stderr=%q", tc.args, res.code, tc.want, res.stderr)
		}
		if !strings.Contains(res.stderr, "Error:") {
			t.Errorf("%v: no error on stderr: %q", tc.args, res.stderr)
		}
		if res.stdout != "" {
			t.Errorf("%v: machine output on stdout for failed run: %q", tc.args, res.stdout)
		}
	}
}

func TestAuthVerifyAndFailure(t *testing.T) {
	newHome(t)
	setToken(t, "good-token")
	api := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		if r.Auth == "Bearer bad-token" {
			return apiErr(400, 1000, "Invalid API Token")
		}
		return 200, envelope(map[string]any{"id": "token-1", "status": "active"})
	})
	res := runCLI(t, "auth", "verify", "--endpoint-url", api.srv.URL)
	if res.code != 0 || !strings.Contains(res.stdout, "active") {
		t.Fatalf("verify: code=%d stdout=%q", res.code, res.stdout)
	}
	setToken(t, "bad-token")
	res = runCLI(t, "auth", "verify", "--endpoint-url", api.srv.URL)
	if res.code != errors.CodeAuth {
		t.Fatalf("invalid token: code=%d, want 3", res.code)
	}
	if strings.Contains(res.stderr, "bad-token") {
		t.Fatalf("token leaked into stderr: %q", res.stderr)
	}
}

func TestMissingTokenFailsWithAuthError(t *testing.T) {
	newHome(t)
	t.Setenv("FLAREADM_API_TOKEN", "")
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	t.Setenv("CF_API_TOKEN", "")
	res := runCLI(t, "zone", "list")
	if res.code != errors.CodeAuth {
		t.Fatalf("code=%d, want 3", res.code)
	}
	if !strings.Contains(res.stderr, "FLAREADM_API_TOKEN") {
		t.Fatalf("missing guidance: %q", res.stderr)
	}
}

func TestDNSRecordDeleteGuardRails(t *testing.T) {
	api := defaultAPI(t)
	setToken(t, "tok")
	newHome(t)
	base := []string{"dns", "record", "delete", recordID, "--zone", zoneID, "--endpoint-url", api.srv.URL}

	// Non-interactive without --yes: exit 2 and no DELETE request.
	res := runCLI(t, base...)
	if res.code != errors.CodeInvalid {
		t.Fatalf("delete without --yes: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "DELETE" {
			t.Fatalf("DELETE was sent without confirmation")
		}
	}
	if !strings.Contains(res.stderr, "--yes") {
		t.Fatalf("error should mention --yes: %q", res.stderr)
	}

	// --dry-run: preview only, no DELETE.
	before := api.count()
	res = runCLI(t, append(append([]string{}, base...), "--dry-run")...)
	if res.code != 0 {
		t.Fatalf("dry-run: code=%d", res.code)
	}
	if !strings.Contains(res.stdout, "Would delete DNS record") {
		t.Fatalf("dry-run output: %q", res.stdout)
	}
	if api.count() != before+1 || api.last().Method != "GET" {
		t.Fatalf("dry-run must only fetch (GET), requests: %d -> %d %+v", before, api.count(), api.requests())
	}

	// --no-input without --yes: exit 2.
	res = runCLI(t, append(append([]string{}, base...), "--no-input")...)
	if res.code != errors.CodeInvalid {
		t.Fatalf("--no-input: code=%d", res.code)
	}

	// --yes: DELETE proceeds.
	res = runCLI(t, append(append([]string{}, base...), "--yes")...)
	if res.code != 0 {
		t.Fatalf("delete --yes: code=%d stderr=%q", res.code, res.stderr)
	}
	last := api.last()
	if last.Method != "DELETE" || last.Path != "/zones/"+zoneID+"/dns_records/"+recordID {
		t.Fatalf("last request = %+v", last)
	}
}

func TestDNSRecordCRUD(t *testing.T) {
	api := defaultAPI(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL

	res := runCLI(t, "dns", "record", "create", "--zone", zoneID, "--type", "A",
		"--name", "api", "--content", "192.0.2.10", "--ttl", "1", "--json", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("create: %d %s", res.code, res.stderr)
	}
	created := api.last()
	if created.Method != "POST" || !strings.Contains(created.Body, `"type":"A"`) || !strings.Contains(created.Body, `"name":"api"`) {
		t.Fatalf("create request: %+v", created)
	}

	// create without required flags -> exit 2, no request.
	before := api.count()
	res = runCLI(t, "dns", "record", "create", "--zone", zoneID, "--type", "A", "--endpoint-url", ep)
	if res.code != errors.CodeInvalid || api.count() != before {
		t.Fatalf("create validation: code=%d requests=%d", res.code, api.count())
	}
	// MX requires priority.
	res = runCLI(t, "dns", "record", "create", "--zone", zoneID, "--type", "MX",
		"--name", "mail", "--content", "mx.example", "--endpoint-url", ep)
	if res.code != errors.CodeInvalid {
		t.Fatalf("MX without priority: code=%d", res.code)
	}

	res = runCLI(t, "dns", "record", "get", recordID, "--zone", zoneID, "--json", "--endpoint-url", ep)
	if res.code != 0 || !strings.Contains(res.stdout, "api.example.com") {
		t.Fatalf("get: code=%d %q", res.code, res.stdout)
	}

	// update merges with the existing record (PUT with full content).
	res = runCLI(t, "dns", "record", "update", recordID, "--zone", zoneID, "--content", "192.0.2.11",
		"--json", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("update: %d %s", res.code, res.stderr)
	}
	upd := api.last()
	if upd.Method != "PUT" || !strings.Contains(upd.Body, "192.0.2.11") || !strings.Contains(upd.Body, "api.example.com") {
		t.Fatalf("update request: %+v", upd)
	}

	res = runCLI(t, "dns", "record", "list", "--zone", zoneID, "--type", "A", "--json", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("list: %d", res.code)
	}
	if !strings.Contains(api.last().Query, "type=A") {
		t.Fatalf("list filter missing: %q", api.last().Query)
	}
}

func TestDNSRecordExportAndImport(t *testing.T) {
	api := defaultAPI(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL

	res := runCLI(t, "dns", "record", "export", "--zone", zoneID, "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("export: %d %s", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "example.com.\t300\tIN\tA\t192.0.2.10") {
		t.Fatalf("export stdout: %q", res.stdout)
	}

	zoneFile := filepath.Join(t.TempDir(), "zone.txt")
	_ = os.WriteFile(zoneFile, []byte("example.com. 300 IN A 192.0.2.10\n"), 0o600)
	res = runCLI(t, "dns", "record", "import", "--zone", zoneID, "--file", zoneFile, "--json", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("import: %d %s", res.code, res.stderr)
	}
	imp := api.last()
	if imp.Method != "POST" || !strings.Contains(imp.Path, "import") || !strings.Contains(imp.Body, "192.0.2.10") {
		t.Fatalf("import request: %+v", imp)
	}
	if !strings.Contains(res.stdout, "recs_added") {
		t.Fatalf("import json: %q", res.stdout)
	}
}

func TestCachePurgeFlow(t *testing.T) {
	api := defaultAPI(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL

	res := runCLI(t, "cache", "purge", "--zone", zoneID, "--endpoint-url", ep)
	if res.code != errors.CodeInvalid {
		t.Fatalf("purge without targets: code=%d", res.code)
	}
	res = runCLI(t, "cache", "purge", "--zone", zoneID, "--everything", "--endpoint-url", ep)
	if res.code != errors.CodeInvalid {
		t.Fatalf("purge without --yes must fail non-interactively: code=%d", res.code)
	}
	res = runCLI(t, "cache", "purge", "--zone", zoneID, "--everything", "--yes", "--json", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("purge --yes: %d %s", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || !strings.Contains(req.Body, "purge_everything") {
		t.Fatalf("purge request: %+v", req)
	}
	// scoped purge
	res = runCLI(t, "cache", "purge", "--zone", zoneID, "--file", "https://example.com/a.js", "--yes", "--endpoint-url", ep)
	if res.code != 0 || !strings.Contains(api.last().Body, "https://example.com/a.js") {
		t.Fatalf("file purge: code=%d body=%q", res.code, api.last().Body)
	}
}

func TestDNSSECCommands(t *testing.T) {
	api := defaultAPI(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL

	res := runCLI(t, "dns", "dnssec", "get", "--zone", zoneID, "--json", "--endpoint-url", ep)
	if res.code != 0 || !strings.Contains(res.stdout, `"status": "active"`) {
		t.Fatalf("get: code=%d %q", res.code, res.stdout)
	}
	res = runCLI(t, "dns", "dnssec", "disable", "--zone", zoneID, "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("disable: %d %s", res.code, res.stderr)
	}
	if api.last().Method != "PATCH" || !strings.Contains(api.last().Body, `"disabled"`) {
		t.Fatalf("disable request: %+v", api.last())
	}
}

func TestAPIRawRequest(t *testing.T) {
	api := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		switch {
		case method == "GET" && path == "/zones":
			return 200, `{"success":true,"result":[{"id":"` + zoneID + `"}]}`
		case method == "POST" && path == "/echo":
			return 200, `{"got":` + r.Body + `}`
		case method == "POST" && path == "/zonefile":
			return 200, `{"file-len":` + fmt.Sprint(len(r.Body)) + `}`
		case method == "DELETE" && path == "/gone":
			return 200, `{"deleted":true}`
		}
		return 404, "not found"
	})
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL

	res := runCLI(t, "api", "request", "GET", "/zones", "--endpoint-url", ep)
	if res.code != 0 || !strings.Contains(res.stdout, zoneID) {
		t.Fatalf("GET: code=%d stdout=%q", res.code, res.stdout)
	}
	res = runCLI(t, "api", "request", "POST", "/echo", "--body", `{"x":1}`, "--endpoint-url", ep)
	if res.code != 0 || !strings.Contains(res.stdout, `{"got":{"x":1}}`) {
		t.Fatalf("inline body: code=%d stdout=%q", res.code, res.stdout)
	}

	bodyFile := filepath.Join(t.TempDir(), "body.json")
	_ = os.WriteFile(bodyFile, []byte(`{"zone_id":"`+zoneID+`"}`), 0o600)
	res = runCLI(t, "api", "request", "POST", "/zonefile", "--body", "@"+bodyFile, "--endpoint-url", ep)
	wantLen := fmt.Sprint(len(`{"zone_id":"` + zoneID + `"}`))
	if res.code != 0 || !strings.Contains(res.stdout, `"file-len":`+wantLen) {
		t.Fatalf("@file body: code=%d stdout=%q", res.code, res.stdout)
	}
	// lower-case method accepted; DELETE allowed.
	res = runCLI(t, "api", "request", "delete", "/gone", "--endpoint-url", ep)
	if res.code != 0 || api.last().Method != "DELETE" {
		t.Fatalf("delete: code=%d", res.code)
	}
	// Bad method and bad path are usage errors (exit 2).
	if res := runCLI(t, "api", "request", "FOO", "/zones"); res.code != errors.CodeInvalid {
		t.Fatalf("bad method: code=%d", res.code)
	}
	if res := runCLI(t, "api", "request", "GET", "zones"); res.code != errors.CodeInvalid {
		t.Fatalf("bad path: code=%d", res.code)
	}
	// Missing body file is a usage error.
	if res := runCLI(t, "api", "request", "POST", "/x", "--body", "@/no/such/file"); res.code != errors.CodeInvalid {
		t.Fatalf("missing file: code=%d", res.code)
	}
}

func TestRawOutputAndTextOutput(t *testing.T) {
	api := defaultAPI(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL

	res := runCLI(t, "zone", "get", zoneID, "--raw", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("raw: %d", res.code)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(res.stdout), &m); err != nil {
		t.Fatalf("raw output not JSON: %v", err)
	}
	if m["success"] != true {
		t.Fatalf("raw output should keep the Cloudflare envelope: %s", res.stdout)
	}

	res = runCLI(t, "zone", "get", zoneID, "--output", "text", "--endpoint-url", ep)
	if res.code != 0 || !strings.Contains(res.stdout, "id\t"+zoneID) {
		t.Fatalf("text: code=%d %q", res.code, res.stdout)
	}
	res = runCLI(t, "zone", "get", zoneID, "--output", "yaml", "--endpoint-url", ep)
	if res.code != 0 || !strings.Contains(res.stdout, "version: v1") {
		t.Fatalf("yaml: code=%d %q", res.code, res.stdout)
	}
	// --json conflicts with a different --output.
	if res := runCLI(t, "zone", "list", "--json", "--output", "text"); res.code != errors.CodeInvalid {
		t.Fatalf("conflict: code=%d", res.code)
	}
	// invalid --output value.
	if res := runCLI(t, "zone", "list", "--output", "xml"); res.code != errors.CodeInvalid {
		t.Fatalf("bad output: code=%d", res.code)
	}
}

func TestDebugLogsDoNotLeakToken(t *testing.T) {
	api := defaultAPI(t)
	setToken(t, "supersecret")
	newHome(t)
	res := runCLI(t, "zone", "list", "--debug", "--endpoint-url", api.srv.URL)
	if res.code != 0 {
		t.Fatalf("code=%d", res.code)
	}
	if strings.Contains(res.stderr, "supersecret") {
		t.Fatalf("token leaked into debug logs:\n%s", res.stderr)
	}
	if !strings.Contains(res.stderr, "debug") {
		t.Fatalf("expected debug lines:\n%s", res.stderr)
	}
}

func TestRetrySurfacesRateLimitExitAfterExhaustion(t *testing.T) {
	var hits int32
	api := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		atomicAdd(&hits, 1)
		return 429, `{"success":false,"errors":[{"code":0,"message":"slow down"}],"messages":[],"result":null}`
	})
	setToken(t, "tok")
	newHome(t)
	res := runCLI(t, "zone", "list", "--endpoint-url", api.srv.URL, "--timeout", "10s")
	if res.code != errors.CodeRateLimit {
		t.Fatalf("code=%d, want 7 (hits=%d)", res.code, hits)
	}
	if hits != 4 {
		t.Fatalf("hits = %d, want 4 attempts", hits)
	}
}

func TestAPIRequestOutputModes(t *testing.T) {
	api := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		switch path {
		case "/jsonx":
			return 200, `{"ok":1}`
		case "/text":
			return 200, "plain text"
		}
		s, b := apiErr(404, 0, "nope")
		return s, b
	})
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	jsonBody := `{"ok":1}`

	// Default on a non-terminal stdout: verbatim bytes, no reformatting
	// and no trailing newline appended.
	res := runCLI(t, "api", "request", "GET", "/jsonx", "--endpoint-url", ep)
	if res.code != 0 || res.stdout != jsonBody {
		t.Fatalf("default non-tty: code=%d stdout=%q", res.code, res.stdout)
	}

	// --json pretty-prints JSON.
	res = runCLI(t, "api", "request", "GET", "/jsonx", "--json", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("--json: code=%d stderr=%q", res.code, res.stderr)
	}
	if res.stdout != "{\n  \"ok\": 1\n}\n" {
		t.Fatalf("--json pretty output = %q", res.stdout)
	}

	// --output yaml converts JSON to YAML.
	res = runCLI(t, "api", "request", "GET", "/jsonx", "--output", "yaml", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("yaml: code=%d stderr=%q", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "ok: 1") {
		t.Fatalf("yaml output = %q", res.stdout)
	}

	// --raw and --output text: verbatim bytes even for JSON bodies.
	for _, extra := range [][]string{{"--raw"}, {"--output", "text"}} {
		args := append([]string{"api", "request", "GET", "/jsonx"}, extra...)
		args = append(args, "--endpoint-url", ep)
		res := runCLI(t, args...)
		if res.code != 0 || res.stdout != jsonBody {
			t.Fatalf("%v: code=%d stdout=%q", extra, res.code, res.stdout)
		}
	}

	// Non-JSON bodies are never reformatted in any mode...
	for _, extra := range [][]string{{}, {"--json"}, {"--raw"}, {"--output", "text"}} {
		args := append([]string{"api", "request", "GET", "/text"}, extra...)
		args = append(args, "--endpoint-url", ep)
		res := runCLI(t, args...)
		if res.code != 0 || res.stdout != "plain text" {
			t.Fatalf("%v non-json: code=%d stdout=%q", extra, res.code, res.stdout)
		}
	}

	// ...and a non-JSON body under --output yaml is a clear usage error.
	res = runCLI(t, "api", "request", "GET", "/text", "--output", "yaml", "--endpoint-url", ep)
	if res.code != errors.CodeInvalid {
		t.Fatalf("yaml of non-json: code=%d, want 2", res.code)
	}
	if !strings.Contains(res.stderr, "yaml") || !strings.Contains(res.stderr, "JSON") {
		t.Fatalf("yaml failure message unclear: %q", res.stderr)
	}
}

func atomicAdd(p *int32, v int32) {
	mu := &sync.Mutex{}
	mu.Lock()
	defer mu.Unlock()
	*p += v
}
