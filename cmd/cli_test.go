// Package cmd integration tests: full command executions against a fake
// Cloudflare API server and an isolated config home. Tests never touch the
// live API.
package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/version"
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
	headers http.Header
}

// setHeader adds a response header applied to the next handler result.
func (a *apiStub) setHeader(key, value string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.headers == nil {
		a.headers = http.Header{}
	}
	a.headers.Set(key, value)
}

type recordedRequest struct {
	Method string
	Path   string
	Query  string
	Body   string
	Auth   string
	Host   string
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
			Host:   r.Host,
		}
		a.mu.Lock()
		a.reqs = append(a.reqs, rec)
		a.mu.Unlock()
		status, resp := handle(r.Method, r.URL.Path, rec)
		a.mu.Lock()
		extra := a.headers
		a.headers = nil
		a.mu.Unlock()
		for k, vals := range extra {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
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
	if res.code != 0 {
		t.Fatalf("version: code=%d stderr=%q", res.code, res.stderr)
	}
	if res.stderr != "" {
		t.Fatalf("version stderr=%q", res.stderr)
	}
	// The version is legitimately overridable at link time (flake.nix and
	// .goreleaser.yaml inject -X .../version.Version, and buildGoModule's
	// checkPhase runs tests with those same ldflags), so only compare
	// against the version linked into this test binary.
	want := version.String()
	if want == "" || !versionRE.MatchString(want) {
		t.Fatalf("linked version %q does not look like a version", want)
	}
	if res.stdout != want+"\n" {
		t.Fatalf("version stdout=%q, want %q", res.stdout, want+"\n")
	}
}

// versionRE accepts plain and injected version strings (e.g. "0.1.0",
// "0.1.0-unstable-dirty", "1.2.3-rc.1").
var versionRE = regexp.MustCompile(`^[0-9][0-9A-Za-z.+\-~]*$`)

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

// ---- structured (data payload) DNS record types --------------------------

// structuredCase drives both the payload assertion and the missing-required
// flag error case for one structured type.
type structuredCase struct {
	typ      string
	args     []string       // required flags for this type
	data     map[string]any // expected "data" object in the request body
	topPrio  *float64       // expected record-level priority (URI only)
	dropArg  string         // flag plus value dropped for the required-field case
	dropFlag string         // flag name expected in the error message
}

func f64(v float64) *float64 { return &v }

var structuredCases = []structuredCase{
	{
		typ:     "CAA",
		args:    []string{"--flags", "0", "--tag", "issue", "--value", "letsencrypt.org"},
		data:    map[string]any{"flags": float64(0), "tag": "issue", "value": "letsencrypt.org"},
		dropArg: "--tag", dropFlag: "tag",
	},
	{
		typ:     "CERT",
		args:    []string{"--algorithm", "8", "--cert-type", "1", "--certificate", "MIICert", "--key-tag", "12345"},
		data:    map[string]any{"algorithm": float64(8), "type": float64(1), "certificate": "MIICert", "key_tag": float64(12345)},
		dropArg: "--key-tag", dropFlag: "key-tag",
	},
	{
		typ:     "DNSKEY",
		args:    []string{"--flags", "257", "--protocol", "3", "--algorithm", "13", "--public-key", "AAAA"},
		data:    map[string]any{"flags": float64(257), "protocol": float64(3), "algorithm": float64(13), "public_key": "AAAA"},
		dropArg: "--public-key", dropFlag: "public-key",
	},
	{
		typ:     "DS",
		args:    []string{"--key-tag", "12345", "--algorithm", "13", "--digest-type", "2", "--digest", "DEADBEEF"},
		data:    map[string]any{"key_tag": float64(12345), "algorithm": float64(13), "digest_type": float64(2), "digest": "DEADBEEF"},
		dropArg: "--digest", dropFlag: "digest",
	},
	{
		typ:     "HTTPS",
		args:    []string{"--priority", "1", "--target", "svc.example.com", "--value", "alpn=h2"},
		data:    map[string]any{"priority": float64(1), "target": "svc.example.com", "value": "alpn=h2"},
		dropArg: "--value", dropFlag: "value",
	},
	{
		typ: "LOC",
		args: []string{
			"--lat-degrees", "37", "--lat-minutes", "46", "--lat-seconds", "30", "--lat-direction", "N",
			"--long-degrees", "122", "--long-minutes", "25", "--long-seconds", "10", "--long-direction", "W",
			"--altitude", "15.5", "--precision-horz", "10", "--precision-vert", "2",
		},
		data: map[string]any{
			"lat_degrees": float64(37), "lat_minutes": float64(46), "lat_seconds": float64(30), "lat_direction": "N",
			"long_degrees": float64(122), "long_minutes": float64(25), "long_seconds": float64(10), "long_direction": "W",
			"altitude": float64(15.5), "precision_horz": float64(10), "precision_vert": float64(2),
		},
		dropArg: "--altitude", dropFlag: "altitude",
	},
	{
		typ:     "NAPTR",
		args:    []string{"--order", "100", "--preference", "10", "--flags", "S", "--service", "SIP+D2U", "--regex", "", "--replacement", "."},
		data:    map[string]any{"order": float64(100), "preference": float64(10), "flags": "S", "service": "SIP+D2U", "regex": "", "replacement": "."},
		dropArg: "--replacement", dropFlag: "replacement",
	},
	{
		typ:     "SMIMEA",
		args:    []string{"--usage", "3", "--selector", "1", "--matching-type", "1", "--certificate", "ABCD"},
		data:    map[string]any{"usage": float64(3), "selector": float64(1), "matching_type": float64(1), "certificate": "ABCD"},
		dropArg: "--certificate", dropFlag: "certificate",
	},
	{
		typ:     "SRV",
		args:    []string{"--priority", "10", "--weight", "5", "--port", "5060", "--target", "sip.example.com"},
		data:    map[string]any{"priority": float64(10), "weight": float64(5), "port": float64(5060), "target": "sip.example.com"},
		dropArg: "--target", dropFlag: "target",
	},
	{
		typ:     "SSHFP",
		args:    []string{"--algorithm", "4", "--fingerprint-type", "2", "--fingerprint", "AABBCC"},
		data:    map[string]any{"algorithm": float64(4), "type": float64(2), "fingerprint": "AABBCC"},
		dropArg: "--fingerprint", dropFlag: "fingerprint",
	},
	{
		typ:     "SVCB",
		args:    []string{"--priority", "1", "--target", "svc.example.com", "--value", "alpn=h2"},
		data:    map[string]any{"priority": float64(1), "target": "svc.example.com", "value": "alpn=h2"},
		dropArg: "--value", dropFlag: "value",
	},
	{
		typ:     "TLSA",
		args:    []string{"--usage", "3", "--selector", "1", "--matching-type", "1", "--certificate", "ABCD"},
		data:    map[string]any{"usage": float64(3), "selector": float64(1), "matching_type": float64(1), "certificate": "ABCD"},
		dropArg: "--certificate", dropFlag: "certificate",
	},
	{
		typ:     "URI",
		args:    []string{"--priority", "10", "--weight", "1", "--target", "https://example.com/"},
		data:    map[string]any{"weight": float64(1), "target": "https://example.com/"},
		topPrio: f64(10),
		dropArg: "--priority", dropFlag: "priority",
	},
}

func decodeRequestBody(t *testing.T, body string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("request body is not JSON: %v\n%s", err, body)
	}
	return m
}

func TestDNSRecordStructuredTypePayloads(t *testing.T) {
	api := defaultAPI(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL

	for _, tc := range structuredCases {
		t.Run(tc.typ, func(t *testing.T) {
			args := []string{"dns", "record", "create", "--zone", zoneID, "--type", tc.typ, "--name", "r.example.com"}
			args = append(args, tc.args...)
			args = append(args, "--endpoint-url", ep)
			res := runCLI(t, args...)
			if res.code != 0 {
				t.Fatalf("create %s: code=%d stderr=%q", tc.typ, res.code, res.stderr)
			}
			got := decodeRequestBody(t, api.last().Body)
			want := map[string]any{
				"name": "r.example.com",
				"type": tc.typ,
				"ttl":  float64(1),
				"data": tc.data,
			}
			if tc.topPrio != nil {
				want["priority"] = *tc.topPrio
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("payload mismatch\n got: %#v\nwant: %#v", got, want)
			}
			if _, hasContent := got["content"]; hasContent {
				t.Fatalf("structured payload must not carry content: %v", got)
			}

			// Required-field validation: drop one flag, expect exit 2
			// naming it and no new API request.
			before := api.count()
			reduced := make([]string, 0, len(args))
			skipNext := false
			for i, a := range args {
				if skipNext {
					skipNext = false
					continue
				}
				if a == tc.dropArg && i+1 < len(args) {
					skipNext = true
					continue
				}
				reduced = append(reduced, a)
			}
			res = runCLI(t, reduced...)
			if res.code != errors.CodeInvalid {
				t.Fatalf("missing %s: code=%d, want 2 (stderr=%q)", tc.dropArg, res.code, res.stderr)
			}
			if !strings.Contains(res.stderr, "--"+tc.dropFlag) {
				t.Fatalf("missing %s error should name --%s: %q", tc.dropArg, tc.dropFlag, res.stderr)
			}
			if api.count() != before {
				t.Fatalf("validation failure still sent a request")
			}
		})
	}
}

func TestDNSRecordStructuredValidation(t *testing.T) {
	api := defaultAPI(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(typ string, extra ...string) []string {
		args := []string{"dns", "record", "create", "--zone", zoneID, "--type", typ, "--name", "r.example.com"}
		return append(append(args, extra...), "--endpoint-url", ep)
	}

	cases := []struct {
		name string
		args []string
		want string // substring expected in stderr
	}{
		{"content type with structured flag",
			base("A", "--content", "192.0.2.1", "--target", "x.example.com"), "--target"},
		{"structured type with content",
			base("SRV", "--content", "0 5 5060 sip.example.com"), "--content"},
		{"structured flag of another type",
			base("SRV", "--priority", "10", "--weight", "5", "--port", "5060", "--target", "sip.example.com", "--usage", "3"), "--usage"},
		{"non-numeric flags for numeric field",
			base("CAA", "--flags", "abc", "--tag", "issue", "--value", "letsencrypt.org"), "--flags"},
		{"bad LOC direction",
			base("LOC", "--lat-degrees", "37", "--lat-minutes", "46", "--lat-seconds", "30", "--lat-direction", "X",
				"--long-degrees", "122", "--long-minutes", "25", "--long-seconds", "10", "--long-direction", "W", "--altitude", "15"), "--lat-direction"},
		{"priority on content type",
			base("A", "--content", "192.0.2.1", "--priority", "10"), "--priority"},
		{"proxied on structured type",
			base("SRV", "--priority", "10", "--weight", "5", "--port", "5060", "--target", "sip.example.com", "--proxied"), "--proxied"},
		{"unknown record type",
			base("BOGUS", "--content", "x"), "invalid record type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := api.count()
			res := runCLI(t, tc.args...)
			if res.code != errors.CodeInvalid {
				t.Fatalf("code=%d, want 2 (stderr=%q)", res.code, res.stderr)
			}
			if !strings.Contains(res.stderr, tc.want) {
				t.Fatalf("stderr %q should mention %q", res.stderr, tc.want)
			}
			if api.count() != before {
				t.Fatalf("invalid input still sent a request")
			}
		})
	}
}

func TestDNSRecordContentRegressionsPreserved(t *testing.T) {
	api := defaultAPI(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL

	// MX keeps its record-level priority behavior.
	res := runCLI(t, "dns", "record", "create", "--zone", zoneID, "--type", "MX", "--name", "example.com",
		"--content", "mx.example.com", "--priority", "10", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("MX: code=%d stderr=%q", res.code, res.stderr)
	}
	want := map[string]any{
		"name": "example.com", "type": "MX", "ttl": float64(1),
		"content": "mx.example.com", "priority": float64(10),
	}
	if got := decodeRequestBody(t, api.last().Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("MX payload mismatch\n got: %#v\nwant: %#v", got, want)
	}

	// OPENPGPKEY is content-based in the SDK (no data object).
	res = runCLI(t, "dns", "record", "create", "--zone", zoneID, "--type", "OPENPGPKEY", "--name", "key.example.com",
		"--content", "-----BEGIN PGP PUBLIC KEY BLOCK-----", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("OPENPGPKEY: code=%d stderr=%q", res.code, res.stderr)
	}
	if got := decodeRequestBody(t, api.last().Body); got["content"] != "-----BEGIN PGP PUBLIC KEY BLOCK-----" || got["data"] != nil {
		t.Fatalf("OPENPGPKEY payload: %#v", got)
	}
}

func TestDNSRecordStructuredUpdateMerge(t *testing.T) {
	existing := map[string]any{
		"id": recordID, "zone_id": zoneID, "zone_name": "example.com",
		"name": "_sip._tcp.example.com", "type": "SRV", "content": "",
		"ttl": 300, "proxied": false,
		"data": map[string]any{"port": 5060, "priority": 10, "target": "sip.example.com", "weight": 5},
	}
	api := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		switch {
		case method == "GET" && path == "/zones/"+zoneID+"/dns_records/"+recordID:
			return 200, envelope(existing)
		case method == "PUT" && path == "/zones/"+zoneID+"/dns_records/"+recordID:
			return 200, envelope(existing)
		}
		s, b := apiErr(404, 0, "nope")
		return s, b
	})
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL

	res := runCLI(t, "dns", "record", "update", recordID, "--zone", zoneID, "--port", "5061", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("update: code=%d stderr=%q", res.code, res.stderr)
	}
	got := decodeRequestBody(t, api.last().Body)
	want := map[string]any{
		"name": "_sip._tcp.example.com", "type": "SRV", "ttl": float64(300),
		"data": map[string]any{"port": float64(5061), "priority": float64(10), "target": "sip.example.com", "weight": float64(5)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merged payload mismatch\n got: %#v\nwant: %#v", got, want)
	}
	if _, hasContent := got["content"]; hasContent {
		t.Fatalf("merged structured payload must not carry content: %#v", got)
	}

	// Changing record families cannot inherit structured fields: required
	// flags are enforced again.
	api.mu.Lock()
	api.reqs = nil
	api.mu.Unlock()
	res = runCLI(t, "dns", "record", "update", recordID, "--zone", zoneID, "--type", "CAA", "--endpoint-url", ep)
	if res.code != errors.CodeInvalid || !strings.Contains(res.stderr, "--flags") {
		t.Fatalf("type-change validation: code=%d stderr=%q", res.code, res.stderr)
	}
}

// ---- v0.2: ssl + certificate ---------------------------------------------

func certJSON(id string) map[string]any {
	return map[string]any{
		"id": id, "zone_id": zoneID, "status": "active", "bundle_method": "ubiquitous",
		"hosts": []string{"secure.example.com"}, "issuer": "DigiCert",
		"priority":   float64(1),
		"expires_on": "2026-01-01T00:00:00Z", "uploaded_on": "2025-01-01T00:00:00Z", "modified_on": "2025-01-01T00:00:00Z",
	}
}

func settingJSON(id, value string) map[string]any {
	return map[string]any{"id": id, "value": value, "editable": true, "modified_on": "2024-01-01T00:00:00Z"}
}

// v02API serves the SSL/TLS and certificate endpoints.
func v02API(t *testing.T) *apiStub {
	return newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		settingsPrefix := "/zones/" + zoneID + "/settings/"
		switch {
		case (method == "GET" || method == "PATCH") && strings.HasPrefix(path, settingsPrefix):
			id := strings.TrimPrefix(path, settingsPrefix)
			return 200, envelope(settingJSON(id, "full"))
		case method == "GET" && path == "/zones/"+zoneID+"/ssl/universal/settings":
			return 200, envelope(map[string]any{"enabled": true})
		case method == "PATCH" && path == "/zones/"+zoneID+"/ssl/universal/settings":
			return 200, envelope(map[string]any{"enabled": strings.Contains(r.Body, "true")})
		case method == "GET" && path == "/zones/"+zoneID+"/ssl/certificate_packs":
			if strings.Contains(r.Query, "page=2") {
				return 200, envelope([]any{})
			}
			return 200, envelope([]map[string]any{{
				"id": "pack1", "type": "universal", "status": "active",
				"hosts":                 []string{"example.com", "*.example.com"},
				"certificate_authority": "digicert", "primary_certificate": "pcert1",
				"certificates": []any{},
			}})
		case method == "GET" && path == "/zones/"+zoneID+"/ssl/certificate_packs/pack1":
			return 200, envelope(map[string]any{
				"id": "pack1", "type": "universal", "status": "active",
				"hosts": []string{"example.com"}, "primary_certificate": "pcert1",
			})
		case method == "GET" && path == "/zones/"+zoneID+"/certificates":
			if strings.Contains(r.Query, "page=2") {
				return 200, envelope([]any{})
			}
			return 200, envelope([]map[string]any{certJSON("cert1")})
		case method == "GET" && path == "/zones/"+zoneID+"/certificates/cert1":
			return 200, envelope(certJSON("cert1"))
		case method == "POST" && path == "/zones/"+zoneID+"/certificates":
			return 200, envelope(certJSON("cert1"))
		case method == "DELETE" && path == "/zones/"+zoneID+"/certificates/cert1":
			return 200, envelope(map[string]any{"id": "cert1"})
		}
		s, b := apiErr(404, 7000, "not found")
		return s, b
	})
}

func TestSSLSettingGet(t *testing.T) {
	api := v02API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL

	// Single setting by name: exactly one GET.
	res := runCLI(t, "ssl", "setting", "get", "min_tls_version", "--zone", zoneID, "--json", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("code=%d stderr=%q", res.code, res.stderr)
	}
	if api.count() != 1 || api.last().Method != "GET" || api.last().Path != "/zones/"+zoneID+"/settings/min_tls_version" {
		t.Fatalf("request = %+v", api.requests())
	}
	var env struct {
		Data []map[string]any `json:"data"`
		Meta struct {
			Count int `json:"count"`
		} `json:"meta"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &env); err != nil {
		t.Fatalf("json: %v", err)
	}
	if env.Meta.Count != 1 || env.Data[0]["id"] != "min_tls_version" || env.Data[0]["value"] != "full" {
		t.Fatalf("data = %+v", env.Data)
	}

	// All settings: one GET per setting, deterministic order.
	api.mu.Lock()
	api.reqs = nil
	api.mu.Unlock()
	res = runCLI(t, "ssl", "setting", "get", "--zone", zoneID, "--json", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("all: code=%d stderr=%q", res.code, res.stderr)
	}
	reqs := api.requests()
	if len(reqs) != 6 {
		t.Fatalf("requests = %d, want 6", len(reqs))
	}
	wantOrder := cloudflare.SSLSettingsIDs
	for i, r := range reqs {
		if r.Path != "/zones/"+zoneID+"/settings/"+wantOrder[i] {
			t.Fatalf("request %d path = %q, want %q", i, r.Path, wantOrder[i])
		}
	}
	if err := json.Unmarshal([]byte(res.stdout), &env); err != nil {
		t.Fatal(err)
	}
	if env.Meta.Count != 6 {
		t.Fatalf("count = %d", env.Meta.Count)
	}

	// Table output shows NAME/VALUE/EDITABLE.
	res = runCLI(t, "ssl", "setting", "get", "ssl", "--zone", zoneID, "--endpoint-url", ep)
	if res.code != 0 || !strings.Contains(res.stdout, "NAME") || !strings.Contains(res.stdout, "ssl") {
		t.Fatalf("table: code=%d stdout=%q", res.code, res.stdout)
	}
}

func TestSSLSettingUpdate(t *testing.T) {
	api := v02API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL

	res := runCLI(t, "ssl", "setting", "update", "--zone", zoneID, "--mode", "full", "--json", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "PATCH" || req.Path != "/zones/"+zoneID+"/settings/ssl" {
		t.Fatalf("request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, map[string]any{"value": "full"}) {
		t.Fatalf("body = %#v", got)
	}

	// Multiple settings patch each one.
	api.mu.Lock()
	api.reqs = nil
	api.mu.Unlock()
	res = runCLI(t, "ssl", "setting", "update", "--zone", zoneID, "--mode", "strict", "--tls-1-3", "on", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("multi: code=%d stderr=%q", res.code, res.stderr)
	}
	reqs := api.requests()
	if len(reqs) != 2 || reqs[0].Path != "/zones/"+zoneID+"/settings/ssl" || reqs[1].Path != "/zones/"+zoneID+"/settings/tls_1_3" {
		t.Fatalf("requests = %+v", reqs)
	}
	if got := decodeRequestBody(t, reqs[1].Body); !reflect.DeepEqual(got, map[string]any{"value": "on"}) {
		t.Fatalf("tls_1_3 body = %#v", got)
	}

	// Validation: nothing to update, invalid value, invalid setting name.
	if res := runCLI(t, "ssl", "setting", "update", "--zone", zoneID, "--endpoint-url", ep); res.code != errors.CodeInvalid {
		t.Fatalf("empty update: code=%d", res.code)
	}
	if res := runCLI(t, "ssl", "setting", "update", "--zone", zoneID, "--mode", "bogus", "--endpoint-url", ep); res.code != errors.CodeInvalid {
		t.Fatalf("bad value: code=%d", res.code)
	}
	if res := runCLI(t, "ssl", "setting", "get", "bogus", "--zone", zoneID, "--endpoint-url", ep); res.code != errors.CodeInvalid {
		t.Fatalf("bad setting name: code=%d", res.code)
	}

	// dry-run previews without requests.
	before := api.count()
	res = runCLI(t, "ssl", "setting", "update", "--zone", zoneID, "--mode", "full", "--dry-run", "--endpoint-url", ep)
	if res.code != 0 || !strings.Contains(res.stdout, "Would set ssl = full") {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if api.count() != before {
		t.Fatalf("dry-run sent requests")
	}
}

func TestSSLSettingUpdateErrorAndPartial(t *testing.T) {
	// 403 on the single PATCH -> exit 4.
	api := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(403, 9109, "forbidden")
		return s, b
	})
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	res := runCLI(t, "ssl", "setting", "update", "--zone", zoneID, "--mode", "full", "--endpoint-url", ep)
	if res.code != errors.CodePermission {
		t.Fatalf("single 403: code=%d, want 4 (stderr=%q)", res.code, res.stderr)
	}

	// First PATCH ok, second 403 -> partial failure exit 9.
	api2 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		if strings.HasSuffix(path, "/settings/ssl") {
			return 200, envelope(settingJSON("ssl", "full"))
		}
		s, b := apiErr(403, 9109, "forbidden")
		return s, b
	})
	ep2 := api2.srv.URL
	res = runCLI(t, "ssl", "setting", "update", "--zone", zoneID, "--mode", "full", "--tls-1-3", "on", "--endpoint-url", ep2)
	if res.code != errors.CodePartial {
		t.Fatalf("partial: code=%d, want 9 (stderr=%q)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "partially applied") {
		t.Fatalf("partial message: %q", res.stderr)
	}
}

func TestSSLUniversal(t *testing.T) {
	api := v02API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL

	res := runCLI(t, "ssl", "universal", "get", "--zone", zoneID, "--json", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("get: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "GET" || req.Path != "/zones/"+zoneID+"/ssl/universal/settings" {
		t.Fatalf("get request = %+v", req)
	}
	if !strings.Contains(res.stdout, `"enabled": true`) {
		t.Fatalf("get output = %s", res.stdout)
	}

	res = runCLI(t, "ssl", "universal", "enable", "--zone", zoneID, "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("enable: code=%d", res.code)
	}
	req = api.last()
	if req.Method != "PATCH" || req.Path != "/zones/"+zoneID+"/ssl/universal/settings" {
		t.Fatalf("enable request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, map[string]any{"enabled": true}) {
		t.Fatalf("enable body = %#v", got)
	}

	res = runCLI(t, "ssl", "universal", "disable", "--zone", zoneID, "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("disable: code=%d", res.code)
	}
	if got := decodeRequestBody(t, api.last().Body); !reflect.DeepEqual(got, map[string]any{"enabled": false}) {
		t.Fatalf("disable body = %#v", got)
	}

	// 404 -> exit 5.
	api404 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(404, 7000, "zone not found")
		return s, b
	})
	res = runCLI(t, "ssl", "universal", "get", "--zone", zoneID, "--endpoint-url", api404.srv.URL)
	if res.code != errors.CodeNotFound {
		t.Fatalf("404: code=%d, want 5", res.code)
	}
}

func TestSSLCertificatePackListGet(t *testing.T) {
	api := v02API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL

	res := runCLI(t, "ssl", "certificate-pack", "list", "--zone", zoneID,
		"--status", "active", "--deploy", "production", "--json", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	first := api.requests()[0]
	if first.Path != "/zones/"+zoneID+"/ssl/certificate_packs" {
		t.Fatalf("path = %q", first.Path)
	}
	if !strings.Contains(first.Query, "status=active") || !strings.Contains(first.Query, "deploy=production") {
		t.Fatalf("query = %q", first.Query)
	}
	// auto-pagination: page 1 + terminating empty page
	if api.count() != 2 {
		t.Fatalf("requests = %d, want 2 (page 1 + empty)", api.count())
	}
	if !strings.Contains(res.stdout, `"id": "pack1"`) || !strings.Contains(res.stdout, `"*.example.com"`) {
		t.Fatalf("list output = %s", res.stdout)
	}

	res = runCLI(t, "ssl", "certificate-pack", "get", "pack1", "--zone", zoneID, "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("get: code=%d", res.code)
	}
	req := api.last()
	if req.Method != "GET" || req.Path != "/zones/"+zoneID+"/ssl/certificate_packs/pack1" {
		t.Fatalf("get request = %+v", req)
	}
	if !strings.Contains(res.stdout, "pack1") {
		t.Fatalf("get output = %q", res.stdout)
	}

	// invalid deploy filter -> exit 2, no request
	before := api.count()
	if res := runCLI(t, "ssl", "certificate-pack", "list", "--zone", zoneID, "--deploy", "bogus", "--endpoint-url", ep); res.code != errors.CodeInvalid {
		t.Fatalf("bad deploy: code=%d", res.code)
	}
	if api.count() != before {
		t.Fatalf("validation sent a request")
	}
}

func TestCertificateListGet(t *testing.T) {
	api := v02API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL

	res := runCLI(t, "certificate", "list", "--zone", zoneID, "--status", "active", "--json", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	first := api.requests()[0]
	if first.Path != "/zones/"+zoneID+"/certificates" || !strings.Contains(first.Query, "status=active") {
		t.Fatalf("request = %+v", first)
	}
	if api.count() != 2 {
		t.Fatalf("requests = %d, want 2 (page 1 + empty)", api.count())
	}
	if !strings.Contains(res.stdout, `"secure.example.com"`) || !strings.Contains(res.stdout, `"status": "active"`) {
		t.Fatalf("list output = %s", res.stdout)
	}

	res = runCLI(t, "certificate", "get", "cert1", "--zone", zoneID, "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("get: code=%d", res.code)
	}
	req := api.last()
	if req.Method != "GET" || req.Path != "/zones/"+zoneID+"/certificates/cert1" {
		t.Fatalf("get request = %+v", req)
	}
	if !strings.Contains(res.stdout, "cert1") || !strings.Contains(res.stdout, "active") {
		t.Fatalf("get output = %q", res.stdout)
	}

	// invalid status -> exit 2; 403 path -> exit 4.
	if res := runCLI(t, "certificate", "list", "--zone", zoneID, "--status", "bogus", "--endpoint-url", ep); res.code != errors.CodeInvalid {
		t.Fatalf("bad status: code=%d", res.code)
	}
	api403 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(403, 9109, "forbidden")
		return s, b
	})
	if res := runCLI(t, "certificate", "list", "--zone", zoneID, "--endpoint-url", api403.srv.URL); res.code != errors.CodePermission {
		t.Fatalf("403: code=%d, want 4", res.code)
	}
}

func TestCertificateCreate(t *testing.T) {
	api := v02API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(certFile, []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"), 0o600)
	_ = os.WriteFile(keyFile, []byte("-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----"), 0o600)

	res := runCLI(t, "certificate", "create", "--zone", zoneID,
		"--certificate", "@"+certFile, "--private-key", "@"+keyFile,
		"--bundle-method", "optimal", "--deploy", "production", "--type", "sni_custom",
		"--json", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || req.Path != "/zones/"+zoneID+"/certificates" {
		t.Fatalf("request = %+v", req)
	}
	want := map[string]any{
		"certificate":   "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
		"private_key":   "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----",
		"bundle_method": "optimal",
		"deploy":        "production",
		"type":          "sni_custom",
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("body mismatch\n got: %#v\nwant: %#v", got, want)
	}
	// The private key must never be echoed back to the user.
	if strings.Contains(res.stdout, "MIIE") || strings.Contains(res.stderr, "MIIE") {
		t.Fatalf("private key leaked: stdout=%q stderr=%q", res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "cert1") {
		t.Fatalf("create output = %s", res.stdout)
	}

	// Validation.
	if res := runCLI(t, "certificate", "create", "--zone", zoneID, "--endpoint-url", ep); res.code != errors.CodeInvalid {
		t.Fatalf("missing certificate: code=%d", res.code)
	}
	if res := runCLI(t, "certificate", "create", "--zone", zoneID, "--certificate", "@"+certFile, "--bundle-method", "bogus", "--endpoint-url", ep); res.code != errors.CodeInvalid {
		t.Fatalf("bad bundle method: code=%d", res.code)
	}
	if res := runCLI(t, "certificate", "create", "--zone", zoneID, "--certificate", "@/no/such/cert.pem", "--endpoint-url", ep); res.code != errors.CodeInvalid {
		t.Fatalf("missing file: code=%d", res.code)
	}
}

func TestCertificateDeleteGuardRails(t *testing.T) {
	api := v02API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := []string{"certificate", "delete", "cert1", "--zone", zoneID, "--endpoint-url", ep}

	// Non-interactive without --yes: exit 2, no DELETE.
	res := runCLI(t, base...)
	if res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d, want 2", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "DELETE" {
			t.Fatalf("DELETE sent without confirmation")
		}
	}
	if !strings.Contains(res.stderr, "--yes") {
		t.Fatalf("error should mention --yes: %q", res.stderr)
	}

	// --dry-run: GET only, preview printed.
	before := api.count()
	res = runCLI(t, append(append([]string{}, base...), "--dry-run")...)
	if res.code != 0 || !strings.Contains(res.stdout, "Would delete certificate cert1") {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if api.count() != before+1 || api.last().Method != "GET" {
		t.Fatalf("dry-run requests: %+v", api.requests())
	}

	// --yes deletes.
	res = runCLI(t, append(append([]string{}, base...), "--yes")...)
	if res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "DELETE" || req.Path != "/zones/"+zoneID+"/certificates/cert1" {
		t.Fatalf("delete request = %+v", req)
	}
	if res.stdout != "" {
		t.Fatalf("delete stdout = %q, want empty", res.stdout)
	}
}

func TestV02MissingZoneExitTwo(t *testing.T) {
	for _, args := range [][]string{
		{"ssl", "setting", "get"},
		{"ssl", "setting", "update", "--mode", "full"},
		{"ssl", "universal", "get"},
		{"ssl", "certificate-pack", "list"},
		{"certificate", "list"},
		{"certificate", "get", "cert1"},
	} {
		res := runCLI(t, args...)
		if res.code != errors.CodeInvalid {
			t.Fatalf("%v: code=%d, want 2 (stderr=%q)", args, res.code, res.stderr)
		}
		if !strings.Contains(res.stderr, "zone") {
			t.Fatalf("%v: error should mention the zone: %q", args, res.stderr)
		}
	}
}

func TestCertificatePrivateKeyFileOnly(t *testing.T) {
	api := v02API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(certFile, []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"), 0o600)
	keyPEM := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END PRIVATE KEY-----"
	_ = os.WriteFile(keyFile, []byte(keyPEM), 0o600)

	// Inline key value must be rejected with exit 2 before any request.
	before := api.count()
	res := runCLI(t, "certificate", "create", "--zone", zoneID,
		"--certificate", "@"+certFile, "--private-key", keyPEM, "--endpoint-url", ep)
	if res.code != errors.CodeInvalid {
		t.Fatalf("inline key: code=%d, want 2 (stderr=%q)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "@") || !strings.Contains(res.stderr, "private-key") {
		t.Fatalf("inline key error should point at the @file form: %q", res.stderr)
	}
	if strings.Contains(res.stderr, "MIIEvQIBADANBgkq") || strings.Contains(res.stderr, "PRIVATE KEY-----") {
		t.Fatalf("inline key material leaked into stderr: %q", res.stderr)
	}
	if api.count() != before {
		t.Fatalf("rejected inline key still sent a request")
	}

	// @file form is accepted and sent verbatim.
	res = runCLI(t, "certificate", "create", "--zone", zoneID,
		"--certificate", "@"+certFile, "--private-key", "@"+keyFile, "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("file key: code=%d stderr=%q", res.code, res.stderr)
	}
	if got := decodeRequestBody(t, api.last().Body); got["private_key"] != keyPEM {
		t.Fatalf("private_key not sent from file: %#v", got)
	}
	if strings.Contains(res.stdout, "MIIEvQIBADANBgkq") || strings.Contains(res.stderr, "MIIEvQIBADANBgkq") {
		t.Fatalf("key leaked into command output")
	}
}

func TestCertificatePrivateKeyNeverEchoedOnAPIError(t *testing.T) {
	keyPEM := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
	// A hostile/stub API echoes the request data back in a 400 body.
	api := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(400, 1004, "invalid request: "+r.Body)
		return s, b
	})
	setToken(t, "tok")
	newHome(t)
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(certFile, []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"), 0o600)
	_ = os.WriteFile(keyFile, []byte(keyPEM), 0o600)

	res := runCLI(t, "certificate", "create", "--zone", zoneID,
		"--certificate", "@"+certFile, "--private-key", "@"+keyFile,
		"--debug", "--endpoint-url", api.srv.URL)
	if res.code != errors.CodeInvalid {
		t.Fatalf("api 400: code=%d, want 2 (stderr=%q)", res.code, res.stderr)
	}
	if strings.Contains(res.stderr, "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC") ||
		strings.Contains(res.stderr, "BEGIN PRIVATE KEY") ||
		strings.Contains(res.stdout, "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC") {
		t.Fatalf("key material leaked through the API error path:\nstdout=%q\nstderr=%q", res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "[REDACTED") {
		t.Fatalf("expected redaction marker in stderr: %q", res.stderr)
	}
}

func TestCertificateCreateDryRunHidesKey(t *testing.T) {
	api := v02API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL

	certPEM, keyPEM := selfSignedCert(t, "dry.example.com")
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(certFile, []byte(certPEM), 0o600)
	_ = os.WriteFile(keyFile, []byte(keyPEM), 0o600)

	before := api.count()
	res := runCLI(t, "certificate", "create", "--zone", zoneID,
		"--certificate", "@"+certFile, "--private-key", "@"+keyFile,
		"--dry-run", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("dry-run: code=%d stderr=%q", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "Would upload a certificate") || !strings.Contains(res.stdout, "dry.example.com") {
		t.Fatalf("dry-run preview = %q", res.stdout)
	}
	if strings.Contains(res.stdout, "PRIVATE KEY") || strings.Contains(res.stdout, "MII") || strings.Contains(res.stderr, "PRIVATE KEY") {
		t.Fatalf("dry-run leaked key material: stdout=%q stderr=%q", res.stdout, res.stderr)
	}
	if api.count() != before {
		t.Fatalf("dry-run sent a request")
	}
}

// selfSignedCert returns a throwaway certificate/key pair for dry-run tests.
func selfSignedCert(t *testing.T, host string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

// ---- v0.2 slice 2: rulesets / waf / cache rules / redirect rules ----------

func envelopeWithInfo(result any, info any) string {
	b, _ := json.Marshal(map[string]any{
		"success": true, "errors": []any{}, "messages": []any{},
		"result": result, "result_info": info,
	})
	return string(b)
}

func cursorPage(items []any, cursor string) string {
	return envelopeWithInfo(items, map[string]any{"count": len(items), "per_page": 100, "cursor": cursor})
}

func rulesetJSON(id, name, phase, kind string) map[string]any {
	return map[string]any{
		"id": id, "name": name, "phase": phase, "kind": kind,
		"version": "1", "description": "desc",
		"last_updated": "2025-01-01T00:00:00Z",
	}
}

func rulesetDetailJSON(id, name, phase, kind string) map[string]any {
	out := rulesetJSON(id, name, phase, kind)
	out["rules"] = []any{map[string]any{
		"id": "r1", "action": "block", "expression": `(http.host eq "x.example.com")`,
		"description": "block it", "enabled": true, "ref": "myref",
		"action_parameters": map[string]any{"a": 1},
		"extra":             "keep-me",
	}}
	return out
}

func entrypointJSON(phase string) map[string]any {
	return map[string]any{
		"id": "ep-" + phase, "name": "phase entrypoint", "phase": phase,
		"version": "1", "last_updated": "2025-01-01T00:00:00Z",
		"rules": []any{map[string]any{
			"id": "rule1", "action": "set_cache_settings", "expression": `(http.host eq "cache.example.com")`,
			"description": "cache all", "enabled": true,
			"action_parameters": map[string]any{"cache": true},
			"extra":             "keep-me",
		}},
	}
}

// rulesAPI serves rulesets and phase entrypoints for the v0.2 slice 2 tests.
func rulesAPI(t *testing.T) *apiStub {
	return newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		switch {
		case method == "GET" && path == "/zones/"+zoneID+"/rulesets":
			if strings.Contains(r.Query, "cursor=c2") {
				return 200, cursorPage([]any{rulesetJSON("rs3", "cache rules", "http_request_cache_settings", "zone")}, "")
			}
			return 200, cursorPage([]any{
				rulesetJSON("rs1", "managed waf", "http_request_firewall_managed", "managed"),
				rulesetJSON("rs2", "custom waf", "http_request_firewall_custom", "zone"),
			}, "c2")
		case method == "GET" && path == "/accounts/"+accountID+"/rulesets":
			return 200, cursorPage([]any{rulesetJSON("ars1", "acct rules", "http_request_firewall_custom", "custom")}, "")
		case method == "GET" && path == "/zones/"+zoneID+"/rulesets/rs1":
			return 200, envelope(rulesetDetailJSON("rs1", "managed waf", "http_request_firewall_managed", "managed"))
		case method == "GET" && path == "/zones/"+zoneID+"/rulesets/rs3":
			return 200, envelope(rulesetJSON("rs3", "cache rules", "http_request_cache_settings", "zone"))
		case method == "POST" && path == "/zones/"+zoneID+"/rulesets":
			return 200, envelope(rulesetDetailJSON("rsnew", "new rules", "http_request_firewall_custom", "zone"))
		case method == "PUT" && path == "/zones/"+zoneID+"/rulesets/rs1":
			return 200, envelope(rulesetDetailJSON("rs1", "managed waf", "http_request_firewall_managed", "managed"))
		case method == "DELETE" && path == "/zones/"+zoneID+"/rulesets/rs1":
			return 200, envelope(map[string]any{"id": "rs1"})
		case strings.HasPrefix(path, "/zones/"+zoneID+"/rulesets/phases/") && strings.HasSuffix(path, "/entrypoint"):
			phase := strings.TrimSuffix(strings.TrimPrefix(path, "/zones/"+zoneID+"/rulesets/phases/"), "/entrypoint")
			switch method {
			case "GET":
				return 200, envelope(entrypointJSON(phase))
			case "PUT":
				var body map[string]any
				_ = json.Unmarshal([]byte(r.Body), &body)
				return 200, envelope(map[string]any{
					"id": "ep-" + phase, "name": "phase entrypoint", "phase": phase,
					"version": "2", "last_updated": "2025-01-02T00:00:00Z",
					"rules": body["rules"],
				})
			}
		}
		s, b := apiErr(404, 7000, "not found")
		return s, b
	})
}

func TestRulesetListAndGet(t *testing.T) {
	api := rulesAPI(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL

	res := runCLI(t, "ruleset", "list", "--zone", zoneID, "--json", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	reqs := api.requests()
	if len(reqs) != 2 {
		t.Fatalf("requests = %d, want 2 (cursor pages)", len(reqs))
	}
	if !strings.Contains(reqs[0].Query, "per_page=100") || strings.Contains(reqs[0].Query, "cursor=") {
		t.Fatalf("first page query = %q", reqs[0].Query)
	}
	if !strings.Contains(reqs[1].Query, "cursor=c2") {
		t.Fatalf("second page query = %q", reqs[1].Query)
	}
	var env struct {
		Data []map[string]any `json:"data"`
		Meta struct {
			Count int `json:"count"`
		} `json:"meta"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &env); err != nil {
		t.Fatalf("json: %v", err)
	}
	if env.Meta.Count != 3 || env.Data[0]["id"] != "rs1" || env.Data[2]["id"] != "rs3" {
		t.Fatalf("data = %+v", env.Data)
	}

	// Client-side phase filter.
	api.mu.Lock()
	api.reqs = nil
	api.mu.Unlock()
	res = runCLI(t, "ruleset", "list", "--zone", zoneID, "--phase", "http_request_firewall_managed", "--json", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("filtered: code=%d", res.code)
	}
	if err := json.Unmarshal([]byte(res.stdout), &env); err != nil {
		t.Fatal(err)
	}
	if env.Meta.Count != 1 || env.Data[0]["id"] != "rs1" {
		t.Fatalf("filtered data = %+v", env.Data)
	}

	// get
	res = runCLI(t, "ruleset", "get", "rs1", "--zone", zoneID, "--json", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("get: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "GET" || req.Path != "/zones/"+zoneID+"/rulesets/rs1" {
		t.Fatalf("get request = %+v", req)
	}
	if !strings.Contains(res.stdout, `"action": "block"`) || !strings.Contains(res.stdout, `"phase": "http_request_firewall_managed"`) {
		t.Fatalf("get output = %s", res.stdout)
	}

	// account scope uses /accounts/... and never resolves a zone.
	api.mu.Lock()
	api.reqs = nil
	api.mu.Unlock()
	res = runCLI(t, "ruleset", "list", "--account-id", accountID, "--json", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("account: code=%d stderr=%q", res.code, res.stderr)
	}
	reqs = api.requests()
	if len(reqs) != 1 || reqs[0].Path != "/accounts/"+accountID+"/rulesets" {
		t.Fatalf("account requests = %+v", reqs)
	}

	// scope and usage errors
	if res := runCLI(t, "ruleset", "list", "--zone", zoneID, "--account-id", accountID, "--endpoint-url", ep); res.code != errors.CodeInvalid {
		t.Fatalf("both scopes: code=%d", res.code)
	}
	if res := runCLI(t, "ruleset", "list"); res.code != errors.CodeInvalid {
		t.Fatalf("missing scope: code=%d", res.code)
	}
	if res := runCLI(t, "ruleset", "list", "--zone", zoneID, "--kind", "bogus", "--endpoint-url", ep); res.code != errors.CodeInvalid {
		t.Fatalf("bad kind: code=%d", res.code)
	}

	// error mapping
	api404 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(404, 7000, "ruleset not found")
		return s, b
	})
	if res := runCLI(t, "ruleset", "get", "rs1", "--zone", zoneID, "--endpoint-url", api404.srv.URL); res.code != errors.CodeNotFound {
		t.Fatalf("404: code=%d, want 5", res.code)
	}
	api403 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(403, 9109, "forbidden")
		return s, b
	})
	if res := runCLI(t, "ruleset", "list", "--zone", zoneID, "--endpoint-url", api403.srv.URL); res.code != errors.CodePermission {
		t.Fatalf("403: code=%d, want 4", res.code)
	}
}

func TestRulesetCreate(t *testing.T) {
	api := rulesAPI(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL

	rulesFile := filepath.Join(t.TempDir(), "rules.json")
	rules := `[{"action":"block","expression":"(http.host eq \"x\")","description":"d"}]`
	_ = os.WriteFile(rulesFile, []byte(rules), 0o600)

	res := runCLI(t, "ruleset", "create", "--zone", zoneID,
		"--phase", "http_request_firewall_custom", "--name", "new rules",
		"--description", "desc", "--rules", "@"+rulesFile, "--json", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || req.Path != "/zones/"+zoneID+"/rulesets" || strings.Contains(req.Query, "dry_run") {
		t.Fatalf("create request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	want := map[string]any{
		"kind": "zone", "name": "new rules", "phase": "http_request_firewall_custom",
		"description": "desc",
		"rules": []any{map[string]any{
			"action": "block", "expression": `(http.host eq "x")`, "description": "d",
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("create body mismatch\n got: %#v\nwant: %#v", got, want)
	}
	if !strings.Contains(res.stdout, `"id": "rsnew"`) {
		t.Fatalf("create output = %s", res.stdout)
	}

	// dry-run: API-native validation, preview output, no confirm.
	api.mu.Lock()
	api.reqs = nil
	api.mu.Unlock()
	res = runCLI(t, "ruleset", "create", "--zone", zoneID,
		"--phase", "http_request_firewall_custom", "--name", "new rules", "--dry-run", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("dry-run: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if !strings.Contains(req.Query, "dry_run=true") {
		t.Fatalf("dry-run query = %q", req.Query)
	}
	if !strings.Contains(res.stdout, "Would create ruleset") {
		t.Fatalf("dry-run preview = %q", res.stdout)
	}

	// validation
	for _, args := range [][]string{
		{"ruleset", "create", "--zone", zoneID, "--name", "x", "--endpoint-url", ep},
		{"ruleset", "create", "--zone", zoneID, "--phase", "p", "--endpoint-url", ep},
		{"ruleset", "create", "--zone", zoneID, "--phase", "p", "--name", "x", "--kind", "managed", "--endpoint-url", ep},
		{"ruleset", "create", "--zone", zoneID, "--phase", "p", "--name", "x", "--rules", `{"not":"array"}`, "--endpoint-url", ep},
		{"ruleset", "create", "--account-id", accountID, "--phase", "p", "--name", "x", "--endpoint-url", ep},
	} {
		if res := runCLI(t, args...); res.code != errors.CodeInvalid {
			t.Fatalf("%v: code=%d, want 2 (stderr=%q)", args, res.code, res.stderr)
		}
	}
}

func TestRulesetUpdatePreservesRules(t *testing.T) {
	api := rulesAPI(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL

	// Renaming must keep the existing rules verbatim (including unknown fields).
	res := runCLI(t, "ruleset", "update", "rs1", "--zone", zoneID, "--name", "renamed", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("update: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "PUT" || req.Path != "/zones/"+zoneID+"/rulesets/rs1" {
		t.Fatalf("update request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	if got["name"] != "renamed" || got["kind"] != "managed" || got["phase"] != "http_request_firewall_managed" {
		t.Fatalf("update body = %#v", got)
	}
	for _, forbidden := range []string{"id", "version", "last_updated"} {
		if _, ok := got[forbidden]; ok {
			t.Fatalf("update body must not carry %q: %#v", forbidden, got)
		}
	}
	rulesArr, ok := got["rules"].([]any)
	if !ok || len(rulesArr) != 1 {
		t.Fatalf("rules = %#v", got["rules"])
	}
	rule := rulesArr[0].(map[string]any)
	if rule["extra"] != "keep-me" || rule["id"] != "r1" || rule["ref"] != "myref" {
		t.Fatalf("existing rules changed: %#v", rule)
	}

	// --rules replaces the array.
	rulesFile := filepath.Join(t.TempDir(), "new-rules.json")
	_ = os.WriteFile(rulesFile, []byte(`[{"action":"skip","expression":"true"}]`), 0o600)
	api.mu.Lock()
	api.reqs = nil
	api.mu.Unlock()
	res = runCLI(t, "ruleset", "update", "rs1", "--zone", zoneID, "--rules", "@"+rulesFile, "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("rules update: code=%d stderr=%q", res.code, res.stderr)
	}
	got = decodeRequestBody(t, api.last().Body)
	if !reflect.DeepEqual(got["rules"], []any{map[string]any{"action": "skip", "expression": "true"}}) {
		t.Fatalf("replaced rules = %#v", got["rules"])
	}
	if got["name"] != "managed waf" {
		t.Fatalf("name must be preserved: %#v", got)
	}

	if res := runCLI(t, "ruleset", "update", "rs1", "--zone", zoneID, "--endpoint-url", ep); res.code != errors.CodeInvalid {
		t.Fatalf("empty update: code=%d", res.code)
	}
}

func TestRulesetDeleteGuardRails(t *testing.T) {
	api := rulesAPI(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := []string{"ruleset", "delete", "rs1", "--zone", zoneID, "--endpoint-url", ep}

	// Refusal: exit 2, no DELETE.
	res := runCLI(t, base...)
	if res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d, want 2", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "DELETE" {
			t.Fatalf("DELETE sent without confirmation")
		}
	}

	// --yes: real DELETE.
	res = runCLI(t, append(append([]string{}, base...), "--yes")...)
	if res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "DELETE" || req.Path != "/zones/"+zoneID+"/rulesets/rs1" || strings.Contains(req.Query, "dry_run") {
		t.Fatalf("delete request = %+v", req)
	}

	// --dry-run: API-native validation with dry_run=true, preview, no confirm.
	api.mu.Lock()
	api.reqs = nil
	api.mu.Unlock()
	res = runCLI(t, append(append([]string{}, base...), "--dry-run")...)
	if res.code != 0 {
		t.Fatalf("dry-run: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "DELETE" || !strings.Contains(req.Query, "dry_run=true") {
		t.Fatalf("dry-run request = %+v", req)
	}
	if !strings.Contains(res.stdout, "Would delete ruleset rs1") {
		t.Fatalf("dry-run preview = %q", res.stdout)
	}
}

func TestWAFRulesetView(t *testing.T) {
	api := rulesAPI(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL

	res := runCLI(t, "waf", "ruleset", "list", "--zone", zoneID, "--json", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	var env struct {
		Data []map[string]any `json:"data"`
		Meta struct {
			Count int `json:"count"`
		} `json:"meta"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &env); err != nil {
		t.Fatal(err)
	}
	if env.Meta.Count != 2 {
		t.Fatalf("waf list should exclude non-WAF phases: %s", res.stdout)
	}
	for _, d := range env.Data {
		if d["id"] == "rs3" {
			t.Fatalf("cache-settings ruleset leaked into the WAF view: %s", res.stdout)
		}
	}

	if res := runCLI(t, "waf", "ruleset", "list", "--zone", zoneID, "--phase", "bogus", "--endpoint-url", ep); res.code != errors.CodeInvalid {
		t.Fatalf("bad phase: code=%d", res.code)
	}

	res = runCLI(t, "waf", "ruleset", "get", "rs1", "--zone", zoneID, "--endpoint-url", ep)
	if res.code != 0 || !strings.Contains(res.stdout, "managed waf") {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}

	// A cache-phase ruleset is not a WAF ruleset.
	res = runCLI(t, "waf", "ruleset", "get", "rs3", "--zone", zoneID, "--endpoint-url", ep)
	if res.code != errors.CodeInvalid || !strings.Contains(res.stderr, "not a WAF phase") {
		t.Fatalf("non-waf get: code=%d stderr=%q", res.code, res.stderr)
	}

	// Overrides update.
	rulesFile := filepath.Join(t.TempDir(), "overrides.json")
	overrides := `[{"id":"r1","action":"log","enabled":false}]`
	_ = os.WriteFile(rulesFile, []byte(overrides), 0o600)
	res = runCLI(t, "waf", "ruleset", "update", "rs1", "--zone", zoneID, "--rules", "@"+rulesFile, "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("override: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "PUT" || req.Path != "/zones/"+zoneID+"/rulesets/rs1" {
		t.Fatalf("override request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	if !reflect.DeepEqual(got["rules"], []any{map[string]any{"id": "r1", "action": "log", "enabled": false}}) {
		t.Fatalf("override body rules = %#v", got["rules"])
	}
	if got["phase"] != "http_request_firewall_managed" || got["name"] != "managed waf" {
		t.Fatalf("override body = %#v", got)
	}
	if res := runCLI(t, "waf", "ruleset", "update", "rs1", "--zone", zoneID, "--endpoint-url", ep); res.code != errors.CodeInvalid {
		t.Fatalf("missing --rules: code=%d", res.code)
	}
}

func TestCacheRuleCRUD(t *testing.T) {
	api := rulesAPI(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	entrypoint := "/zones/" + zoneID + "/rulesets/phases/http_request_cache_settings/entrypoint"

	// list
	res := runCLI(t, "cache", "rule", "list", "--zone", zoneID, "--json", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != entrypoint || api.last().Method != "GET" {
		t.Fatalf("list request = %+v", api.last())
	}
	if !strings.Contains(res.stdout, `"id": "rule1"`) || !strings.Contains(res.stdout, "set_cache_settings") {
		t.Fatalf("list output = %s", res.stdout)
	}

	// get (found + not found)
	res = runCLI(t, "cache", "rule", "get", "rule1", "--zone", zoneID, "--endpoint-url", ep)
	if res.code != 0 || !strings.Contains(res.stdout, "rule1") {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}
	res = runCLI(t, "cache", "rule", "get", "missing", "--zone", zoneID, "--endpoint-url", ep)
	if res.code != errors.CodeNotFound {
		t.Fatalf("missing rule: code=%d, want 5", res.code)
	}

	// create -> PUT with existing + new rule
	res = runCLI(t, "cache", "rule", "create", "--zone", zoneID,
		"--action", "set_cache_settings", "--expression", `(http.host eq "x.example.com")`,
		"--description", "x", "--action-parameters", `{"cache":false}`, "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "PUT" || req.Path != entrypoint {
		t.Fatalf("create request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	rules := got["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("create rules = %#v", rules)
	}
	second := rules[1].(map[string]any)
	if second["action"] != "set_cache_settings" || second["expression"] != `(http.host eq "x.example.com")` ||
		second["description"] != "x" || second["enabled"] != true {
		t.Fatalf("created rule = %#v", second)
	}
	if !reflect.DeepEqual(second["action_parameters"], map[string]any{"cache": false}) {
		t.Fatalf("action parameters = %#v", second["action_parameters"])
	}

	// update -> preserves id and unknown fields, applies overrides
	res = runCLI(t, "cache", "rule", "update", "rule1", "--zone", zoneID, "--enabled=false", "--action", "set_cache_settings", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("update: code=%d stderr=%q", res.code, res.stderr)
	}
	got = decodeRequestBody(t, api.last().Body)
	first := got["rules"].([]any)[0].(map[string]any)
	if first["id"] != "rule1" || first["enabled"] != false || first["extra"] != "keep-me" ||
		first["expression"] != `(http.host eq "cache.example.com")` {
		t.Fatalf("updated rule = %#v", first)
	}

	// delete: refusal (no PUT), then --yes, then --dry-run
	base := []string{"cache", "rule", "delete", "rule1", "--zone", zoneID, "--endpoint-url", ep}
	before := api.count()
	res = runCLI(t, base...)
	if res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d, want 2", res.code)
	}
	if api.count() != before+1 { // only the entrypoint GET
		t.Fatalf("refusal sent writes: %+v", api.requests()[before:])
	}
	res = runCLI(t, append(append([]string{}, base...), "--yes")...)
	if res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	got = decodeRequestBody(t, api.last().Body)
	if len(got["rules"].([]any)) != 0 {
		t.Fatalf("delete did not remove the rule: %#v", got)
	}

	api.mu.Lock()
	api.reqs = nil
	api.mu.Unlock()
	res = runCLI(t, append(append([]string{}, base...), "--dry-run")...)
	if res.code != 0 {
		t.Fatalf("dry-run: code=%d stderr=%q", res.code, res.stderr)
	}
	if !strings.Contains(api.last().Query, "dry_run=true") {
		t.Fatalf("dry-run query = %q", api.last().Query)
	}
	if !strings.Contains(res.stdout, "Would delete cache rule") {
		t.Fatalf("dry-run preview = %q", res.stdout)
	}

	// usage errors
	if res := runCLI(t, "cache", "rule", "create", "--zone", zoneID, "--expression", "true", "--endpoint-url", ep); res.code != errors.CodeInvalid {
		t.Fatalf("missing action: code=%d", res.code)
	}
	if res := runCLI(t, "cache", "rule", "create", "--zone", zoneID, "--action", "x", "--endpoint-url", ep); res.code != errors.CodeInvalid {
		t.Fatalf("missing expression: code=%d", res.code)
	}
	if res := runCLI(t, "cache", "rule", "update", "rule1", "--zone", zoneID, "--endpoint-url", ep); res.code != errors.CodeInvalid {
		t.Fatalf("empty update: code=%d", res.code)
	}
	if res := runCLI(t, "cache", "rule", "list"); res.code != errors.CodeInvalid {
		t.Fatalf("missing zone: code=%d", res.code)
	}
}

func TestRedirectRulePhase(t *testing.T) {
	api := rulesAPI(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	entrypoint := "/zones/" + zoneID + "/rulesets/phases/http_request_dynamic_redirect/entrypoint"

	res := runCLI(t, "redirect", "rule", "list", "--zone", zoneID, "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != entrypoint {
		t.Fatalf("list path = %q, want %q", api.last().Path, entrypoint)
	}

	res = runCLI(t, "redirect", "rule", "create", "--zone", zoneID,
		"--action", "redirect", "--expression", `(http.request.uri.path eq "/old")`,
		"--action-parameters", `{"from_value":{"target_url":{"value":"https://example.com/new"},"status_code":301}}`,
		"--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "PUT" || req.Path != entrypoint {
		t.Fatalf("create request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	rules := got["rules"].([]any)
	if len(rules) != 2 || rules[1].(map[string]any)["action"] != "redirect" {
		t.Fatalf("create rules = %#v", rules)
	}
	params := rules[1].(map[string]any)["action_parameters"].(map[string]any)
	if _, ok := params["from_value"]; !ok {
		t.Fatalf("action parameters lost: %#v", params)
	}
}

// ---- v0.3 slice 1: r2 / kv / page-rule ------------------------------------

func r2BucketJSON(name string) map[string]any {
	return map[string]any{
		"name": name, "location": "WEUR", "storage_class": "Standard",
		"jurisdiction": "default", "creation_date": "2025-01-01T00:00:00Z",
	}
}

func namespaceJSON(id, title string) map[string]any {
	return map[string]any{"id": id, "title": title, "supports_url_encoding": true}
}

func pageRuleJSON(id string) map[string]any {
	return map[string]any{
		"id": id, "status": "active", "priority": 1,
		"targets":    []any{map[string]any{"target": "url", "constraint": map[string]any{"operator": "matches", "value": "example.com/*"}}},
		"actions":    []any{map[string]any{"id": "always_use_https"}},
		"created_on": "2025-01-01T00:00:00Z", "modified_on": "2025-01-01T00:00:00Z",
	}
}

// v03API serves R2, KV and page rule endpoints.
func v03API(t *testing.T) *apiStub {
	return newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		switch {
		// R2 buckets (cursor pagination).
		case method == "GET" && path == "/accounts/"+accountID+"/r2/buckets":
			if strings.Contains(r.Query, "cursor=c2") {
				return 200, envelopeWithInfo(map[string]any{"buckets": []any{r2BucketJSON("b3")}},
					map[string]any{"count": 1, "per_page": 100, "cursor": ""})
			}
			return 200, envelopeWithInfo(map[string]any{"buckets": []any{r2BucketJSON("b1"), r2BucketJSON("b2")}},
				map[string]any{"count": 2, "per_page": 100, "cursor": "c2"})
		case method == "POST" && path == "/accounts/"+accountID+"/r2/buckets":
			return 200, envelope(r2BucketJSON("bnew"))
		case (method == "GET" || method == "DELETE") && path == "/accounts/"+accountID+"/r2/buckets/b1":
			if method == "DELETE" {
				return 200, envelope(map[string]any{"name": "b1"})
			}
			return 200, envelope(r2BucketJSON("b1"))
		// KV namespaces (page pagination).
		case method == "GET" && path == "/accounts/"+accountID+"/storage/kv/namespaces":
			if strings.Contains(r.Query, "page=2") {
				return 200, envelope([]any{})
			}
			return 200, envelope([]any{namespaceJSON("ns1", "my namespace")})
		case method == "POST" && path == "/accounts/"+accountID+"/storage/kv/namespaces":
			return 200, envelope(namespaceJSON("nsnew", "created"))
		case (method == "GET" || method == "DELETE") && path == "/accounts/"+accountID+"/storage/kv/namespaces/ns1":
			if method == "DELETE" {
				return 200, envelope(nil)
			}
			return 200, envelope(namespaceJSON("ns1", "my namespace"))
		// KV keys (cursor pagination).
		case method == "GET" && path == "/accounts/"+accountID+"/storage/kv/namespaces/ns1/keys":
			if strings.Contains(r.Query, "cursor=kc2") {
				return 200, envelopeWithInfo([]any{map[string]any{"name": "k3"}}, map[string]any{"cursor": ""})
			}
			return 200, envelopeWithInfo([]any{
				map[string]any{"name": "k1", "metadata": map[string]any{"a": 1}},
				map[string]any{"name": "k2", "expiration": float64(1893456000)},
			}, map[string]any{"cursor": "kc2"})
		// KV value.
		case method == "GET" && path == "/accounts/"+accountID+"/storage/kv/namespaces/ns1/values/k1":
			return 200, "hello world"
		case method == "PUT" && path == "/accounts/"+accountID+"/storage/kv/namespaces/ns1/values/k1":
			return 200, `{"success":true,"errors":[],"messages":[],"result":null}`
		case method == "DELETE" && path == "/accounts/"+accountID+"/storage/kv/namespaces/ns1/values/k1":
			return 200, `{"success":true,"errors":[],"messages":[],"result":null}`
		// Page rules.
		case method == "GET" && path == "/zones/"+zoneID+"/pagerules":
			return 200, envelope([]any{pageRuleJSON("pr1")})
		case method == "POST" && path == "/zones/"+zoneID+"/pagerules":
			return 200, envelope(pageRuleJSON("prnew"))
		case (method == "GET" || method == "PATCH" || method == "DELETE") && path == "/zones/"+zoneID+"/pagerules/pr1":
			switch method {
			case "DELETE":
				return 200, envelope(map[string]any{"id": "pr1"})
			default:
				return 200, envelope(pageRuleJSON("pr1"))
			}
		}
		s, b := apiErr(404, 7000, "not found")
		return s, b
	})
}

func TestR2BucketCRUD(t *testing.T) {
	api := v03API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}

	// list: cursor pagination, filters, json output
	res := runCLI(t, base("r2", "bucket", "list", "--name-contains", "asset", "--order", "name", "--json")...)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	reqs := api.requests()
	if len(reqs) != 2 {
		t.Fatalf("requests = %d, want 2 cursor pages", len(reqs))
	}
	if !strings.Contains(reqs[0].Query, "name_contains=asset") || !strings.Contains(reqs[0].Query, "order=name") ||
		!strings.Contains(reqs[0].Query, "per_page=100") {
		t.Fatalf("query = %q", reqs[0].Query)
	}
	if !strings.Contains(reqs[1].Query, "cursor=c2") {
		t.Fatalf("page 2 query = %q", reqs[1].Query)
	}
	var env struct {
		Data []map[string]any `json:"data"`
		Meta struct {
			Count int `json:"count"`
		} `json:"meta"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &env); err != nil {
		t.Fatal(err)
	}
	if env.Meta.Count != 3 || env.Data[0]["name"] != "b1" || env.Data[2]["name"] != "b3" {
		t.Fatalf("list data = %+v", env.Data)
	}

	// jurisdiction header + no-paginate + max-items
	api.mu.Lock()
	api.reqs = nil
	api.mu.Unlock()
	res = runCLI(t, base("r2", "bucket", "list", "--jurisdiction", "eu", "--no-paginate")...)
	if res.code != 0 {
		t.Fatalf("jurisdiction: code=%d stderr=%q", res.code, res.stderr)
	}
	if len(api.requests()) != 1 {
		t.Fatalf("no-paginate requests = %d", len(api.requests()))
	}
	api.mu.Lock()
	api.reqs = nil
	api.mu.Unlock()
	res = runCLI(t, base("r2", "bucket", "list", "--max-items", "2", "--json")...)
	if res.code != 0 {
		t.Fatalf("max-items: code=%d", res.code)
	}
	if len(api.requests()) != 1 {
		t.Fatalf("max-items fetched %d pages", len(api.requests()))
	}
	if err := json.Unmarshal([]byte(res.stdout), &env); err != nil {
		t.Fatal(err)
	}
	if env.Meta.Count != 2 {
		t.Fatalf("max-items count = %d", env.Meta.Count)
	}

	// get
	res = runCLI(t, base("r2", "bucket", "get", "b1", "--json")...)
	if res.code != 0 || !strings.Contains(res.stdout, `"name": "b1"`) {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}
	if api.last().Path != "/accounts/"+accountID+"/r2/buckets/b1" {
		t.Fatalf("get path = %q", api.last().Path)
	}

	// create: exact body
	res = runCLI(t, base("r2", "bucket", "create", "--name", "assets", "--location-hint", "weur", "--storage-class", "Standard")...)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" {
		t.Fatalf("create request = %+v", req)
	}
	want := map[string]any{"name": "assets", "locationHint": "weur", "storageClass": "Standard"}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("create body mismatch\n got: %#v\nwant: %#v", got, want)
	}

	// create dry-run: preview, no POST
	before := api.count()
	res = runCLI(t, base("r2", "bucket", "create", "--name", "assets", "--dry-run")...)
	if res.code != 0 || !strings.Contains(res.stdout, "Would create R2 bucket assets") {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if api.count() != before {
		t.Fatalf("dry-run sent a request")
	}

	// validation
	for _, args := range [][]string{
		base("r2", "bucket", "create"),
		base("r2", "bucket", "create", "--name", "x", "--location-hint", "mars"),
		base("r2", "bucket", "create", "--name", "x", "--storage-class", "Glacier"),
		base("r2", "bucket", "list", "--jurisdiction", "moon"),
	} {
		if res := runCLI(t, args...); res.code != errors.CodeInvalid {
			t.Fatalf("%v: code=%d, want 2", args, res.code)
		}
	}

	// delete guard rails
	delBase := base("r2", "bucket", "delete", "b1")
	res = runCLI(t, delBase...)
	if res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "DELETE" {
			t.Fatalf("DELETE without confirmation")
		}
	}
	res = runCLI(t, append(append([]string{}, delBase...), "--dry-run")...)
	if res.code != 0 || !strings.Contains(res.stdout, "Would delete R2 bucket b1") {
		t.Fatalf("dry-run delete: code=%d stdout=%q", res.code, res.stdout)
	}
	res = runCLI(t, append(append([]string{}, delBase...), "--yes")...)
	if res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != "/accounts/"+accountID+"/r2/buckets/b1" {
		t.Fatalf("delete request = %+v", req)
	}

	// error mapping
	api404 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(404, 7000, "bucket not found")
		return s, b
	})
	if res := runCLI(t, "r2", "bucket", "get", "missing", "--account-id", accountID, "--endpoint-url", api404.srv.URL); res.code != errors.CodeNotFound {
		t.Fatalf("404: code=%d, want 5", res.code)
	}
	api403 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(403, 9109, "forbidden")
		return s, b
	})
	if res := runCLI(t, "r2", "bucket", "list", "--account-id", accountID, "--endpoint-url", api403.srv.URL); res.code != errors.CodePermission {
		t.Fatalf("403: code=%d, want 4", res.code)
	}
}

func TestR2AccountResolutionReused(t *testing.T) {
	// Discovery: a single accessible account is used automatically.
	api := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		switch {
		case method == "GET" && path == "/accounts":
			if strings.Contains(r.Query, "page=2") {
				return 200, envelope([]any{})
			}
			return 200, envelope([]any{map[string]any{"id": accountID, "name": "only"}})
		case method == "GET" && path == "/accounts/"+accountID+"/r2/buckets":
			return 200, envelopeWithInfo(map[string]any{"buckets": []any{}}, map[string]any{"cursor": ""})
		}
		s, b := apiErr(404, 0, "nope")
		return s, b
	})
	setToken(t, "tok")
	newHome(t)
	res := runCLI(t, "r2", "bucket", "list", "--endpoint-url", api.srv.URL)
	if res.code != 0 {
		t.Fatalf("discovery: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.requests()[0].Path != "/accounts" {
		t.Fatalf("expected account discovery first: %+v", api.requests())
	}

	// Ambiguous accounts -> exit 2 with the account list.
	api2 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		if method == "GET" && path == "/accounts" {
			return 200, envelope([]any{
				map[string]any{"id": accountID, "name": "one"},
				map[string]any{"id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "name": "two"},
			})
		}
		s, b := apiErr(404, 0, "nope")
		return s, b
	})
	res = runCLI(t, "r2", "bucket", "list", "--endpoint-url", api2.srv.URL)
	if res.code != errors.CodeInvalid {
		t.Fatalf("ambiguous: code=%d, want 2 (stderr=%q)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "one ("+accountID+")") {
		t.Fatalf("ambiguous message = %q", res.stderr)
	}
}

func TestKVNamespaceCRUD(t *testing.T) {
	api := v03API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}

	res := runCLI(t, base("kv", "namespace", "list", "--json")...)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.count() != 2 {
		t.Fatalf("list requests = %d, want 2 (page 1 + empty page 2)", api.count())
	}
	if !strings.Contains(res.stdout, `"id": "ns1"`) || !strings.Contains(res.stdout, "my namespace") {
		t.Fatalf("list output = %s", res.stdout)
	}

	res = runCLI(t, base("kv", "namespace", "get", "ns1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "ns1") {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}
	if api.last().Path != "/accounts/"+accountID+"/storage/kv/namespaces/ns1" {
		t.Fatalf("get path = %q", api.last().Path)
	}

	res = runCLI(t, base("kv", "namespace", "create", "--title", "created", "--jurisdiction", "eu")...)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || req.Path != "/accounts/"+accountID+"/storage/kv/namespaces" {
		t.Fatalf("create request = %+v", req)
	}
	want := map[string]any{"title": "created", "jurisdiction": "eu"}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("create body mismatch\n got: %#v\nwant: %#v", got, want)
	}
	if res := runCLI(t, base("kv", "namespace", "create")...); res.code != errors.CodeInvalid {
		t.Fatalf("missing title: code=%d", res.code)
	}

	del := base("kv", "namespace", "delete", "ns1")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete KV namespace") {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != "/accounts/"+accountID+"/storage/kv/namespaces/ns1" {
		t.Fatalf("delete request = %+v", req)
	}
}

func TestKVKeyCommands(t *testing.T) {
	api := v03API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	ns := []string{"--namespace", "ns1", "--account-id", accountID, "--endpoint-url", ep}

	// list: cursor pagination + prefix + normalized json
	res := runCLI(t, append([]string{"kv", "key", "list", "--prefix", "k"}, append(ns, "--json")...)...)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.count() != 2 {
		t.Fatalf("list requests = %d, want 2 cursor pages", api.count())
	}
	if !strings.Contains(api.requests()[0].Query, "prefix=k") || !strings.Contains(api.requests()[1].Query, "cursor=kc2") {
		t.Fatalf("queries = %q / %q", api.requests()[0].Query, api.requests()[1].Query)
	}
	if !strings.Contains(res.stdout, `"name": "k1"`) || !strings.Contains(res.stdout, `"name": "k3"`) {
		t.Fatalf("list output = %s", res.stdout)
	}

	// get: verbatim value, no added newline
	res = runCLI(t, append([]string{"kv", "key", "get", "k1"}, ns...)...)
	if res.code != 0 {
		t.Fatalf("get: code=%d stderr=%q", res.code, res.stderr)
	}
	if res.stdout != "hello world" {
		t.Fatalf("get stdout = %q", res.stdout)
	}
	// get with --json wraps the value in the envelope
	res = runCLI(t, append([]string{"kv", "key", "get", "k1"}, append(ns, "--json")...)...)
	if res.code != 0 || !strings.Contains(res.stdout, `"value": "hello world"`) {
		t.Fatalf("get json: code=%d stdout=%q", res.code, res.stdout)
	}

	// put from @file with metadata + TTL, and no value leakage in debug
	valueFile := filepath.Join(t.TempDir(), "value.json")
	_ = os.WriteFile(valueFile, []byte(`{"secret":"s3cr3t-value"}`), 0o600)
	res = runCLI(t, append([]string{"kv", "key", "put", "k1", "--value", "@" + valueFile,
		"--metadata", `{"a":1}`, "--expiration-ttl", "3600", "--debug"}, ns...)...)
	if res.code != 0 {
		t.Fatalf("put: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "PUT" || req.Path != "/accounts/"+accountID+"/storage/kv/namespaces/ns1/values/k1" {
		t.Fatalf("put request = %+v", req)
	}
	if !strings.Contains(req.Query, "expiration_ttl=3600") {
		t.Fatalf("put query = %q", req.Query)
	}
	if !strings.Contains(req.Body, "s3cr3t-value") || !strings.Contains(req.Body, "metadata") {
		t.Fatalf("put body = %q", req.Body)
	}
	if strings.Contains(res.stdout, "s3cr3t-value") || strings.Contains(res.stderr, "s3cr3t-value") {
		t.Fatalf("value leaked: stdout=%q stderr=%q", res.stdout, res.stderr)
	}

	// validation: value required, metadata must be an object, both expirations
	if res := runCLI(t, append([]string{"kv", "key", "put", "k1"}, ns...)...); res.code != errors.CodeInvalid {
		t.Fatalf("missing value: code=%d", res.code)
	}
	if res := runCLI(t, append([]string{"kv", "key", "put", "k1", "--value", "x", "--metadata", "[1]"}, ns...)...); res.code != errors.CodeInvalid {
		t.Fatalf("bad metadata: code=%d", res.code)
	}
	if res := runCLI(t, append([]string{"kv", "key", "put", "k1", "--value", "x", "--expiration", "1", "--expiration-ttl", "2"}, ns...)...); res.code != errors.CodeInvalid {
		t.Fatalf("expiration conflict: code=%d", res.code)
	}

	// delete: unknown key -> 5, refusal -> 2, dry-run, then --yes
	res = runCLI(t, append([]string{"kv", "key", "delete", "missing"}, ns...)...)
	if res.code != errors.CodeNotFound {
		t.Fatalf("missing key: code=%d, want 5", res.code)
	}
	del := append([]string{"kv", "key", "delete", "k1"}, ns...)
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "DELETE" {
			t.Fatalf("DELETE without confirmation")
		}
	}
	if res := runCLI(t, append(append([]string{}, del...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete key k1") {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != "/accounts/"+accountID+"/storage/kv/namespaces/ns1/values/k1" {
		t.Fatalf("delete request = %+v", req)
	}
}

func TestPageRuleCRUD(t *testing.T) {
	api := v03API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--zone", zoneID, "--endpoint-url", ep)
	}
	targets := `[{"target":"url","constraint":{"operator":"matches","value":"example.com/*"}}]`
	actions := `[{"id":"always_use_https"}]`

	// list with filters
	res := runCLI(t, base("page-rule", "list", "--status", "active", "--direction", "desc", "--match", "all", "--json")...)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Path != "/zones/"+zoneID+"/pagerules" {
		t.Fatalf("list path = %q", req.Path)
	}
	for _, want := range []string{"status=active", "direction=desc", "match=all"} {
		if !strings.Contains(req.Query, want) {
			t.Fatalf("list query %q missing %q", req.Query, want)
		}
	}
	if !strings.Contains(res.stdout, `"priority": 1`) || !strings.Contains(res.stdout, "always_use_https") {
		t.Fatalf("list output = %s", res.stdout)
	}

	// get
	res = runCLI(t, base("page-rule", "get", "pr1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "pr1") || !strings.Contains(res.stdout, "example.com/*") {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}

	// create: exact body
	res = runCLI(t, base("page-rule", "create", "--targets", targets, "--actions", actions, "--priority", "5", "--status", "active")...)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "POST" || req.Path != "/zones/"+zoneID+"/pagerules" {
		t.Fatalf("create request = %+v", req)
	}
	want := map[string]any{
		"targets":  []any{map[string]any{"target": "url", "constraint": map[string]any{"operator": "matches", "value": "example.com/*"}}},
		"actions":  []any{map[string]any{"id": "always_use_https"}},
		"priority": float64(5),
		"status":   "active",
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("create body mismatch\n got: %#v\nwant: %#v", got, want)
	}

	// update: PATCH carries only the provided fields
	res = runCLI(t, base("page-rule", "update", "pr1", "--priority", "2")...)
	if res.code != 0 {
		t.Fatalf("update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PATCH" {
		t.Fatalf("update request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, map[string]any{"priority": float64(2)}) {
		t.Fatalf("update body = %#v", got)
	}

	// validation
	for _, args := range [][]string{
		base("page-rule", "create", "--actions", actions),
		base("page-rule", "create", "--targets", targets),
		base("page-rule", "create", "--targets", targets, "--actions", actions, "--status", "paused"),
		base("page-rule", "create", "--targets", targets, "--actions", actions, "--priority", "0"),
		base("page-rule", "update", "pr1"),
		base("page-rule", "list", "--match", "some"),
		{"page-rule", "list"},
	} {
		if res := runCLI(t, args...); res.code != errors.CodeInvalid {
			t.Fatalf("%v: code=%d, want 2 (stderr=%q)", args, res.code, res.stderr)
		}
	}

	// delete guard rails
	del := base("page-rule", "delete", "pr1")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "DELETE" {
			t.Fatalf("DELETE without confirmation")
		}
	}
	if res := runCLI(t, append(append([]string{}, del...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete page rule pr1") {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != "/zones/"+zoneID+"/pagerules/pr1" {
		t.Fatalf("delete request = %+v", req)
	}

	// 404 mapping
	api404 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(404, 7000, "page rule not found")
		return s, b
	})
	if res := runCLI(t, "page-rule", "get", "pr1", "--zone", zoneID, "--endpoint-url", api404.srv.URL); res.code != errors.CodeNotFound {
		t.Fatalf("404: code=%d, want 5", res.code)
	}
}

// ---- v0.3 slice 2: d1 / queue ---------------------------------------------

func d1DB(id, name string) map[string]any {
	return map[string]any{
		"uuid": id, "name": name, "version": "production",
		"num_tables": float64(2), "file_size": float64(2048),
		"jurisdiction": "eu", "created_at": "2025-01-01T00:00:00Z",
		"read_replication": map[string]any{"mode": "auto"},
	}
}

func queueJSON(id, name string) map[string]any {
	return map[string]any{
		"queue_id": id, "queue_name": name,
		"created_on": "2025-01-01T00:00:00Z", "modified_on": "2025-01-02T00:00:00Z",
		"consumers_total_count": float64(1), "producers_total_count": float64(0),
		"settings":  map[string]any{"delivery_delay": float64(0), "delivery_paused": false, "message_retention_period": float64(86400)},
		"consumers": []any{map[string]any{"consumer_id": "c1", "type": "worker", "script_name": "my-worker"}},
	}
}

func consumerJSON() map[string]any {
	return map[string]any{"consumer_id": "c1", "type": "worker", "script_name": "my-worker", "dead_letter_queue": "dlq"}
}

// v04API serves D1 and Queues endpoints.
func v04API(t *testing.T) *apiStub {
	var stub *apiStub
	stub = newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		d1base := "/accounts/" + accountID + "/d1/database"
		qbase := "/accounts/" + accountID + "/queues"
		switch {
		// D1 databases
		case method == "GET" && path == d1base:
			if strings.Contains(r.Query, "page=2") {
				return 200, envelope([]any{})
			}
			return 200, envelope([]any{d1DB("db1", "app-db")})
		case method == "POST" && path == d1base:
			return 200, envelope(d1DB("dbnew", "new-db"))
		case method == "GET" && path == d1base+"/db1":
			return 200, envelope(d1DB("db1", "app-db"))
		case method == "PATCH" && path == d1base+"/db1":
			return 200, envelope(d1DB("db1", "app-db"))
		case method == "DELETE" && path == d1base+"/db1":
			return 200, envelope(nil)
		// D1 query / raw
		case method == "POST" && path == d1base+"/db1/query":
			return 200, envelope([]any{map[string]any{
				"success": true,
				"results": []any{map[string]any{"id": float64(1), "name": "alpha"}, map[string]any{"id": float64(2), "name": "beta"}},
				"meta":    map[string]any{"rows_read": float64(2), "rows_written": float64(0), "changes": float64(0), "duration": float64(1.5)},
			}})
		case method == "POST" && path == d1base+"/db1/raw":
			return 200, envelope([]any{map[string]any{
				"success": true,
				"results": []any{[]any{float64(1), "alpha"}, []any{float64(2), "beta"}},
				"meta":    map[string]any{"rows_read": float64(2), "duration": float64(2)},
			}})
		// D1 export / import
		case method == "POST" && path == d1base+"/db1/export":
			return 200, envelope(map[string]any{
				"status": "complete", "at_bookmark": "bm1",
				"result": map[string]any{"filename": "dump.sql", "signed_url": "http://" + r.Host + "/dump.sql"},
			})
		case method == "GET" && path == "/dump.sql":
			return 200, "SQL DUMP CONTENT"
		case method == "POST" && path == d1base+"/db1/import":
			if strings.Contains(r.Body, `"action":"init"`) {
				return 200, envelope(map[string]any{
					"status": "pending", "filename": "local.sql",
					"upload_url": "http://" + r.Host + "/upload",
				})
			}
			return 200, envelope(map[string]any{
				"status": "running", "filename": "local.sql",
				"result": map[string]any{"final_bookmark": "bm-final", "num_queries": float64(3)},
			})
		case method == "PUT" && path == "/upload":
			if stub != nil {
				stub.setHeader("ETag", `"etag-1"`)
			}
			return 200, ""
		// D1 time travel
		case method == "GET" && path == d1base+"/db1/time_travel/bookmark":
			return 200, envelope(map[string]any{"bookmark": "bm0"})
		case method == "POST" && path == d1base+"/db1/time_travel/restore":
			return 200, envelope(map[string]any{"bookmark": "bm0", "previous_bookmark": "bm1", "message": "restored"})
		// Queues
		case method == "GET" && path == qbase:
			return 200, envelope([]any{queueJSON("q1", "my-queue")})
		case method == "POST" && path == qbase:
			return 200, envelope(queueJSON("qnew", "new-queue"))
		case method == "GET" && path == qbase+"/q1":
			return 200, envelope(queueJSON("q1", "my-queue"))
		case method == "PATCH" && path == qbase+"/q1":
			return 200, envelope(queueJSON("q1", "my-queue"))
		case method == "DELETE" && path == qbase+"/q1":
			return 200, envelope(nil)
		case method == "GET" && path == qbase+"/q1/metrics":
			return 200, envelope(map[string]any{"backlog_bytes": float64(1024), "backlog_count": float64(7), "oldest_message_timestamp_ms": float64(1700000000000)})
		case method == "GET" && path == qbase+"/q1/consumers":
			return 200, envelope([]any{consumerJSON()})
		case method == "POST" && path == qbase+"/q1/consumers":
			return 200, envelope(consumerJSON())
		case method == "GET" && path == qbase+"/q1/consumers/c1":
			return 200, envelope(consumerJSON())
		case method == "PATCH" && path == qbase+"/q1/consumers/c1":
			return 200, envelope(consumerJSON())
		case method == "DELETE" && path == qbase+"/q1/consumers/c1":
			return 200, envelope(nil)
		case method == "POST" && path == qbase+"/q1/messages":
			return 200, envelope(map[string]any{"metadata": map[string]any{"id": "m1"}})
		case method == "POST" && path == qbase+"/q1/messages/batch":
			return 200, envelope(map[string]any{"metadata": map[string]any{"ids": []any{"m1", "m2"}}})
		case method == "POST" && path == qbase+"/q1/messages/pull":
			return 200, envelope(map[string]any{
				"messages":              []any{map[string]any{"id": "m1", "attempts": float64(1), "body": "hello", "lease_id": "L1", "timestamp_ms": float64(1700000000000)}},
				"message_backlog_count": float64(3),
			})
		case method == "POST" && path == qbase+"/q1/messages/peek":
			return 200, envelope(map[string]any{
				"messages": []any{map[string]any{"id": "m1", "attempts": float64(0), "body": "hello", "lease_id": ""}},
			})
		case method == "POST" && path == qbase+"/q1/messages/ack":
			return 200, envelope(map[string]any{"ackCount": float64(1), "retryCount": float64(1)})
		case method == "POST" && path == qbase+"/q1/messages/purge":
			return 200, envelope(nil)
		case method == "POST" && path == qbase+"/q1/purge":
			return 200, envelope(queueJSON("q1", "my-queue"))
		case method == "GET" && path == qbase+"/q1/purge":
			return 200, envelope(map[string]any{"completed": "true", "started_at": "2025-01-01T00:00:00Z"})
		}
		s, b := apiErr(404, 7000, "not found")
		return s, b
	})
	return stub
}

func TestD1DatabaseCRUD(t *testing.T) {
	api := v04API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}

	res := runCLI(t, base("d1", "database", "list", "--name", "app-db", "--json")...)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.count() != 2 {
		t.Fatalf("list requests = %d, want 2 (page pagination)", api.count())
	}
	if !strings.Contains(api.requests()[0].Query, "name=app-db") {
		t.Fatalf("list query = %q", api.requests()[0].Query)
	}
	if !strings.Contains(res.stdout, `"uuid": "db1"`) || !strings.Contains(res.stdout, "app-db") {
		t.Fatalf("list output = %s", res.stdout)
	}

	res = runCLI(t, base("d1", "database", "get", "db1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "app-db") || !strings.Contains(res.stdout, "2.0 KiB") {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}

	res = runCLI(t, base("d1", "database", "create", "--name", "new-db", "--location-hint", "weur",
		"--jurisdiction", "eu", "--read-replication-mode", "auto")...)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || req.Path != "/accounts/"+accountID+"/d1/database" {
		t.Fatalf("create request = %+v", req)
	}
	want := map[string]any{
		"name": "new-db", "primary_location_hint": "weur", "jurisdiction": "eu",
		"read_replication": map[string]any{"mode": "auto"},
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("create body mismatch\n got: %#v\nwant: %#v", got, want)
	}

	res = runCLI(t, base("d1", "database", "update", "db1", "--read-replication-mode", "disabled")...)
	if res.code != 0 {
		t.Fatalf("update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PATCH" {
		t.Fatalf("update request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, map[string]any{"read_replication": map[string]any{"mode": "disabled"}}) {
		t.Fatalf("update body = %#v", got)
	}

	// dry-run create sends nothing
	before := api.count()
	res = runCLI(t, base("d1", "database", "create", "--name", "x", "--dry-run")...)
	if res.code != 0 || !strings.Contains(res.stdout, "Would create D1 database x") || api.count() != before {
		t.Fatalf("dry-run create: code=%d stdout=%q requests=%d", res.code, res.stdout, api.count())
	}

	// validation
	for _, args := range [][]string{
		base("d1", "database", "create"),
		base("d1", "database", "create", "--name", "x", "--location-hint", "moon"),
		base("d1", "database", "create", "--name", "x", "--jurisdiction", "moon"),
		base("d1", "database", "create", "--name", "x", "--read-replication-mode", "sometimes"),
		base("d1", "database", "update", "db1"),
		base("d1", "database", "update", "db1", "--read-replication-mode", "sometimes"),
	} {
		if res := runCLI(t, args...); res.code != errors.CodeInvalid {
			t.Fatalf("%v: code=%d, want 2", args, res.code)
		}
	}

	// delete guard rails
	del := base("d1", "database", "delete", "db1")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "DELETE" {
			t.Fatalf("DELETE without confirmation")
		}
	}
	if res := runCLI(t, append(append([]string{}, del...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete D1 database app-db") {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != "/accounts/"+accountID+"/d1/database/db1" {
		t.Fatalf("delete request = %+v", req)
	}

	// error mapping
	api404 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(404, 7000, "database not found")
		return s, b
	})
	if res := runCLI(t, "d1", "database", "get", "missing", "--account-id", accountID, "--endpoint-url", api404.srv.URL); res.code != errors.CodeNotFound {
		t.Fatalf("404: code=%d, want 5", res.code)
	}
	api403 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(403, 9109, "forbidden")
		return s, b
	})
	if res := runCLI(t, "d1", "database", "list", "--account-id", accountID, "--endpoint-url", api403.srv.URL); res.code != errors.CodePermission {
		t.Fatalf("403: code=%d, want 4", res.code)
	}
}

func TestD1QueryAndRaw(t *testing.T) {
	api := v04API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}

	res := runCLI(t, base("d1", "database", "query", "db1", "--sql", "SELECT id, name FROM users", "--params", "[1, \"a\"]")...)
	if res.code != 0 {
		t.Fatalf("query: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || req.Path != "/accounts/"+accountID+"/d1/database/db1/query" {
		t.Fatalf("query request = %+v", req)
	}
	want := map[string]any{"sql": "SELECT id, name FROM users", "params": []any{float64(1), "a"}}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("query body mismatch\n got: %#v\nwant: %#v", got, want)
	}
	if !strings.Contains(res.stdout, "id") || !strings.Contains(res.stdout, "alpha") || !strings.Contains(res.stdout, "beta") {
		t.Fatalf("query table = %s", res.stdout)
	}

	// json envelope keeps statement structure
	res = runCLI(t, base("d1", "database", "query", "db1", "--sql", "SELECT 1", "--json")...)
	if res.code != 0 || !strings.Contains(res.stdout, `"success": true`) || !strings.Contains(res.stdout, `"rows_read": 2`) {
		t.Fatalf("query json: code=%d stdout=%q", res.code, res.stdout)
	}

	// --raw is byte-faithful
	res = runCLI(t, base("d1", "database", "query", "db1", "--sql", "SELECT 1", "--raw")...)
	if res.code != 0 {
		t.Fatalf("raw: code=%d stderr=%q", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, `"results"`) {
		t.Fatalf("raw output = %s", res.stdout)
	}

	// batch pass-through
	res = runCLI(t, base("d1", "database", "query", "db1", "--batch", `[{"sql":"SELECT 1"},{"sql":"SELECT 2"}]`)...)
	if res.code != 0 {
		t.Fatalf("batch: code=%d stderr=%q", res.code, res.stderr)
	}
	got := decodeRequestBody(t, api.last().Body)
	if _, ok := got["batch"]; !ok || got["sql"] != nil {
		t.Fatalf("batch body = %#v", got)
	}

	// raw command prints positional columns
	res = runCLI(t, base("d1", "database", "raw", "db1", "--sql", "SELECT id, name FROM users")...)
	if res.code != 0 {
		t.Fatalf("raw command: code=%d stderr=%q", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "C1") || !strings.Contains(res.stdout, "C2") || !strings.Contains(res.stdout, "alpha") {
		t.Fatalf("raw table = %s", res.stdout)
	}

	// validation
	for _, args := range [][]string{
		base("d1", "database", "query", "db1"),
		base("d1", "database", "query", "db1", "--params", "[1]"),
		base("d1", "database", "query", "db1", "--sql", "SELECT 1", "--params", "not-json"),
		base("d1", "database", "raw", "db1", "--batch", "not-json"),
	} {
		if res := runCLI(t, args...); res.code != errors.CodeInvalid {
			t.Fatalf("%v: code=%d, want 2 (stderr=%q)", args, res.code, res.stderr)
		}
	}

	// 404 mapping
	api404 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(404, 7000, "database not found")
		return s, b
	})
	if res := runCLI(t, "d1", "database", "query", "db1", "--sql", "SELECT 1", "--account-id", accountID, "--endpoint-url", api404.srv.URL); res.code != errors.CodeNotFound {
		t.Fatalf("404: code=%d, want 5", res.code)
	}
}

func TestD1ExportAndImport(t *testing.T) {
	api := v04API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}

	// export
	res := runCLI(t, base("d1", "database", "export", "db1", "--bookmark", "bm1")...)
	if res.code != 0 {
		t.Fatalf("export: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || req.Path != "/accounts/"+accountID+"/d1/database/db1/export" {
		t.Fatalf("export request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, map[string]any{"output_format": "polling", "current_bookmark": "bm1"}) {
		t.Fatalf("export body = %#v", got)
	}
	if !strings.Contains(res.stdout, "complete") || !strings.Contains(res.stdout, "dump.sql") {
		t.Fatalf("export output = %s", res.stdout)
	}
	if res := runCLI(t, base("d1", "database", "export", "db1", "--output-format", "csv")...); res.code != errors.CodeInvalid {
		t.Fatalf("bad format: code=%d", res.code)
	}

	// export --download
	dl := filepath.Join(t.TempDir(), "dump.sql")
	res = runCLI(t, base("d1", "database", "export", "db1", "--download", dl)...)
	if res.code != 0 {
		t.Fatalf("export download: code=%d stderr=%q", res.code, res.stderr)
	}
	content, err := os.ReadFile(dl)
	if err != nil || string(content) != "SQL DUMP CONTENT" {
		t.Fatalf("download content = %q err=%v", content, err)
	}

	// single import step
	res = runCLI(t, base("d1", "database", "import", "db1", "--action", "ingest", "--filename", "local.sql",
		"--etag", "e1", "--bookmark", "bm1")...)
	if res.code != 0 {
		t.Fatalf("import step: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "POST" || req.Path != "/accounts/"+accountID+"/d1/database/db1/import" {
		t.Fatalf("import request = %+v", req)
	}
	want := map[string]any{"action": "ingest", "filename": "local.sql", "etag": "e1", "current_bookmark": "bm1"}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("import body mismatch\n got: %#v\nwant: %#v", got, want)
	}
	if !strings.Contains(res.stdout, "bm-final") {
		t.Fatalf("import output = %s", res.stdout)
	}
	if res := runCLI(t, base("d1", "database", "import", "db1", "--action", "bogus")...); res.code != errors.CodeInvalid {
		t.Fatalf("bad action: code=%d", res.code)
	}

	// full --file flow (init -> upload -> ingest)
	sqlFile := filepath.Join(t.TempDir(), "local.sql")
	_ = os.WriteFile(sqlFile, []byte("CREATE TABLE t (id INT);"), 0o600)
	api.mu.Lock()
	api.reqs = nil
	api.mu.Unlock()
	res = runCLI(t, base("d1", "database", "import", "db1", "--file", "@"+sqlFile)...)
	if res.code != 0 {
		t.Fatalf("import flow: code=%d stderr=%q", res.code, res.stderr)
	}
	reqs := api.requests()
	if len(reqs) != 3 {
		t.Fatalf("import flow requests = %d, want 3 (init, upload, ingest): %+v", len(reqs), reqs)
	}
	if !strings.Contains(reqs[0].Body, `"action":"init"`) || !strings.Contains(reqs[0].Body, `"filename":"local.sql"`) {
		t.Fatalf("init body = %q", reqs[0].Body)
	}
	if reqs[1].Method != "PUT" || !strings.Contains(reqs[1].Body, "CREATE TABLE t") {
		t.Fatalf("upload request = %+v", reqs[1])
	}
	if !strings.Contains(reqs[2].Body, `"action":"ingest"`) || !strings.Contains(reqs[2].Body, `"etag":"`) {
		t.Fatalf("ingest body = %q", reqs[2].Body)
	}
	for _, step := range []string{"import: init ok", "import: uploaded", "import: ingest ok"} {
		if !strings.Contains(res.stderr, step) {
			t.Fatalf("step %q missing from stderr: %q", step, res.stderr)
		}
	}

	// --wait with a failing poll exits 9 and names the final bookmark
	apiFail := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		switch {
		case method == "POST" && strings.HasSuffix(path, "/import"):
			if strings.Contains(r.Body, `"action":"init"`) {
				return 200, envelope(map[string]any{"status": "pending", "filename": "local.sql", "upload_url": "http://" + r.Host + "/upload"})
			}
			if strings.Contains(r.Body, `"action":"ingest"`) {
				return 200, envelope(map[string]any{"status": "running", "result": map[string]any{"final_bookmark": "bm-final"}})
			}
			s, b := apiErr(500, 0, "poll exploded")
			return s, b
		case method == "PUT" && path == "/upload":
			return 200, ""
		}
		s, b := apiErr(404, 0, "nope")
		return s, b
	})
	res = runCLI(t, "d1", "database", "import", "db1", "--file", "@"+sqlFile, "--wait",
		"--account-id", accountID, "--endpoint-url", apiFail.srv.URL)
	if res.code != errors.CodePartial {
		t.Fatalf("wait failure: code=%d, want 9 (stderr=%q)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "bm-final") {
		t.Fatalf("partial error must name the final bookmark: %q", res.stderr)
	}

	// validation
	for _, args := range [][]string{
		base("d1", "database", "import", "db1"),
		base("d1", "database", "import", "db1", "--file", "@"+sqlFile, "--action", "init"),
		base("d1", "database", "import", "db1", "--action", "init", "--wait"),
		base("d1", "database", "import", "db1", "--file", "@/no/such/file.sql"),
	} {
		if res := runCLI(t, args...); res.code != errors.CodeInvalid {
			t.Fatalf("%v: code=%d, want 2 (stderr=%q)", args, res.code, res.stderr)
		}
	}
}

func TestD1TimeTravel(t *testing.T) {
	api := v04API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}

	res := runCLI(t, base("d1", "database", "bookmark", "db1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "bm0") {
		t.Fatalf("bookmark: code=%d stdout=%q", res.code, res.stdout)
	}
	req := api.last()
	if req.Method != "GET" || req.Path != "/accounts/"+accountID+"/d1/database/db1/time_travel/bookmark" || req.Query != "" {
		t.Fatalf("bookmark request = %+v", req)
	}

	res = runCLI(t, base("d1", "database", "bookmark", "db1", "--timestamp", "2026-01-02T15:04:05Z")...)
	if res.code != 0 {
		t.Fatalf("bookmark ts: code=%d stderr=%q", res.code, res.stderr)
	}
	if !strings.Contains(api.last().Query, "timestamp=2026-01-02T15%3A04%3A05Z") {
		t.Fatalf("bookmark timestamp query = %q", api.last().Query)
	}

	// restore guard rails
	res = runCLI(t, base("d1", "database", "restore", "db1", "--bookmark", "bm0")...)
	if res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	before := api.count()
	res = runCLI(t, base("d1", "database", "restore", "db1", "--bookmark", "bm0", "--dry-run")...)
	if res.code != 0 || !strings.Contains(res.stdout, "Would restore D1 database db1 to bm0") || api.count() != before {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	res = runCLI(t, base("d1", "database", "restore", "db1", "--bookmark", "bm0", "--yes")...)
	if res.code != 0 {
		t.Fatalf("restore: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "POST" || !strings.Contains(req.Query, "bookmark=bm0") {
		t.Fatalf("restore request = %+v", req)
	}
	for _, args := range [][]string{
		base("d1", "database", "restore", "db1"),
		base("d1", "database", "restore", "db1", "--bookmark", "bm0", "--timestamp", "2026-01-02T15:04:05Z"),
		base("d1", "database", "bookmark", "db1", "--timestamp", "not-a-time"),
	} {
		if res := runCLI(t, args...); res.code != errors.CodeInvalid {
			t.Fatalf("%v: code=%d, want 2", args, res.code)
		}
	}
}

func TestQueueCRUD(t *testing.T) {
	api := v04API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}

	res := runCLI(t, base("queue", "list", "--json")...)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, `"queue_name": "my-queue"`) {
		t.Fatalf("list output = %s", res.stdout)
	}
	if api.last().Path != "/accounts/"+accountID+"/queues" {
		t.Fatalf("list path = %q", api.last().Path)
	}

	res = runCLI(t, base("queue", "get", "q1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "my-queue") {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}

	res = runCLI(t, base("queue", "create", "--name", "new-queue")...)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || req.Path != "/accounts/"+accountID+"/queues" {
		t.Fatalf("create request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, map[string]any{"queue_name": "new-queue"}) {
		t.Fatalf("create body = %#v", got)
	}
	if res := runCLI(t, base("queue", "create")...); res.code != errors.CodeInvalid {
		t.Fatalf("missing name: code=%d", res.code)
	}

	res = runCLI(t, base("queue", "update", "q1", "--delivery-delay", "60", "--delivery-paused")...)
	if res.code != 0 {
		t.Fatalf("update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PATCH" {
		t.Fatalf("update request = %+v", req)
	}
	want := map[string]any{"queue": map[string]any{"settings": map[string]any{"delivery_delay": float64(60), "delivery_paused": true}}}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("update body mismatch\n got: %#v\nwant: %#v", got, want)
	}
	if res := runCLI(t, base("queue", "update", "q1")...); res.code != errors.CodeInvalid {
		t.Fatalf("empty update: code=%d", res.code)
	}

	res = runCLI(t, base("queue", "metrics", "q1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "1024") || !strings.Contains(res.stdout, "7") {
		t.Fatalf("metrics: code=%d stdout=%q", res.code, res.stdout)
	}

	// delete guard rails
	del := base("queue", "delete", "q1")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "DELETE" {
			t.Fatalf("DELETE without confirmation")
		}
	}
	if res := runCLI(t, append(append([]string{}, del...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete queue my-queue") {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != "/accounts/"+accountID+"/queues/q1" {
		t.Fatalf("delete request = %+v", req)
	}

	// error mapping
	api404 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(404, 7000, "queue not found")
		return s, b
	})
	if res := runCLI(t, "queue", "get", "q1", "--account-id", accountID, "--endpoint-url", api404.srv.URL); res.code != errors.CodeNotFound {
		t.Fatalf("404: code=%d, want 5", res.code)
	}
	api403 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(403, 9109, "forbidden")
		return s, b
	})
	if res := runCLI(t, "queue", "list", "--account-id", accountID, "--endpoint-url", api403.srv.URL); res.code != errors.CodePermission {
		t.Fatalf("403: code=%d, want 4", res.code)
	}
	// Missing account scope with several accessible accounts -> exit 2.
	apiAmbig := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		if method == "GET" && path == "/accounts" {
			return 200, envelope([]any{
				map[string]any{"id": accountID, "name": "one"},
				map[string]any{"id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "name": "two"},
			})
		}
		s, b := apiErr(404, 0, "nope")
		return s, b
	})
	res = runCLI(t, "queue", "list", "--endpoint-url", apiAmbig.srv.URL)
	if res.code != errors.CodeInvalid {
		t.Fatalf("ambiguous account: code=%d, want 2 (stderr=%q)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "one ("+accountID+")") {
		t.Fatalf("ambiguous message = %q", res.stderr)
	}
}

func TestQueueConsumerCRUD(t *testing.T) {
	api := v04API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}

	res := runCLI(t, base("queue", "consumer", "list", "q1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "my-worker") {
		t.Fatalf("list: code=%d stdout=%q", res.code, res.stdout)
	}
	if api.last().Path != "/accounts/"+accountID+"/queues/q1/consumers" {
		t.Fatalf("list path = %q", api.last().Path)
	}

	res = runCLI(t, base("queue", "consumer", "get", "q1", "c1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "c1") {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}
	if api.last().Path != "/accounts/"+accountID+"/queues/q1/consumers/c1" {
		t.Fatalf("get path = %q", api.last().Path)
	}

	res = runCLI(t, base("queue", "consumer", "create", "q1", "--type", "worker", "--script", "my-worker", "--dead-letter-queue", "dlq")...)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || req.Path != "/accounts/"+accountID+"/queues/q1/consumers" {
		t.Fatalf("create request = %+v", req)
	}
	want := map[string]any{"type": "worker", "script_name": "my-worker", "dead_letter_queue": "dlq"}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("create body mismatch\n got: %#v\nwant: %#v", got, want)
	}

	// http_pull with settings
	res = runCLI(t, base("queue", "consumer", "create", "q1", "--type", "http_pull", "--settings", `{"batch_size":10}`)...)
	if res.code != 0 {
		t.Fatalf("http_pull create: code=%d stderr=%q", res.code, res.stderr)
	}
	got := decodeRequestBody(t, api.last().Body)
	if got["type"] != "http_pull" || !reflect.DeepEqual(got["settings"], map[string]any{"batch_size": float64(10)}) {
		t.Fatalf("http_pull body = %#v", got)
	}

	// validation
	for _, args := range [][]string{
		base("queue", "consumer", "create", "q1"),
		base("queue", "consumer", "create", "q1", "--type", "worker"),
		base("queue", "consumer", "create", "q1", "--type", "bogus"),
		base("queue", "consumer", "create", "q1", "--type", "worker", "--script", "s", "--settings", "[1]"),
		base("queue", "consumer", "update", "q1", "c1"),
	} {
		if res := runCLI(t, args...); res.code != errors.CodeInvalid {
			t.Fatalf("%v: code=%d, want 2 (stderr=%q)", args, res.code, res.stderr)
		}
	}

	// update
	res = runCLI(t, base("queue", "consumer", "update", "q1", "c1", "--script", "other-worker")...)
	if res.code != 0 {
		t.Fatalf("update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PATCH" {
		t.Fatalf("update request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, map[string]any{"script_name": "other-worker"}) {
		t.Fatalf("update body = %#v", got)
	}

	// delete guard rails
	del := base("queue", "consumer", "delete", "q1", "c1")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "DELETE" {
			t.Fatalf("DELETE without confirmation")
		}
	}
	if res := runCLI(t, append(append([]string{}, del...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete consumer c1") {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != "/accounts/"+accountID+"/queues/q1/consumers/c1" {
		t.Fatalf("delete request = %+v", req)
	}
}

func TestQueueMessages(t *testing.T) {
	api := v04API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}

	// push text
	res := runCLI(t, base("queue", "message", "push", "q1", "--body", "hello")...)
	if res.code != 0 {
		t.Fatalf("push text: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || req.Path != "/accounts/"+accountID+"/queues/q1/messages" {
		t.Fatalf("push request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, map[string]any{"body": "hello", "content_type": "text"}) {
		t.Fatalf("push text body = %#v", got)
	}
	if !strings.Contains(res.stdout, "m1") {
		t.Fatalf("push output = %s", res.stdout)
	}

	// push json (parsed value, not a string)
	res = runCLI(t, base("queue", "message", "push", "q1", "--body", `{"k":"v"}`, "--content-type", "json", "--delay-seconds", "5")...)
	if res.code != 0 {
		t.Fatalf("push json: code=%d stderr=%q", res.code, res.stderr)
	}
	want := map[string]any{"body": map[string]any{"k": "v"}, "content_type": "json", "delay_seconds": float64(5)}
	if got := decodeRequestBody(t, api.last().Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("push json body mismatch\n got: %#v\nwant: %#v", got, want)
	}

	// bulk push
	res = runCLI(t, base("queue", "message", "push", "q1", "--bulk", `[{"body":"a","content_type":"text"}]`)...)
	if res.code != 0 {
		t.Fatalf("bulk: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != "/accounts/"+accountID+"/queues/q1/messages/batch" {
		t.Fatalf("bulk path = %q", api.last().Path)
	}

	// validation
	for _, args := range [][]string{
		base("queue", "message", "push", "q1"),
		base("queue", "message", "push", "q1", "--body", "x", "--bulk", "[]"),
		base("queue", "message", "push", "q1", "--body", "not-json", "--content-type", "json"),
		base("queue", "message", "push", "q1", "--body", "x", "--content-type", "xml"),
		base("queue", "message", "push", "q1", "--bulk", `{"not":"array"}`),
	} {
		if res := runCLI(t, args...); res.code != errors.CodeInvalid {
			t.Fatalf("%v: code=%d, want 2 (stderr=%q)", args, res.code, res.stderr)
		}
	}

	// pull
	res = runCLI(t, base("queue", "message", "pull", "q1", "--batch-size", "5", "--visibility-timeout-ms", "1000")...)
	if res.code != 0 {
		t.Fatalf("pull: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Path != "/accounts/"+accountID+"/queues/q1/messages/pull" {
		t.Fatalf("pull path = %q", req.Path)
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, map[string]any{"batch_size": float64(5), "visibility_timeout_ms": float64(1000)}) {
		t.Fatalf("pull body = %#v", got)
	}
	if !strings.Contains(res.stdout, "m1") || !strings.Contains(res.stdout, "L1") {
		t.Fatalf("pull output = %s", res.stdout)
	}

	// peek
	res = runCLI(t, base("queue", "message", "peek", "q1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "hello") {
		t.Fatalf("peek: code=%d stdout=%q", res.code, res.stdout)
	}

	// ack
	res = runCLI(t, base("queue", "message", "ack", "q1", "--ack", "L1", "--retry", "L2")...)
	if res.code != 0 {
		t.Fatalf("ack: code=%d stderr=%q", res.code, res.stderr)
	}
	if got := decodeRequestBody(t, api.last().Body); !reflect.DeepEqual(got, map[string]any{"acks": []any{"L1"}, "retries": []any{"L2"}}) {
		t.Fatalf("ack body = %#v", got)
	}
	if !strings.Contains(res.stdout, "ACKED") {
		t.Fatalf("ack output = %s", res.stdout)
	}
	if res := runCLI(t, base("queue", "message", "ack", "q1")...); res.code != errors.CodeInvalid {
		t.Fatalf("ack without ids: code=%d", res.code)
	}

	// message delete guard rails
	del := base("queue", "message", "delete", "q1", "--ref", "L1")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Path == "/accounts/"+accountID+"/queues/q1/messages/purge" {
			t.Fatalf("purge sent without confirmation")
		}
	}
	if res := runCLI(t, append(append([]string{}, del...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete 1 message(s)") {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if got := decodeRequestBody(t, api.last().Body); !reflect.DeepEqual(got, map[string]any{"refs": []any{"L1"}}) {
		t.Fatalf("purge body = %#v", got)
	}
	if res := runCLI(t, base("queue", "message", "delete", "q1")...); res.code != errors.CodeInvalid {
		t.Fatalf("delete without refs: code=%d", res.code)
	}
}

func TestQueuePurge(t *testing.T) {
	api := v04API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}

	start := base("queue", "purge", "q1")
	res := runCLI(t, start...)
	if res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Path == "/accounts/"+accountID+"/queues/q1/purge" && r.Method == "POST" {
			t.Fatalf("purge started without confirmation")
		}
	}
	before := api.count()
	res = runCLI(t, append(append([]string{}, start...), "--dry-run")...)
	if res.code != 0 || !strings.Contains(res.stdout, "Would purge queue q1") || api.count() != before {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	res = runCLI(t, append(append([]string{}, start...), "--yes", "--permanent")...)
	if res.code != 0 {
		t.Fatalf("purge: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || req.Path != "/accounts/"+accountID+"/queues/q1/purge" {
		t.Fatalf("purge request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, map[string]any{"delete_messages_permanently": true}) {
		t.Fatalf("purge body = %#v", got)
	}

	res = runCLI(t, base("queue", "purge", "get", "q1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "true") {
		t.Fatalf("purge status: code=%d stdout=%q", res.code, res.stdout)
	}
	if api.last().Method != "GET" {
		t.Fatalf("purge status method = %s", api.last().Method)
	}
}

func TestPayloadHygiene(t *testing.T) {
	// A hostile API echoes the request body back in its error message.
	echoStub := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(400, 1004, "bad request: "+r.Body)
		return s, b
	})
	setToken(t, "tok")
	newHome(t)
	ep := echoStub.srv.URL

	cases := []struct {
		name   string
		marker string
		args   []string
	}{
		{"d1 query params", "S3CR3T-D1-PARAMS",
			[]string{"d1", "database", "query", "db1", "--sql", "SELECT ?",
				"--params", `["S3CR3T-D1-PARAMS"]`, "--account-id", accountID, "--debug", "--endpoint-url", ep}},
		{"d1 batch payload", "S3CR3T-D1-BATCH",
			[]string{"d1", "database", "query", "db1",
				"--batch", `[{"sql":"SELECT 'S3CR3T-D1-BATCH'"}]`, "--account-id", accountID, "--debug", "--endpoint-url", ep}},
		{"queue message body", "S3CR3T-QUEUE-BODY",
			[]string{"queue", "message", "push", "q1", "--body", "S3CR3T-QUEUE-BODY",
				"--account-id", accountID, "--debug", "--endpoint-url", ep}},
		{"queue bulk payload", "S3CR3T-QUEUE-BULK",
			[]string{"queue", "message", "push", "q1", "--bulk", `[{"body":"S3CR3T-QUEUE-BULK","content_type":"text"}]`,
				"--account-id", accountID, "--debug", "--endpoint-url", ep}},
		{"kv value", "S3CR3T-KV-VALUE",
			[]string{"kv", "key", "put", "k1", "--namespace", "ns1", "--value", "S3CR3T-KV-VALUE",
				"--account-id", accountID, "--debug", "--endpoint-url", ep}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runCLI(t, tc.args...)
			if res.code != errors.CodeInvalid {
				t.Fatalf("code=%d, want 2 (stderr=%q)", res.code, res.stderr)
			}
			if !strings.Contains(res.stderr, "debug:") {
				t.Fatalf("expected debug diagnostics to be active: %q", res.stderr)
			}
			if strings.Contains(res.stdout, tc.marker) || strings.Contains(res.stderr, tc.marker) {
				t.Fatalf("payload leaked:\nstdout=%q\nstderr=%q", res.stdout, res.stderr)
			}
		})
	}

	// D1 import file bytes: the signed upload endpoint echoes the file.
	fileStub := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		switch {
		case method == "POST" && strings.HasSuffix(path, "/import"):
			return 200, envelope(map[string]any{"status": "pending", "filename": "dump.sql", "upload_url": "http://" + r.Host + "/upload"})
		case method == "PUT" && path == "/upload":
			s, b := apiErr(400, 1004, "echo: "+r.Body)
			return s, b
		}
		s, b := apiErr(404, 0, "nope")
		return s, b
	})
	sqlFile := filepath.Join(t.TempDir(), "dump.sql")
	_ = os.WriteFile(sqlFile, []byte("CREATE TABLE t (s TEXT DEFAULT 'S3CR3T-DUMP-BYTES');"), 0o600)
	res := runCLI(t, "d1", "database", "import", "db1", "--file", "@"+sqlFile, "--debug",
		"--account-id", accountID, "--endpoint-url", fileStub.srv.URL)
	if res.code == 0 {
		t.Fatalf("expected the upload failure to fail the command")
	}
	if strings.Contains(res.stdout, "S3CR3T-DUMP-BYTES") || strings.Contains(res.stderr, "S3CR3T-DUMP-BYTES") {
		t.Fatalf("import file bytes leaked:\nstdout=%q\nstderr=%q", res.stdout, res.stderr)
	}
}
