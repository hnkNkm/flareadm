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
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/pagination"
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
// newHome isolates the configuration directory in a temp directory. Both the
// XDG variable (unix) and APPDATA (windows) are redirected because
// config.DefaultPath prefers APPDATA on Windows; without this the CLI would
// write into the developer's real profile and cfgPath would read a path that
// was never written.
func newHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("APPDATA", home)
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
	Method      string
	Path        string
	Query       string
	Body        string
	Auth        string
	Host        string
	ContentType string
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
			Method:      r.Method,
			Path:        r.URL.Path,
			Query:       r.URL.RawQuery,
			Body:        string(body),
			Auth:        r.Header.Get("Authorization"),
			Host:        r.Host,
			ContentType: r.Header.Get("Content-Type"),
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

// TestConfigureInitCreatesMissingConfigDir points the configuration home at a
// nested directory that does not exist yet and asserts that the write path
// creates it. The unix directory mode is part of the contract; on Windows the
// same check is skipped because the platform ignores POSIX modes.
func TestConfigureInitCreatesMissingConfigDir(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "nested", "dir")
	t.Setenv("XDG_CONFIG_HOME", nested)
	t.Setenv("APPDATA", nested)
	setToken(t, "tok")

	target := filepath.Join(nested, "flareadm", "config.toml")
	if _, err := os.Stat(target); err == nil {
		t.Fatalf("%s must not exist before init", target)
	}
	if res := runCLI(t, "configure", "init"); res.code != 0 {
		t.Fatalf("init: code=%d stderr=%q", res.code, res.stderr)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("init did not create %s: %v", target, err)
	}
	if !strings.Contains(string(data), "[profile.default]") {
		t.Fatalf("config = %s", data)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Dir(target))
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o700 {
			t.Fatalf("config directory mode = %o, want 700", perm)
		}
		if perm := fileMode(t, target); perm != 0o600 {
			t.Fatalf("config file mode = %o, want 600", perm)
		}
	}

	// A nested write through another entry point (configure set) keeps working.
	if res := runCLI(t, "configure", "set", "account_id", accountID); res.code != 0 {
		t.Fatalf("set: code=%d stderr=%q", res.code, res.stderr)
	}
	if res := runCLI(t, "configure", "get", "account_id"); res.code != 0 || !strings.Contains(res.stdout, accountID) {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
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
	if len(env.Data) != 5 {
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
	if len(reqs) != 2 || reqs[0].Path != "/zones" || !strings.Contains(reqs[0].Query, "page=1") ||
		reqs[1].Path != "/zones/"+zoneID {
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
			if perPage == "1" {
				// one item per page, three pages total
				if page > 3 {
					return 200, envelope([]any{})
				}
				return 200, envelope([]any{zoneJSON(fmt.Sprintf("%032d", page), fmt.Sprintf("z%d.example", page), "active")})
			}
			if page > 1 {
				return 200, envelope([]any{})
			}
			// A full page for the default per_page=100, so the short-page
			// stop rule does not end the loop after page 1.
			items := make([]any, 0, 100)
			for i := 0; i < 100; i++ {
				items = append(items, zoneJSON(fmt.Sprintf("%032d", i), fmt.Sprintf("z%d.example", i), "active"))
			}
			return 200, envelope(items)
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
	if api.count() != 1 {
		t.Fatalf("requests = %d, want 1 (short page terminates)", api.count())
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
	if api.count() != 1 {
		t.Fatalf("requests = %d, want 1 (short page terminates)", api.count())
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
	if api.count() != 1 {
		t.Fatalf("list requests = %d, want 1 (short page terminates)", api.count())
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
	if api.count() != 1 {
		t.Fatalf("list requests = %d, want 1 (short page terminates)", api.count())
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
		{"vectorize query vector", "S3CR3T-QUERY-VECTOR",
			[]string{"vectorize", "vector", "query", "idx1", "--vector", "[0.5]",
				"--filter", `{"marker":"S3CR3T-QUERY-VECTOR"}`,
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

// ---- v0.3 slice 3: hyperdrive / vectorize ---------------------------------

func hyperdriveJSON(id, name string) map[string]any {
	return map[string]any{
		"id": id, "name": name,
		"origin": map[string]any{
			"host": "db.example.com", "port": float64(5432), "database": "app",
			"user": "app_user", "password": "origin-password", "scheme": "postgres",
		},
		"caching":                 map[string]any{"disabled": false},
		"origin_connection_limit": float64(10),
		"created_on":              "2025-01-01T00:00:00Z",
		"modified_on":             "2025-01-02T00:00:00Z",
	}
}

func indexJSON(name string) map[string]any {
	return map[string]any{
		"name": name, "description": "docs index",
		"config":     map[string]any{"dimensions": float64(768), "metric": "cosine"},
		"created_on": "2025-01-01T00:00:00Z", "modified_on": "2025-01-02T00:00:00Z",
	}
}

func v05API(t *testing.T) *apiStub {
	hbase := "/accounts/" + accountID + "/hyperdrive/configs"
	vbase := "/accounts/" + accountID + "/vectorize/v2/indexes"
	return newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		switch {
		// Hyperdrive
		case method == "GET" && path == hbase:
			if strings.Contains(r.Query, "page=2") {
				return 200, envelope([]any{})
			}
			return 200, envelope([]any{hyperdriveJSON("hd1", "app-db")})
		case method == "POST" && path == hbase:
			return 200, envelope(hyperdriveJSON("hdnew", "new-config"))
		case (method == "GET" || method == "PATCH" || method == "DELETE") && path == hbase+"/hd1":
			if method == "DELETE" {
				return 200, envelope(nil)
			}
			return 200, envelope(hyperdriveJSON("hd1", "app-db"))
		// Vectorize indexes
		case method == "GET" && path == vbase:
			return 200, envelope([]any{indexJSON("idx1")})
		case method == "POST" && path == vbase:
			return 200, envelope(indexJSON("idx-new"))
		case (method == "GET" || method == "DELETE") && path == vbase+"/idx1":
			if method == "DELETE" {
				return 200, envelope(nil)
			}
			return 200, envelope(indexJSON("idx1"))
		case method == "GET" && path == vbase+"/idx1/info":
			return 200, envelope(map[string]any{
				"vectorCount": float64(42), "dimensions": float64(768),
				"processedUpToMutation": "mut-9",
			})
		case method == "POST" && (path == vbase+"/idx1/insert" || path == vbase+"/idx1/upsert"):
			return 200, envelope(map[string]any{"mutationId": "mut1"})
		case method == "POST" && path == vbase+"/idx1/query":
			return 200, envelope(map[string]any{
				"count":   float64(1),
				"matches": []any{map[string]any{"id": "v1", "score": 0.9, "namespace": "ns"}},
			})
		case method == "POST" && path == vbase+"/idx1/get_by_ids":
			return 200, envelope(map[string]any{"vectors": []any{map[string]any{"id": "v1", "values": []any{0.1, 0.2}}}})
		case method == "POST" && path == vbase+"/idx1/delete_by_ids":
			return 200, envelope(map[string]any{"mutationId": "mut2"})
		case method == "GET" && path == vbase+"/idx1/list":
			return 200, envelope(map[string]any{
				"vectors": []any{map[string]any{"id": "v1"}},
				"count":   float64(1), "isTruncated": true, "totalCount": float64(2), "nextCursor": "cur2",
			})
		case method == "GET" && path == vbase+"/idx1/metadata_index/list":
			return 200, envelope([]any{map[string]any{"propertyName": "lang", "indexType": "string"}})
		case method == "POST" && (path == vbase+"/idx1/metadata_index/create" || path == vbase+"/idx1/metadata_index/delete"):
			return 200, envelope(map[string]any{"mutationId": "mut3"})
		}
		s, b := apiErr(404, 7000, "not found")
		return s, b
	})
}

func TestHyperdriveConfigCRUD(t *testing.T) {
	api := v05API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}
	originFile := filepath.Join(t.TempDir(), "origin.json")
	originJSON := `{"host":"db.example.com","port":5432,"database":"app","user":"app_user","password":"S3CR3T-ORIGIN-PASSWORD","scheme":"postgres"}`
	_ = os.WriteFile(originFile, []byte(originJSON), 0o600)

	res := runCLI(t, base("hyperdrive", "config", "list", "--json")...)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.count() != 1 {
		t.Fatalf("list requests = %d, want 1 (short page terminates)", api.count())
	}
	if !strings.Contains(res.stdout, `"id": "hd1"`) || !strings.Contains(res.stdout, "db.example.com") {
		t.Fatalf("list output = %s", res.stdout)
	}

	res = runCLI(t, base("hyperdrive", "config", "get", "hd1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "app-db") || !strings.Contains(res.stdout, "db.example.com") {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}

	// create with @file origin: exact body, no secret leakage
	res = runCLI(t, base("hyperdrive", "config", "create", "--name", "new-config",
		"--origin", "@"+originFile, "--caching", `{"disabled":true}`, "--origin-connection-limit", "5", "--debug")...)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || req.Path != "/accounts/"+accountID+"/hyperdrive/configs" {
		t.Fatalf("create request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	inner, ok := got["hyperdrive"].(map[string]any)
	if !ok {
		t.Fatalf("create body = %#v", got)
	}
	if inner["name"] != "new-config" || inner["origin_connection_limit"] != float64(5) {
		t.Fatalf("create inner = %#v", inner)
	}
	origin := inner["origin"].(map[string]any)
	if origin["password"] != "S3CR3T-ORIGIN-PASSWORD" || origin["host"] != "db.example.com" {
		t.Fatalf("origin = %#v", origin)
	}
	if !reflect.DeepEqual(inner["caching"], map[string]any{"disabled": true}) {
		t.Fatalf("caching = %#v", inner["caching"])
	}
	if strings.Contains(res.stdout, "S3CR3T-ORIGIN-PASSWORD") || strings.Contains(res.stderr, "S3CR3T-ORIGIN-PASSWORD") {
		t.Fatalf("origin secret leaked: stdout=%q stderr=%q", res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "debug:") {
		t.Fatalf("expected debug logging to be active")
	}

	// inline origin rejected
	res = runCLI(t, base("hyperdrive", "config", "create", "--name", "x", "--origin", originJSON)...)
	if res.code != errors.CodeInvalid {
		t.Fatalf("inline origin: code=%d, want 2", res.code)
	}
	if !strings.Contains(res.stderr, "@file") || strings.Contains(res.stderr, "S3CR3T-ORIGIN-PASSWORD") {
		t.Fatalf("inline origin error message = %q", res.stderr)
	}

	// update: PATCH with only caching
	res = runCLI(t, base("hyperdrive", "config", "update", "hd1", "--caching", `{"disabled":false}`)...)
	if res.code != 0 {
		t.Fatalf("update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PATCH" {
		t.Fatalf("update request = %+v", req)
	}
	got = decodeRequestBody(t, req.Body)
	inner = got["hyperdrive"].(map[string]any)
	if _, hasName := inner["name"]; hasName {
		t.Fatalf("update must not send unnamed fields: %#v", inner)
	}
	if !reflect.DeepEqual(inner["caching"], map[string]any{"disabled": false}) {
		t.Fatalf("update caching = %#v", inner["caching"])
	}

	// validation
	for _, args := range [][]string{
		base("hyperdrive", "config", "create", "--origin", "@"+originFile),
		base("hyperdrive", "config", "create", "--name", "x"),
		base("hyperdrive", "config", "update", "hd1"),
		base("hyperdrive", "config", "update", "hd1", "--caching", "[1]"),
	} {
		if res := runCLI(t, args...); res.code != errors.CodeInvalid {
			t.Fatalf("%v: code=%d, want 2 (stderr=%q)", args, res.code, res.stderr)
		}
	}

	// delete guard rails
	del := base("hyperdrive", "config", "delete", "hd1")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "DELETE" {
			t.Fatalf("DELETE without confirmation")
		}
	}
	if res := runCLI(t, append(append([]string{}, del...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete Hyperdrive configuration app-db") {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != "/accounts/"+accountID+"/hyperdrive/configs/hd1" {
		t.Fatalf("delete request = %+v", req)
	}

	// error mapping
	api404 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(404, 7000, "config not found")
		return s, b
	})
	if res := runCLI(t, "hyperdrive", "config", "get", "hd1", "--account-id", accountID, "--endpoint-url", api404.srv.URL); res.code != errors.CodeNotFound {
		t.Fatalf("404: code=%d, want 5", res.code)
	}
	api403 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(403, 9109, "forbidden")
		return s, b
	})
	if res := runCLI(t, "hyperdrive", "config", "list", "--account-id", accountID, "--endpoint-url", api403.srv.URL); res.code != errors.CodePermission {
		t.Fatalf("403: code=%d, want 4", res.code)
	}
}

func TestVectorizeIndexCRUD(t *testing.T) {
	api := v05API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}

	res := runCLI(t, base("vectorize", "index", "list", "--json")...)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, `"name": "idx1"`) || !strings.Contains(res.stdout, `"dimensions": 768`) {
		t.Fatalf("list output = %s", res.stdout)
	}

	res = runCLI(t, base("vectorize", "index", "get", "idx1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "idx1") || !strings.Contains(res.stdout, "cosine") {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}

	res = runCLI(t, base("vectorize", "index", "create", "--name", "idx-new", "--dimensions", "768", "--metric", "cosine", "--description", "docs")...)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || req.Path != "/accounts/"+accountID+"/vectorize/v2/indexes" {
		t.Fatalf("create request = %+v", req)
	}
	want := map[string]any{
		"name": "idx-new", "description": "docs",
		"config": map[string]any{"dimensions": float64(768), "metric": "cosine"},
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("create body mismatch\n got: %#v\nwant: %#v", got, want)
	}

	// preset variant
	res = runCLI(t, base("vectorize", "index", "create", "--name", "idx-preset", "--preset", "my-preset")...)
	if res.code != 0 {
		t.Fatalf("preset create: code=%d stderr=%q", res.code, res.stderr)
	}
	got := decodeRequestBody(t, api.last().Body)
	if !reflect.DeepEqual(got["config"], map[string]any{"preset": "my-preset"}) {
		t.Fatalf("preset config = %#v", got["config"])
	}

	// validation
	for _, args := range [][]string{
		base("vectorize", "index", "create", "--dimensions", "768", "--metric", "cosine"),
		base("vectorize", "index", "create", "--name", "x"),
		base("vectorize", "index", "create", "--name", "x", "--dimensions", "768", "--metric", "cosine", "--preset", "p"),
		base("vectorize", "index", "create", "--name", "x", "--dimensions", "768", "--metric", "manhattan"),
	} {
		if res := runCLI(t, args...); res.code != errors.CodeInvalid {
			t.Fatalf("%v: code=%d, want 2 (stderr=%q)", args, res.code, res.stderr)
		}
	}

	res = runCLI(t, base("vectorize", "index", "info", "idx1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "42") || !strings.Contains(res.stdout, "768") {
		t.Fatalf("info: code=%d stdout=%q", res.code, res.stdout)
	}

	// delete guard rails
	del := base("vectorize", "index", "delete", "idx1")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "DELETE" {
			t.Fatalf("DELETE without confirmation")
		}
	}
	if res := runCLI(t, append(append([]string{}, del...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete Vectorize index idx1") {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != "/accounts/"+accountID+"/vectorize/v2/indexes/idx1" {
		t.Fatalf("delete request = %+v", req)
	}
}

func TestVectorizeVectorOps(t *testing.T) {
	api := v05API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}
	ndjson := "{\"id\":\"v1\",\"values\":[0.1,0.2]}\n"
	vectorsFile := filepath.Join(t.TempDir(), "vectors.ndjson")
	_ = os.WriteFile(vectorsFile, []byte(ndjson), 0o600)

	// insert: exact NDJSON body + content type + unparsable behavior
	res := runCLI(t, base("vectorize", "vector", "insert", "idx1", "--vectors", "@"+vectorsFile, "--unparsable-behavior", "discard")...)
	if res.code != 0 {
		t.Fatalf("insert: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || req.Path != "/accounts/"+accountID+"/vectorize/v2/indexes/idx1/insert" {
		t.Fatalf("insert request = %+v", req)
	}
	if req.Body != ndjson {
		t.Fatalf("insert body = %q, want %q", req.Body, ndjson)
	}
	if !strings.HasPrefix(req.ContentType, "application/x-ndjson") {
		t.Fatalf("insert content type = %q", req.ContentType)
	}
	if !strings.Contains(req.Query, "unparsable-behavior=discard") {
		t.Fatalf("insert query = %q", req.Query)
	}
	if !strings.Contains(res.stdout, "mut1") {
		t.Fatalf("insert output = %s", res.stdout)
	}

	// upsert
	res = runCLI(t, base("vectorize", "vector", "upsert", "idx1", "--vectors", "@"+vectorsFile)...)
	if res.code != 0 {
		t.Fatalf("upsert: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != "/accounts/"+accountID+"/vectorize/v2/indexes/idx1/upsert" {
		t.Fatalf("upsert path = %q", api.last().Path)
	}

	// insert requires @file
	res = runCLI(t, base("vectorize", "vector", "insert", "idx1", "--vectors", ndjson)...)
	if res.code != errors.CodeInvalid || !strings.Contains(res.stderr, "@file") {
		t.Fatalf("inline vectors: code=%d stderr=%q", res.code, res.stderr)
	}
	if res := runCLI(t, base("vectorize", "vector", "insert", "idx1", "--vectors", "@"+vectorsFile, "--unparsable-behavior", "sometimes")...); res.code != errors.CodeInvalid {
		t.Fatalf("bad behavior: code=%d", res.code)
	}

	// query: exact body + table
	res = runCLI(t, base("vectorize", "vector", "query", "idx1", "--vector", "[0.1, 0.2]",
		"--top-k", "3", "--return-values", "--return-metadata", "all", "--filter", `{"lang":"en"}`)...)
	if res.code != 0 {
		t.Fatalf("query: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Path != "/accounts/"+accountID+"/vectorize/v2/indexes/idx1/query" {
		t.Fatalf("query path = %q", req.Path)
	}
	want := map[string]any{
		"vector": []any{0.1, 0.2}, "topK": float64(3),
		"returnValues": true, "returnMetadata": "all",
		"filter": map[string]any{"lang": "en"},
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("query body mismatch\n got: %#v\nwant: %#v", got, want)
	}
	if !strings.Contains(res.stdout, "v1") || !strings.Contains(res.stdout, "0.9000") {
		t.Fatalf("query output = %s", res.stdout)
	}
	for _, args := range [][]string{
		base("vectorize", "vector", "query", "idx1", "--vector", `{"a":1}`),
		base("vectorize", "vector", "query", "idx1", "--vector", `["a"]`),
		base("vectorize", "vector", "query", "idx1", "--vector", "[1]", "--return-metadata", "sometimes"),
	} {
		if res := runCLI(t, args...); res.code != errors.CodeInvalid {
			t.Fatalf("%v: code=%d, want 2 (stderr=%q)", args, res.code, res.stderr)
		}
	}

	// get by ids
	res = runCLI(t, base("vectorize", "vector", "get", "idx1", "--id", "v1", "--id", "v2")...)
	if res.code != 0 {
		t.Fatalf("get: code=%d stderr=%q", res.code, res.stderr)
	}
	if got := decodeRequestBody(t, api.last().Body); !reflect.DeepEqual(got, map[string]any{"ids": []any{"v1", "v2"}}) {
		t.Fatalf("get body = %#v", got)
	}
	if !strings.Contains(res.stdout, "v1") {
		t.Fatalf("get output = %s", res.stdout)
	}

	// delete by ids guard rails
	del := base("vectorize", "vector", "delete", "idx1", "--id", "v1")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Path == "/accounts/"+accountID+"/vectorize/v2/indexes/idx1/delete_by_ids" {
			t.Fatalf("delete_by_ids sent without confirmation")
		}
	}
	if res := runCLI(t, append(append([]string{}, del...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete 1 vector(s)") {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if got := decodeRequestBody(t, api.last().Body); !reflect.DeepEqual(got, map[string]any{"ids": []any{"v1"}}) {
		t.Fatalf("delete body = %#v", got)
	}

	// list with cursor reporting
	res = runCLI(t, base("vectorize", "vector", "list", "idx1", "--count", "1", "--cursor", "cur1")...)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if !strings.Contains(req.Query, "count=1") || !strings.Contains(req.Query, "cursor=cur1") {
		t.Fatalf("list query = %q", req.Query)
	}
	if !strings.Contains(res.stdout, "v1") || !strings.Contains(res.stderr, "next cursor: cur2") {
		t.Fatalf("list stdout=%q stderr=%q", res.stdout, res.stderr)
	}
}

func TestVectorizeMetadataIndexes(t *testing.T) {
	api := v05API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}

	res := runCLI(t, base("vectorize", "index", "metadata", "list", "idx1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "lang") {
		t.Fatalf("list: code=%d stdout=%q", res.code, res.stdout)
	}
	if api.last().Path != "/accounts/"+accountID+"/vectorize/v2/indexes/idx1/metadata_index/list" {
		t.Fatalf("list path = %q", api.last().Path)
	}

	res = runCLI(t, base("vectorize", "index", "metadata", "create", "idx1", "--property", "lang", "--type", "string")...)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	if got := decodeRequestBody(t, api.last().Body); !reflect.DeepEqual(got, map[string]any{"propertyName": "lang", "indexType": "string"}) {
		t.Fatalf("create body = %#v", got)
	}
	for _, args := range [][]string{
		base("vectorize", "index", "metadata", "create", "idx1", "--type", "string"),
		base("vectorize", "index", "metadata", "create", "idx1", "--property", "lang", "--type", "date"),
		base("vectorize", "index", "metadata", "delete", "idx1"),
	} {
		if res := runCLI(t, args...); res.code != errors.CodeInvalid {
			t.Fatalf("%v: code=%d, want 2 (stderr=%q)", args, res.code, res.stderr)
		}
	}

	del := base("vectorize", "index", "metadata", "delete", "idx1", "--property", "lang")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete metadata index lang") {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if got := decodeRequestBody(t, api.last().Body); !reflect.DeepEqual(got, map[string]any{"propertyName": "lang"}) {
		t.Fatalf("delete body = %#v", got)
	}
}

// ---- pagination loop-guard regressions ------------------------------------

func TestPaginationTotalPagesStopsLoop(t *testing.T) {
	// A full page with result_info.total_pages=1: exactly one request.
	api := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		if method == "GET" && path == "/zones" {
			items := make([]any, 0, 100)
			for i := 0; i < 100; i++ {
				items = append(items, zoneJSON(fmt.Sprintf("%032d", i), fmt.Sprintf("z%d.example", i), "active"))
			}
			return 200, envelopeWithInfo(items, map[string]any{"page": 1, "per_page": 100, "count": 100, "total_count": 100, "total_pages": 1})
		}
		s, b := apiErr(404, 0, "nope")
		return s, b
	})
	setToken(t, "tok")
	newHome(t)
	res := runCLI(t, "zone", "list", "--zone", zoneID, "--json", "--endpoint-url", api.srv.URL)
	if res.code != 0 {
		t.Fatalf("code=%d stderr=%q", res.code, res.stderr)
	}
	if api.count() != 1 {
		t.Fatalf("requests = %d, want exactly 1 (total_pages=1)", api.count())
	}
	var env struct {
		Meta struct {
			Count int `json:"count"`
		} `json:"meta"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &env); err != nil {
		t.Fatal(err)
	}
	if env.Meta.Count != 100 {
		t.Fatalf("count = %d, want 100", env.Meta.Count)
	}
}

func TestPaginationEndlessFullPageFailsBounded(t *testing.T) {
	// The API always returns a full page and no result_info: the loop must
	// stop at the documented safety cap with a clear diagnostic (exit 1:
	// the API never reached a terminal page, which is not a usage error).
	api := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		if method == "GET" && path == "/zones" {
			items := make([]any, 0, 100)
			for i := 0; i < 100; i++ {
				items = append(items, zoneJSON(fmt.Sprintf("%032d", i), fmt.Sprintf("z%d.example", i), "active"))
			}
			return 200, envelope(items)
		}
		s, b := apiErr(404, 0, "nope")
		return s, b
	})
	setToken(t, "tok")
	newHome(t)
	res := runCLI(t, "zone", "list", "--zone", zoneID, "--endpoint-url", api.srv.URL)
	if res.code != errors.CodeUnclassified {
		t.Fatalf("code=%d, want 1 (stderr=%q)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "pagination safety limit exceeded") {
		t.Fatalf("diagnostic missing: %q", res.stderr)
	}
	if got := api.count(); got != pagination.MaxPages {
		t.Fatalf("requests = %d, want exactly MaxPages (%d)", got, pagination.MaxPages)
	}
}

func TestPaginationRepeatedCursorTerminates(t *testing.T) {
	// A cursor endpoint that keeps returning the same cursor must not loop.
	api := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		if method == "GET" && path == "/zones/"+zoneID+"/rulesets" {
			return 200, envelopeWithInfo([]any{rulesetJSON("rs1", "waf", "http_request_firewall_managed", "managed")},
				map[string]any{"count": 1, "per_page": 100, "cursor": "c2"})
		}
		s, b := apiErr(404, 0, "nope")
		return s, b
	})
	setToken(t, "tok")
	newHome(t)
	res := runCLI(t, "ruleset", "list", "--zone", zoneID, "--endpoint-url", api.srv.URL)
	if res.code != errors.CodeUnclassified {
		t.Fatalf("code=%d, want 1 (stderr=%q)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "repeated the same cursor") {
		t.Fatalf("diagnostic missing: %q", res.stderr)
	}
	if got := api.count(); got > 2 {
		t.Fatalf("requests = %d, want the loop to stop as soon as the cursor repeats", got)
	}
}

// ---- v0.4 slice 1: zero-trust tunnel / routes / organization --------------

func tunnelJSON(id, name string) map[string]any {
	return map[string]any{
		"id": id, "name": name, "status": "healthy", "tun_type": "cfd_tunnel",
		"config_src": "cloudflare", "remote_config": true,
		"connections": []any{map[string]any{"id": "c1", "arch": "linux_amd64", "config_version": float64(3), "features": []string{"ha"}, "run_at": "2025-01-01T00:00:00Z"}},
		"created_at":  "2025-01-01T00:00:00Z", "conns_active_at": "2025-01-02T00:00:00Z",
	}
}

func routeJSON(id string) map[string]any {
	return map[string]any{
		"id": id, "network": "10.0.0.0/8", "tunnel_id": "t1", "comment": "office",
		"virtual_network_id": "vn1", "created_at": "2025-01-01T00:00:00Z",
	}
}

func orgJSON() map[string]any {
	return map[string]any{
		"name": "Acme", "auth_domain": "acme.cloudflareaccess.com", "session_duration": "24h",
		"is_ui_read_only": false, "mfa_required_for_all_apps": true, "allow_authenticate_via_warp": true,
		"custom_pages": map[string]any{"forbidden": "page-1"},
	}
}

func v06API(t *testing.T) *apiStub {
	tbase := "/accounts/" + accountID + "/cfd_tunnel"
	rbase := "/accounts/" + accountID + "/teamnet/routes"
	obase := "/accounts/" + accountID + "/access/organizations"
	return newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		switch {
		// Tunnels
		case method == "GET" && path == tbase:
			return 200, envelope([]any{tunnelJSON("t1", "edge")})
		case method == "POST" && path == tbase:
			return 200, envelope(tunnelJSON("tnew", "new-tunnel"))
		case (method == "GET" || method == "PATCH" || method == "DELETE") && path == tbase+"/t1":
			switch method {
			case "DELETE":
				return 200, envelope(tunnelJSON("t1", "edge"))
			default:
				return 200, envelope(tunnelJSON("t1", "edge"))
			}
		case method == "GET" && path == tbase+"/t1/token":
			return 200, envelope("S3CR3T-TUNNEL-TOKEN")
		case method == "GET" && path == tbase+"/t1/connections":
			return 200, envelope([]any{map[string]any{"id": "c1", "arch": "linux_amd64", "config_version": float64(3), "features": []string{"ha"}, "run_at": "2025-01-01T00:00:00Z"}})
		case method == "DELETE" && path == tbase+"/t1/connections":
			return 200, envelope(nil)
		case method == "GET" && path == tbase+"/t1/configurations":
			return 200, envelope(map[string]any{"config": map[string]any{
				"ingress":      []any{map[string]any{"hostname": "app.example.com", "service": "http://localhost:8080"}},
				"unknownField": "keep-me",
			}})
		case method == "PUT" && path == tbase+"/t1/configurations":
			var body map[string]any
			_ = json.Unmarshal([]byte(r.Body), &body)
			return 200, envelope(map[string]any{"config": body["config"]})
		// Routes
		case method == "GET" && path == rbase:
			return 200, envelope([]any{routeJSON("r1")})
		case method == "POST" && path == rbase:
			return 200, envelope(routeJSON("rnew"))
		case (method == "GET" || method == "PATCH" || method == "DELETE") && path == rbase+"/r1":
			if method == "DELETE" {
				return 200, envelope(routeJSON("r1"))
			}
			return 200, envelope(routeJSON("r1"))
		// Organization
		case method == "GET" && path == obase:
			return 200, envelope(orgJSON())
		case method == "PUT" && path == obase:
			var body map[string]any
			_ = json.Unmarshal([]byte(r.Body), &body)
			return 200, envelope(body)
		}
		s, b := apiErr(404, 7000, "not found")
		return s, b
	})
}

func TestTunnelCRUD(t *testing.T) {
	api := v06API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}

	res := runCLI(t, base("zero-trust", "tunnel", "list", "--name", "edge", "--status", "healthy",
		"--uuid", "11111111-1111-1111-1111-111111111111", "--deleted")...)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Path != "/accounts/"+accountID+"/cfd_tunnel" {
		t.Fatalf("list path = %q", req.Path)
	}
	for _, want := range []string{"name=edge", "status=healthy", "uuid=11111111", "is_deleted=true"} {
		if !strings.Contains(req.Query, want) {
			t.Fatalf("list query %q missing %q", req.Query, want)
		}
	}
	if !strings.Contains(res.stdout, "edge") || !strings.Contains(res.stdout, "healthy") || !strings.Contains(res.stdout, "cfd_tunnel") {
		t.Fatalf("list output = %s", res.stdout)
	}

	res = runCLI(t, base("zero-trust", "tunnel", "get", "t1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "edge") {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}

	// create with a @file tunnel secret
	secretFile := filepath.Join(t.TempDir(), "secret.txt")
	_ = os.WriteFile(secretFile, []byte("S3CR3T-TUNNEL-SECRET"), 0o600)
	res = runCLI(t, base("zero-trust", "tunnel", "create", "--name", "new-tunnel",
		"--config-src", "cloudflare", "--tunnel-secret", "@"+secretFile)...)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "POST" || req.Path != "/accounts/"+accountID+"/cfd_tunnel" {
		t.Fatalf("create request = %+v", req)
	}
	want := map[string]any{"name": "new-tunnel", "config_src": "cloudflare", "tunnel_secret": "S3CR3T-TUNNEL-SECRET"}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("create body mismatch\n got: %#v\nwant: %#v", got, want)
	}
	if strings.Contains(res.stdout, "S3CR3T-TUNNEL-SECRET") || strings.Contains(res.stderr, "S3CR3T-TUNNEL-SECRET") {
		t.Fatalf("tunnel secret leaked")
	}

	// inline secret rejected
	res = runCLI(t, base("zero-trust", "tunnel", "create", "--name", "x", "--tunnel-secret", "S3CR3T-INLINE")...)
	if res.code != errors.CodeInvalid || !strings.Contains(res.stderr, "@file") {
		t.Fatalf("inline secret: code=%d stderr=%q", res.code, res.stderr)
	}
	if strings.Contains(res.stderr, "S3CR3T-INLINE") {
		t.Fatalf("inline secret value echoed: %q", res.stderr)
	}

	// dry-run + validation
	before := api.count()
	res = runCLI(t, base("zero-trust", "tunnel", "create", "--name", "x", "--dry-run")...)
	if res.code != 0 || !strings.Contains(res.stdout, "Would create tunnel x") || api.count() != before {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	for _, args := range [][]string{
		base("zero-trust", "tunnel", "create"),
		base("zero-trust", "tunnel", "create", "--name", "x", "--config-src", "sometimes"),
		base("zero-trust", "tunnel", "update", "t1"),
	} {
		if res := runCLI(t, args...); res.code != errors.CodeInvalid {
			t.Fatalf("%v: code=%d, want 2 (stderr=%q)", args, res.code, res.stderr)
		}
	}

	// update
	res = runCLI(t, base("zero-trust", "tunnel", "update", "t1", "--name", "renamed")...)
	if res.code != 0 {
		t.Fatalf("update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PATCH" {
		t.Fatalf("update request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, map[string]any{"name": "renamed"}) {
		t.Fatalf("update body = %#v", got)
	}

	// delete guard rails
	del := base("zero-trust", "tunnel", "delete", "t1")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "DELETE" {
			t.Fatalf("DELETE without confirmation")
		}
	}
	if res := runCLI(t, append(append([]string{}, del...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete tunnel edge") {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != "/accounts/"+accountID+"/cfd_tunnel/t1" {
		t.Fatalf("delete request = %+v", req)
	}

	// error mapping
	api404 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(404, 7000, "tunnel not found")
		return s, b
	})
	if res := runCLI(t, "zero-trust", "tunnel", "get", "t1", "--account-id", accountID, "--endpoint-url", api404.srv.URL); res.code != errors.CodeNotFound {
		t.Fatalf("404: code=%d, want 5", res.code)
	}
	api403 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(403, 9109, "forbidden")
		return s, b
	})
	if res := runCLI(t, "zero-trust", "tunnel", "list", "--account-id", accountID, "--endpoint-url", api403.srv.URL); res.code != errors.CodePermission {
		t.Fatalf("403: code=%d, want 4", res.code)
	}

	// ambiguous account scope
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
	if res := runCLI(t, "zero-trust", "tunnel", "list", "--endpoint-url", apiAmbig.srv.URL); res.code != errors.CodeInvalid {
		t.Fatalf("ambiguous account: code=%d, want 2 (stderr=%q)", res.code, res.stderr)
	}
}

func TestTunnelTokenHygiene(t *testing.T) {
	api := v06API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL

	res := runCLI(t, "zero-trust", "tunnel", "token", "t1", "--account-id", accountID, "--debug", "--endpoint-url", ep)
	if res.code != 0 {
		t.Fatalf("token: code=%d stderr=%q", res.code, res.stderr)
	}
	if res.stdout != "S3CR3T-TUNNEL-TOKEN\n" {
		t.Fatalf("token stdout = %q", res.stdout)
	}
	if !strings.Contains(res.stderr, "debug:") {
		t.Fatalf("expected debug diagnostics active: %q", res.stderr)
	}
	if strings.Contains(res.stderr, "S3CR3T-TUNNEL-TOKEN") {
		t.Fatalf("token leaked into --debug output: %q", res.stderr)
	}
	if api.last().Path != "/accounts/"+accountID+"/cfd_tunnel/t1/token" {
		t.Fatalf("token path = %q", api.last().Path)
	}

	// --raw prints the raw envelope on stdout only.
	res = runCLI(t, "zero-trust", "tunnel", "token", "t1", "--raw", "--account-id", accountID, "--endpoint-url", ep)
	if res.code != 0 || !strings.Contains(res.stdout, "S3CR3T-TUNNEL-TOKEN") {
		t.Fatalf("raw token: code=%d stdout=%q", res.code, res.stdout)
	}
	if strings.Contains(res.stderr, "S3CR3T-TUNNEL-TOKEN") {
		t.Fatalf("raw token leaked into stderr")
	}
}

func TestProtectSecretRedactsErrorText(t *testing.T) {
	// The tunnel token command registers the token with ProtectSecret; this
	// proves that anything registered that way is scrubbed from error text
	// (including upstream messages that echo it).
	rt := app.NewRuntime(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	rt.ProtectSecret("S3CR3T-REGISTERED")
	if got := rt.Redact("Error: upstream said S3CR3T-REGISTERED twice S3CR3T-REGISTERED"); strings.Contains(got, "S3CR3T-REGISTERED") {
		t.Fatalf("registered secret not redacted: %q", got)
	}
}

func TestTunnelConnections(t *testing.T) {
	api := v06API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}

	res := runCLI(t, base("zero-trust", "tunnel", "connection", "list", "t1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "c1") || !strings.Contains(res.stdout, "linux_amd64") {
		t.Fatalf("list: code=%d stdout=%q", res.code, res.stdout)
	}
	if api.last().Path != "/accounts/"+accountID+"/cfd_tunnel/t1/connections" {
		t.Fatalf("list path = %q", api.last().Path)
	}

	res = runCLI(t, base("zero-trust", "tunnel", "connection", "get", "t1", "c1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "c1") {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, base("zero-trust", "tunnel", "connection", "get", "t1", "missing")...); res.code != errors.CodeNotFound {
		t.Fatalf("missing connection: code=%d, want 5", res.code)
	}

	del := base("zero-trust", "tunnel", "connection", "delete", "t1", "--client-id", "c1")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "DELETE" {
			t.Fatalf("DELETE without confirmation")
		}
	}
	if res := runCLI(t, append(append([]string{}, del...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete connection c1") {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "DELETE" || req.Path != "/accounts/"+accountID+"/cfd_tunnel/t1/connections" || !strings.Contains(req.Query, "client_id=c1") {
		t.Fatalf("delete request = %+v", req)
	}
	if res := runCLI(t, base("zero-trust", "tunnel", "connection", "delete", "t1")...); res.code != errors.CodeInvalid {
		t.Fatalf("missing client id: code=%d", res.code)
	}
}

func TestTunnelConfiguration(t *testing.T) {
	api := v06API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}

	res := runCLI(t, base("zero-trust", "tunnel", "configuration", "get", "t1", "--json")...)
	if res.code != 0 {
		t.Fatalf("get: code=%d stderr=%q", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "app.example.com") || !strings.Contains(res.stdout, "keep-me") {
		t.Fatalf("get output = %s", res.stdout)
	}
	if api.last().Path != "/accounts/"+accountID+"/cfd_tunnel/t1/configurations" {
		t.Fatalf("get path = %q", api.last().Path)
	}

	configFile := filepath.Join(t.TempDir(), "config.json")
	config := `{"ingress":[{"hostname":"new.example.com","service":"http://localhost:9000","unknownNested":{"keep":true}}],"unknownTop":"keep"}`
	_ = os.WriteFile(configFile, []byte(config), 0o600)
	res = runCLI(t, base("zero-trust", "tunnel", "configuration", "update", "t1", "--config", "@"+configFile)...)
	if res.code != 0 {
		t.Fatalf("update: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "PUT" || req.Path != "/accounts/"+accountID+"/cfd_tunnel/t1/configurations" {
		t.Fatalf("update request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	cfg, ok := got["config"].(map[string]any)
	if !ok {
		t.Fatalf("update body = %#v", got)
	}
	if cfg["unknownTop"] != "keep" {
		t.Fatalf("unknown fields not preserved: %#v", cfg)
	}
	ingress := cfg["ingress"].([]any)[0].(map[string]any)
	if ingress["service"] != "http://localhost:9000" {
		t.Fatalf("ingress = %#v", ingress)
	}
	if _, ok := ingress["unknownNested"]; !ok {
		t.Fatalf("nested unknown field dropped: %#v", ingress)
	}

	before := api.count()
	res = runCLI(t, base("zero-trust", "tunnel", "configuration", "update", "t1", "--config", "@"+configFile, "--dry-run")...)
	if res.code != 0 || !strings.Contains(res.stdout, "Would replace the configuration") || api.count() != before {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	for _, args := range [][]string{
		base("zero-trust", "tunnel", "configuration", "update", "t1"),
		base("zero-trust", "tunnel", "configuration", "update", "t1", "--config", "[1]"),
	} {
		if res := runCLI(t, args...); res.code != errors.CodeInvalid {
			t.Fatalf("%v: code=%d, want 2 (stderr=%q)", args, res.code, res.stderr)
		}
	}
}

func TestTunnelRoutesCRUD(t *testing.T) {
	api := v06API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}

	res := runCLI(t, base("zero-trust", "route", "list", "--network-subset", "10.0.0.0/9", "--tunnel-id", "t1", "--comment", "office")...)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Path != "/accounts/"+accountID+"/teamnet/routes" {
		t.Fatalf("list path = %q", req.Path)
	}
	for _, want := range []string{"network_subset=10.0.0.0", "tunnel_id=t1", "comment=office"} {
		if !strings.Contains(req.Query, want) {
			t.Fatalf("list query %q missing %q", req.Query, want)
		}
	}
	if !strings.Contains(res.stdout, "10.0.0.0/8") {
		t.Fatalf("list output = %s", res.stdout)
	}

	res = runCLI(t, base("zero-trust", "route", "get", "r1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "office") {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}

	res = runCLI(t, base("zero-trust", "route", "create", "--network", "192.168.0.0/16", "--tunnel-id", "t1", "--comment", "lan")...)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "POST" {
		t.Fatalf("create request = %+v", req)
	}
	want := map[string]any{"network": "192.168.0.0/16", "tunnel_id": "t1", "comment": "lan"}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("create body mismatch\n got: %#v\nwant: %#v", got, want)
	}

	res = runCLI(t, base("zero-trust", "route", "update", "r1", "--comment", "updated")...)
	if res.code != 0 {
		t.Fatalf("update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PATCH" {
		t.Fatalf("update request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, map[string]any{"comment": "updated"}) {
		t.Fatalf("update body = %#v", got)
	}

	for _, args := range [][]string{
		base("zero-trust", "route", "create", "--tunnel-id", "t1"),
		base("zero-trust", "route", "create", "--network", "10.0.0.0/8"),
		base("zero-trust", "route", "update", "r1"),
	} {
		if res := runCLI(t, args...); res.code != errors.CodeInvalid {
			t.Fatalf("%v: code=%d, want 2", args, res.code)
		}
	}

	del := base("zero-trust", "route", "delete", "r1")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "DELETE" {
			t.Fatalf("DELETE without confirmation")
		}
	}
	if res := runCLI(t, append(append([]string{}, del...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete route 10.0.0.0/8") {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != "/accounts/"+accountID+"/teamnet/routes/r1" {
		t.Fatalf("delete request = %+v", req)
	}

	api404 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(404, 7000, "route not found")
		return s, b
	})
	if res := runCLI(t, "zero-trust", "route", "get", "r1", "--account-id", accountID, "--endpoint-url", api404.srv.URL); res.code != errors.CodeNotFound {
		t.Fatalf("404: code=%d, want 5", res.code)
	}
}

func TestZeroTrustOrganization(t *testing.T) {
	api := v06API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}

	res := runCLI(t, base("zero-trust", "organization", "get", "--json")...)
	if res.code != 0 {
		t.Fatalf("get: code=%d stderr=%q", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "Acme") || !strings.Contains(res.stdout, "acme.cloudflareaccess.com") {
		t.Fatalf("get output = %s", res.stdout)
	}
	if api.last().Path != "/accounts/"+accountID+"/access/organizations" {
		t.Fatalf("get path = %q", api.last().Path)
	}

	res = runCLI(t, base("zero-trust", "organization", "update", "--name", "Acme2", "--session-duration", "48h", "--mfa-required-for-all-apps=false")...)
	if res.code != 0 {
		t.Fatalf("update: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "PUT" || req.Path != "/accounts/"+accountID+"/access/organizations" {
		t.Fatalf("update request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	if got["name"] != "Acme2" || got["session_duration"] != "48h" || got["mfa_required_for_all_apps"] != false {
		t.Fatalf("update body = %#v", got)
	}
	if _, ok := got["custom_pages"]; !ok {
		t.Fatalf("unmapped fields must be preserved: %#v", got)
	}
	if got["auth_domain"] != "acme.cloudflareaccess.com" {
		t.Fatalf("existing fields must be preserved: %#v", got)
	}

	// --settings merges arbitrary fields
	res = runCLI(t, base("zero-trust", "organization", "update", "--settings", `{"deny_unmatched_requests":true}`)...)
	if res.code != 0 {
		t.Fatalf("settings update: code=%d stderr=%q", res.code, res.stderr)
	}
	got = decodeRequestBody(t, api.last().Body)
	if got["deny_unmatched_requests"] != true {
		t.Fatalf("settings merge failed: %#v", got)
	}

	if res := runCLI(t, base("zero-trust", "organization", "update")...); res.code != errors.CodeInvalid {
		t.Fatalf("empty update: code=%d", res.code)
	}
	if res := runCLI(t, base("zero-trust", "organization", "update", "--settings", "[1]")...); res.code != errors.CodeInvalid {
		t.Fatalf("bad settings: code=%d", res.code)
	}

	api403 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(403, 9109, "forbidden")
		return s, b
	})
	if res := runCLI(t, "zero-trust", "organization", "get", "--account-id", accountID, "--endpoint-url", api403.srv.URL); res.code != errors.CodePermission {
		t.Fatalf("403: code=%d, want 4", res.code)
	}
}

// ---- v0.4 slice 2: zero-trust Access --------------------------------------

func accessAppJSON() map[string]any {
	return map[string]any{
		"id": "app1", "name": "wiki", "domain": "wiki.example.com", "type": "self_hosted",
		"session_duration": "24h", "aud": "AUD123", "allowed_idps": []any{"idp1"},
		"created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-02T00:00:00Z",
		"eager_redirect_cookie_setting": true,
	}
}

func accessPolicyJSON(id string, appCount int) map[string]any {
	m := map[string]any{
		"id": id, "name": "allow staff", "decision": "allow", "precedence": float64(1),
		"session_duration": "24h", "include": []any{map[string]any{"email_domain": map[string]any{"domain": "example.com"}}},
		"created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-02T00:00:00Z",
		"mfa_config": map[string]any{"enabled": true},
	}
	if appCount > 0 {
		m["app_count"] = float64(appCount)
		m["reusable"] = true
	}
	return m
}

func accessGroupJSON() map[string]any {
	return map[string]any{
		"id": "grp1", "name": "contractors",
		"include":    []any{map[string]any{"email_domain": map[string]any{"domain": "example.com"}}},
		"is_default": false,
	}
}

func identityProviderJSON() map[string]any {
	return map[string]any{
		"id": "idp1", "name": "okta", "type": "okta", "read_only": false,
		"config": map[string]any{"client_id": "cid", "client_secret": "S3CR3T-IDP-CONFIG-SECRET"},
	}
}

func serviceTokenJSON(secret string) map[string]any {
	m := map[string]any{
		"id": "tok1", "name": "ci", "client_id": "CID123", "duration": "8760h",
		"enabled": true, "expires_at": "2026-01-01T00:00:00Z",
		"created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-02T00:00:00Z",
	}
	if secret != "" {
		m["client_secret"] = secret
	}
	return m
}

func v07API(t *testing.T) *apiStub {
	base := "/accounts/" + accountID + "/access"
	appPolicies := base + "/apps/app1/policies"
	return newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		echoPUT := func() (int, string) {
			var body map[string]any
			_ = json.Unmarshal([]byte(r.Body), &body)
			return 200, envelope(body)
		}
		switch {
		case method == "GET" && path == base+"/apps":
			return 200, envelope([]any{accessAppJSON()})
		case method == "POST" && path == base+"/apps":
			return 200, envelope(accessAppJSON())
		case path == base+"/apps/app1" && method == "GET":
			return 200, envelope(accessAppJSON())
		case path == base+"/apps/app1" && method == "PUT":
			return echoPUT()
		case path == base+"/apps/app1" && method == "DELETE":
			return 200, envelope(accessAppJSON())
		case method == "GET" && path == appPolicies:
			return 200, envelope([]any{accessPolicyJSON("pol1", 0)})
		case method == "POST" && path == appPolicies:
			return 200, envelope(accessPolicyJSON("polnew", 0))
		case path == appPolicies+"/pol1" && method == "GET":
			return 200, envelope(accessPolicyJSON("pol1", 0))
		case path == appPolicies+"/pol1" && method == "PUT":
			return echoPUT()
		case path == appPolicies+"/pol1" && method == "DELETE":
			return 200, envelope(accessPolicyJSON("pol1", 0))
		case method == "GET" && path == base+"/policies":
			return 200, envelope([]any{accessPolicyJSON("rpol1", 3)})
		case method == "POST" && path == base+"/policies":
			return 200, envelope(accessPolicyJSON("rpolnew", 0))
		case path == base+"/policies/rpol1" && method == "GET":
			return 200, envelope(accessPolicyJSON("rpol1", 3))
		case path == base+"/policies/rpol1" && method == "PUT":
			return echoPUT()
		case path == base+"/policies/rpol1" && method == "DELETE":
			return 200, envelope(accessPolicyJSON("rpol1", 3))
		case method == "GET" && path == base+"/groups":
			return 200, envelope([]any{accessGroupJSON()})
		case method == "POST" && path == base+"/groups":
			return 200, envelope(accessGroupJSON())
		case path == base+"/groups/grp1" && method == "GET":
			return 200, envelope(accessGroupJSON())
		case path == base+"/groups/grp1" && method == "PUT":
			return echoPUT()
		case path == base+"/groups/grp1" && method == "DELETE":
			return 200, envelope(accessGroupJSON())
		case method == "GET" && path == base+"/identity_providers":
			return 200, envelope([]any{identityProviderJSON()})
		case method == "POST" && path == base+"/identity_providers":
			return 200, envelope(identityProviderJSON())
		case path == base+"/identity_providers/idp1" && method == "GET":
			return 200, envelope(identityProviderJSON())
		case path == base+"/identity_providers/idp1" && method == "PUT":
			return echoPUT()
		case path == base+"/identity_providers/idp1" && method == "DELETE":
			return 200, envelope(identityProviderJSON())
		case method == "GET" && path == base+"/service_tokens":
			return 200, envelope([]any{serviceTokenJSON("S3CR3T-LEAKED-BY-LIST")})
		case method == "POST" && path == base+"/service_tokens":
			return 200, envelope(serviceTokenJSON("S3CR3T-CLIENT-SECRET"))
		case path == base+"/service_tokens/tok1" && method == "GET":
			return 200, envelope(serviceTokenJSON("S3CR3T-LEAKED-BY-GET"))
		case path == base+"/service_tokens/tok1" && method == "PUT":
			return echoPUT()
		case path == base+"/service_tokens/tok1" && method == "DELETE":
			return 200, envelope(serviceTokenJSON(""))
		case path == base+"/service_tokens/tok1/rotate" && method == "POST":
			return 200, envelope(serviceTokenJSON("S3CR3T-ROTATED-SECRET"))
		}
		s, b := apiErr(404, 7000, "not found")
		return s, b
	})
}

func TestAccessApplications(t *testing.T) {
	api := v07API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}
	prefix := "/accounts/" + accountID + "/access/apps"

	res := runCLI(t, base("zero-trust", "access", "app", "list", "--name", "wiki", "--search", "wiki", "--domain", "wiki.example.com", "--exact")...)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Path != prefix {
		t.Fatalf("list path = %q", req.Path)
	}
	for _, want := range []string{"name=wiki", "search=wiki", "domain=wiki.example.com", "exact=true"} {
		if !strings.Contains(req.Query, want) {
			t.Fatalf("list query %q missing %q", req.Query, want)
		}
	}
	if !strings.Contains(res.stdout, "wiki.example.com") || !strings.Contains(res.stdout, "self_hosted") {
		t.Fatalf("list output = %s", res.stdout)
	}

	res = runCLI(t, base("zero-trust", "access", "app", "get", "app1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "AUD123") {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}

	res = runCLI(t, base("zero-trust", "access", "app", "create", "--name", "wiki", "--type", "self_hosted",
		"--domain", "wiki.example.com", "--session-duration", "24h", "--allowed-idps", "idp1, idp2",
		"--skip-interstitial", "--settings", `{"scim_config":{"idp_uid":"idp1"}}`)...)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "POST" || req.Path != prefix {
		t.Fatalf("create request = %+v", req)
	}
	want := map[string]any{
		"name": "wiki", "type": "self_hosted", "domain": "wiki.example.com",
		"session_duration": "24h", "allowed_idps": []any{"idp1", "idp2"}, "skip_interstitial": true,
		"scim_config": map[string]any{"idp_uid": "idp1"},
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("create body mismatch\n got: %#v\nwant: %#v", got, want)
	}

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"create", "--type", "self_hosted", "--domain", "x.example.com"}, "--name is required"},
		{[]string{"create", "--name", "x", "--domain", "x.example.com"}, "--type is required"},
		{[]string{"create", "--name", "x", "--type", "nonsense", "--domain", "x.example.com"}, "invalid --type"},
		{[]string{"create", "--name", "x", "--type", "self_hosted"}, "--domain is required"},
	} {
		res := runCLI(t, base(append([]string{"zero-trust", "access", "app"}, tc.args...)...)...)
		if res.code != errors.CodeInvalid || !strings.Contains(res.stderr, tc.want) {
			t.Fatalf("%v: code=%d stderr=%q (want contains %q)", tc.args, res.code, res.stderr, tc.want)
		}
	}
	// domain may come from --settings
	res = runCLI(t, base("zero-trust", "access", "app", "create", "--name", "x", "--type", "self_hosted",
		"--settings", `{"domain":"x.example.com"}`, "--dry-run")...)
	if res.code != 0 || !strings.Contains(res.stdout, "Would create access application x") {
		t.Fatalf("settings domain: code=%d stdout=%q", res.code, res.stdout)
	}

	res = runCLI(t, base("zero-trust", "access", "app", "update", "app1", "--session-duration", "48h")...)
	if res.code != 0 {
		t.Fatalf("update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PUT" || req.Path != prefix+"/app1" {
		t.Fatalf("update request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	if got["session_duration"] != "48h" {
		t.Fatalf("update did not apply override: %#v", got)
	}
	if got["eager_redirect_cookie_setting"] != true || got["name"] != "wiki" {
		t.Fatalf("update dropped unmodeled or existing fields: %#v", got)
	}
	if res := runCLI(t, base("zero-trust", "access", "app", "update", "app1")...); res.code != errors.CodeInvalid {
		t.Fatalf("empty update: code=%d", res.code)
	}
	if res := runCLI(t, base("zero-trust", "access", "app", "update", "app1", "--session-duration", "48h", "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would update access application app1") {
		t.Fatalf("dry-run update: code=%d stdout=%q", res.code, res.stdout)
	}

	del := base("zero-trust", "access", "app", "delete", "app1")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "DELETE" {
			t.Fatalf("DELETE without confirmation")
		}
	}
	if res := runCLI(t, append(append([]string{}, del...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete access application wiki") {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != prefix+"/app1" {
		t.Fatalf("delete request = %+v", req)
	}

	api404 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(404, 7000, "app not found")
		return s, b
	})
	if res := runCLI(t, "zero-trust", "access", "app", "get", "app1", "--account-id", accountID, "--endpoint-url", api404.srv.URL); res.code != errors.CodeNotFound {
		t.Fatalf("404: code=%d, want 5", res.code)
	}
	api403 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(403, 9109, "forbidden")
		return s, b
	})
	if res := runCLI(t, "zero-trust", "access", "app", "list", "--account-id", accountID, "--endpoint-url", api403.srv.URL); res.code != errors.CodePermission {
		t.Fatalf("403: code=%d, want 4", res.code)
	}
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
	if res := runCLI(t, "zero-trust", "access", "app", "list", "--endpoint-url", apiAmbig.srv.URL); res.code != errors.CodeInvalid {
		t.Fatalf("ambiguous account: code=%d, want 2 (stderr=%q)", res.code, res.stderr)
	}
}

func TestAccessAppPolicies(t *testing.T) {
	api := v07API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}
	prefix := "/accounts/" + accountID + "/access/apps/app1/policies"
	rulesFile := filepath.Join(t.TempDir(), "rules.json")
	_ = os.WriteFile(rulesFile, []byte(`[{"email_domain":{"domain":"example.com"}}]`), 0o600)

	res := runCLI(t, base("zero-trust", "access", "app", "policy", "list", "app1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "pol1") {
		t.Fatalf("list: code=%d stdout=%q", res.code, res.stdout)
	}
	if api.last().Path != prefix {
		t.Fatalf("list path = %q", api.last().Path)
	}

	res = runCLI(t, base("zero-trust", "access", "app", "policy", "get", "app1", "pol1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "allow") {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}

	res = runCLI(t, base("zero-trust", "access", "app", "policy", "create", "app1",
		"--name", "allow staff", "--decision", "allow", "--include", "@"+rulesFile,
		"--session-duration", "24h", "--precedence", "1")...)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || req.Path != prefix {
		t.Fatalf("create request = %+v", req)
	}
	want := map[string]any{
		"name": "allow staff", "decision": "allow",
		"include":          []any{map[string]any{"email_domain": map[string]any{"domain": "example.com"}}},
		"session_duration": "24h", "precedence": float64(1),
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("create body mismatch\n got: %#v\nwant: %#v", got, want)
	}

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"app", "policy", "create", "app1", "--name", "x", "--decision", "allow"}, "--include is required"},
		{[]string{"app", "policy", "create", "app1", "--name", "x", "--include", "@" + rulesFile}, "--decision is required"},
		{[]string{"app", "policy", "create", "app1", "--decision", "allow", "--include", "@" + rulesFile}, "--name is required"},
		{[]string{"app", "policy", "create", "app1", "--name", "x", "--decision", "maybe", "--include", "@" + rulesFile}, "invalid --decision"},
		{[]string{"app", "policy", "create", "app1", "--name", "x", "--decision", "allow", "--include", "not-json"}, "must be a JSON array"},
	} {
		res := runCLI(t, base(append([]string{"zero-trust", "access"}, tc.args...)...)...)
		if res.code != errors.CodeInvalid || !strings.Contains(res.stderr, tc.want) {
			t.Fatalf("%v: code=%d stderr=%q (want %q)", tc.args, res.code, res.stderr, tc.want)
		}
	}

	res = runCLI(t, base("zero-trust", "access", "app", "policy", "update", "app1", "pol1", "--session-duration", "48h")...)
	if res.code != 0 {
		t.Fatalf("update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PUT" || req.Path != prefix+"/pol1" {
		t.Fatalf("update request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	if got["session_duration"] != "48h" || got["mfa_config"] == nil {
		t.Fatalf("update body = %#v", got)
	}

	del := base("zero-trust", "access", "app", "policy", "delete", "app1", "pol1")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "DELETE" {
			t.Fatalf("DELETE without confirmation")
		}
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != prefix+"/pol1" {
		t.Fatalf("delete request = %+v", req)
	}
}

func TestAccessPolicies(t *testing.T) {
	api := v07API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}
	prefix := "/accounts/" + accountID + "/access/policies"
	rulesFile := filepath.Join(t.TempDir(), "rules.json")
	_ = os.WriteFile(rulesFile, []byte(`[{"group":{"id":"grp1"}}]`), 0o600)

	res := runCLI(t, base("zero-trust", "access", "policy", "list")...)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != prefix {
		t.Fatalf("list path = %q", api.last().Path)
	}
	if !strings.Contains(res.stdout, "rpol1") || !strings.Contains(res.stdout, "3") {
		t.Fatalf("list output = %s", res.stdout)
	}

	res = runCLI(t, base("zero-trust", "access", "policy", "get", "rpol1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "rpol1") {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}

	res = runCLI(t, base("zero-trust", "access", "policy", "create", "--name", "allow staff",
		"--decision", "allow", "--include", "@"+rulesFile, "--purpose-justification-required")...)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || req.Path != prefix {
		t.Fatalf("create request = %+v", req)
	}
	want := map[string]any{
		"name": "allow staff", "decision": "allow",
		"include":                        []any{map[string]any{"group": map[string]any{"id": "grp1"}}},
		"purpose_justification_required": true,
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("create body mismatch\n got: %#v\nwant: %#v", got, want)
	}

	res = runCLI(t, base("zero-trust", "access", "policy", "update", "rpol1", "--decision", "deny")...)
	if res.code != 0 {
		t.Fatalf("update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PUT" || req.Path != prefix+"/rpol1" {
		t.Fatalf("update request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); got["decision"] != "deny" {
		t.Fatalf("update body = %#v", got)
	}
	if res := runCLI(t, base("zero-trust", "access", "policy", "update", "rpol1")...); res.code != errors.CodeInvalid {
		t.Fatalf("empty update: code=%d", res.code)
	}

	del := base("zero-trust", "access", "policy", "delete", "rpol1")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete access policy allow staff") {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != prefix+"/rpol1" {
		t.Fatalf("delete request = %+v", req)
	}
}

func TestAccessGroups(t *testing.T) {
	api := v07API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}
	prefix := "/accounts/" + accountID + "/access/groups"
	rulesFile := filepath.Join(t.TempDir(), "rules.json")
	_ = os.WriteFile(rulesFile, []byte(`[{"email":{"email":"a@example.com"}}]`), 0o600)

	res := runCLI(t, base("zero-trust", "access", "group", "list", "--name", "contractors", "--search", "contract")...)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Path != prefix || !strings.Contains(req.Query, "name=contractors") || !strings.Contains(req.Query, "search=contract") {
		t.Fatalf("list request = %+v", req)
	}
	if !strings.Contains(res.stdout, "grp1") {
		t.Fatalf("list output = %s", res.stdout)
	}

	if res := runCLI(t, base("zero-trust", "access", "group", "get", "grp1")...); res.code != 0 || !strings.Contains(res.stdout, "contractors") {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}

	res = runCLI(t, base("zero-trust", "access", "group", "create", "--name", "contractors",
		"--include", "@"+rulesFile, "--is-default=false")...)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "POST" || req.Path != prefix {
		t.Fatalf("create request = %+v", req)
	}
	want := map[string]any{
		"name": "contractors", "is_default": false,
		"include": []any{map[string]any{"email": map[string]any{"email": "a@example.com"}}},
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("create body mismatch\n got: %#v\nwant: %#v", got, want)
	}

	if res := runCLI(t, base("zero-trust", "access", "group", "create", "--name", "x")...); res.code != errors.CodeInvalid {
		t.Fatalf("missing include: code=%d", res.code)
	}
	if res := runCLI(t, base("zero-trust", "access", "group", "update", "grp1")...); res.code != errors.CodeInvalid {
		t.Fatalf("empty update: code=%d", res.code)
	}

	res = runCLI(t, base("zero-trust", "access", "group", "update", "grp1", "--name", "staff")...)
	if res.code != 0 {
		t.Fatalf("update: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "PUT" || req.Path != prefix+"/grp1" {
		t.Fatalf("update request = %+v", req)
	}

	del := base("zero-trust", "access", "group", "delete", "grp1")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != prefix+"/grp1" {
		t.Fatalf("delete request = %+v", req)
	}
}

func TestAccessIdentityProviders(t *testing.T) {
	api := v07API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}
	prefix := "/accounts/" + accountID + "/access/identity_providers"
	configFile := filepath.Join(t.TempDir(), "okta.json")
	_ = os.WriteFile(configFile, []byte(`{"client_id":"cid","client_secret":"S3CR3T-IDP-CONFIG-SECRET","okta_account":"acme.okta.com"}`), 0o600)

	res := runCLI(t, base("zero-trust", "access", "identity-provider", "list", "--scim-enabled", "true")...)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Path != prefix || !strings.Contains(req.Query, "scim_enabled=true") {
		t.Fatalf("list request = %+v", req)
	}
	if !strings.Contains(res.stdout, "okta") {
		t.Fatalf("list output = %s", res.stdout)
	}

	res = runCLI(t, base("zero-trust", "access", "identity-provider", "get", "idp1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "okta") {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}

	res = runCLI(t, base("zero-trust", "access", "identity-provider", "create", "--name", "okta",
		"--type", "okta", "--config", "@"+configFile)...)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "POST" || req.Path != prefix {
		t.Fatalf("create request = %+v", req)
	}
	want := map[string]any{
		"name": "okta", "type": "okta",
		"config": map[string]any{"client_id": "cid", "client_secret": "S3CR3T-IDP-CONFIG-SECRET", "okta_account": "acme.okta.com"},
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("create body mismatch\n got: %#v\nwant: %#v", got, want)
	}
	if strings.Contains(res.stderr, "S3CR3T-IDP-CONFIG-SECRET") {
		t.Fatalf("config secret leaked to stderr")
	}

	// --config is @file-only because it carries credentials
	res = runCLI(t, base("zero-trust", "access", "identity-provider", "create", "--name", "x",
		"--type", "okta", "--config", `{"client_secret":"S3CR3T-INLINE"}`)...)
	if res.code != errors.CodeInvalid || !strings.Contains(res.stderr, "@file") {
		t.Fatalf("inline config: code=%d stderr=%q", res.code, res.stderr)
	}
	if strings.Contains(res.stderr, "S3CR3T-INLINE") {
		t.Fatalf("inline config value echoed: %q", res.stderr)
	}
	for _, args := range [][]string{
		{"create", "--type", "okta", "--config", "@" + configFile},
		{"create", "--name", "x", "--config", "@" + configFile},
	} {
		if res := runCLI(t, base(append([]string{"zero-trust", "access", "identity-provider"}, args...)...)...); res.code != errors.CodeInvalid {
			t.Fatalf("%v: code=%d, want 2", args, res.code)
		}
	}

	res = runCLI(t, base("zero-trust", "access", "identity-provider", "update", "idp1", "--name", "okta2")...)
	if res.code != 0 {
		t.Fatalf("update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PUT" || req.Path != prefix+"/idp1" {
		t.Fatalf("update request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	cfg, ok := got["config"].(map[string]any)
	if !ok || cfg["client_secret"] != "S3CR3T-IDP-CONFIG-SECRET" {
		t.Fatalf("update did not preserve the existing config: %#v", got)
	}
	if got["name"] != "okta2" {
		t.Fatalf("update did not apply the override: %#v", got)
	}
	if strings.Contains(res.stdout, "S3CR3T-IDP-CONFIG-SECRET") || strings.Contains(res.stderr, "S3CR3T-IDP-CONFIG-SECRET") {
		t.Fatalf("update leaked the preserved config secret")
	}
	if res := runCLI(t, base("zero-trust", "access", "identity-provider", "update", "idp1")...); res.code != errors.CodeInvalid {
		t.Fatalf("empty update: code=%d", res.code)
	}

	del := base("zero-trust", "access", "identity-provider", "delete", "idp1")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != prefix+"/idp1" {
		t.Fatalf("delete request = %+v", req)
	}

	// A config secret must never surface in API error text: --config values are
	// registered as protected secrets before any request is made.
	apiEcho := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(400, 6003, "invalid client_secret S3CR3T-IDP-CONFIG-SECRET")
		return s, b
	})
	res = runCLI(t, "zero-trust", "access", "identity-provider", "create", "--name", "okta",
		"--type", "okta", "--config", "@"+configFile, "--account-id", accountID, "--endpoint-url", apiEcho.srv.URL)
	if res.code == 0 {
		t.Fatalf("echo stub should fail the command")
	}
	if strings.Contains(res.stderr, "S3CR3T-IDP-CONFIG-SECRET") {
		t.Fatalf("config secret leaked into API error text: %q", res.stderr)
	}
}

func TestAccessServiceTokens(t *testing.T) {
	api := v07API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}
	prefix := "/accounts/" + accountID + "/access/service_tokens"

	res := runCLI(t, base("zero-trust", "access", "service-token", "list", "--name", "ci", "--search", "ci")...)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Path != prefix || !strings.Contains(req.Query, "name=ci") || !strings.Contains(req.Query, "search=ci") {
		t.Fatalf("list request = %+v", req)
	}
	if !strings.Contains(res.stdout, "CID123") {
		t.Fatalf("list output = %s", res.stdout)
	}
	if strings.Contains(res.stdout, "S3CR3T-LEAKED-BY-LIST") {
		t.Fatalf("list printed a client secret returned by the API: %s", res.stdout)
	}

	res = runCLI(t, base("zero-trust", "access", "service-token", "get", "tok1", "--json")...)
	if res.code != 0 {
		t.Fatalf("get: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != prefix+"/tok1" {
		t.Fatalf("get path = %q", api.last().Path)
	}
	if strings.Contains(res.stdout, "S3CR3T-LEAKED-BY-GET") {
		t.Fatalf("get printed a client secret returned by the API: %s", res.stdout)
	}

	// create is the explicit request for the value: stdout only.
	res = runCLI(t, base("zero-trust", "access", "service-token", "create", "--name", "ci",
		"--duration", "8760h", "--debug")...)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "POST" || req.Path != prefix {
		t.Fatalf("create request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, map[string]any{"name": "ci", "duration": "8760h"}) {
		t.Fatalf("create body = %#v", got)
	}
	if !strings.Contains(res.stdout, "S3CR3T-CLIENT-SECRET") {
		t.Fatalf("create did not print the client secret: %s", res.stdout)
	}
	if !strings.Contains(res.stderr, "debug:") {
		t.Fatalf("expected debug diagnostics active: %q", res.stderr)
	}
	if strings.Contains(res.stderr, "S3CR3T-CLIENT-SECRET") {
		t.Fatalf("client secret leaked into --debug output: %q", res.stderr)
	}

	res = runCLI(t, base("zero-trust", "access", "service-token", "rotate", "tok1",
		"--previous-secret-expires-at", "2026-01-01T00:00:00Z")...)
	if res.code != 0 {
		t.Fatalf("rotate: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "POST" || req.Path != prefix+"/tok1/rotate" {
		t.Fatalf("rotate request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, map[string]any{"previous_client_secret_expires_at": "2026-01-01T00:00:00Z"}) {
		t.Fatalf("rotate body = %#v", got)
	}
	if !strings.Contains(res.stdout, "S3CR3T-ROTATED-SECRET") {
		t.Fatalf("rotate did not print the new client secret: %s", res.stdout)
	}
	if strings.Contains(res.stderr, "S3CR3T-ROTATED-SECRET") {
		t.Fatalf("rotated secret leaked into stderr: %q", res.stderr)
	}
	if res := runCLI(t, base("zero-trust", "access", "service-token", "rotate", "tok1", "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would rotate service token tok1") {
		t.Fatalf("rotate dry-run: code=%d stdout=%q", res.code, res.stdout)
	}

	res = runCLI(t, base("zero-trust", "access", "service-token", "update", "tok1", "--duration", "4380h")...)
	if res.code != 0 {
		t.Fatalf("update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PUT" || req.Path != prefix+"/tok1" {
		t.Fatalf("update request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); got["duration"] != "4380h" || got["name"] != "ci" {
		t.Fatalf("update body = %#v", got)
	}
	if strings.Contains(res.stdout, "S3CR3T-LEAKED-BY-GET") || strings.Contains(res.stderr, "S3CR3T-LEAKED-BY-GET") {
		t.Fatalf("update leaked the client secret carried through the read-modify-PUT")
	}

	for _, args := range [][]string{
		{"create"},
		{"update", "tok1"},
	} {
		res := runCLI(t, base(append([]string{"zero-trust", "access", "service-token"}, args...)...)...)
		if res.code != errors.CodeInvalid {
			t.Fatalf("%v: code=%d, want 2 (stderr=%q)", args, res.code, res.stderr)
		}
	}

	del := base("zero-trust", "access", "service-token", "delete", "tok1")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "DELETE" {
			t.Fatalf("DELETE without confirmation")
		}
	}
	if res := runCLI(t, append(append([]string{}, del...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete service token ci") {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != prefix+"/tok1" {
		t.Fatalf("delete request = %+v", req)
	}
}

func TestAccessSecretRedactedFromErrorText(t *testing.T) {
	// Both create and rotate register the client secret with ProtectSecret the
	// moment it is received; this proves that any later error text containing a
	// registered secret is scrubbed before it reaches stderr (the same
	// rt.Redact call the CLI error printer makes).
	rt := app.NewRuntime(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	rt.ProtectSecret("S3CR3T-CLIENT-SECRET")
	if got := rt.Redact("Error: upstream rejected S3CR3T-CLIENT-SECRET"); strings.Contains(got, "S3CR3T-CLIENT-SECRET") {
		t.Fatalf("registered client secret not redacted: %q", got)
	}
}

// ---- v0.4 slice 3: zero-trust Gateway and devices -------------------------

func gatewayRuleJSON(id, name string) map[string]any {
	return map[string]any{
		"id": id, "name": name, "action": "block", "enabled": true, "precedence": float64(1),
		"traffic":       "any(dns.security_category[*] in {\"malware\"})",
		"filters":       []any{map[string]any{"expression": "dns.fqdn in $list"}},
		"rule_settings": map[string]any{"block_page_enabled": true},
		"schedule":      map[string]any{"mon": "00:00-24:00"},
		"expiration":    map[string]any{"expires_at": "2026-01-01T00:00:00Z", "duration": float64(60)},
		"created_at":    "2025-01-01T00:00:00Z", "updated_at": "2025-01-02T00:00:00Z",
		"warning_status": "none", "read_only": false, "sharable": true, "version": float64(3),
	}
}

func gatewayListJSON() map[string]any {
	return map[string]any{
		"id": "list1", "name": "blocked", "type": "DOMAIN", "count": float64(2),
		"description": "blocked domains",
		"items": []any{
			map[string]any{"value": "a.example.com", "description": "ads", "created_at": "2025-01-01T00:00:00Z"},
			map[string]any{"value": "b.example.com"},
		},
		"created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-02T00:00:00Z",
	}
}

func gatewayLocationJSON() map[string]any {
	return map[string]any{
		"id": "loc1", "name": "office", "client_default": true, "ecs_support": false,
		"networks":               []any{map[string]any{"network": "192.0.2.0/24"}},
		"endpoints":              map[string]any{"doh": map[string]any{"enabled": true}},
		"max_ttl":                map[string]any{"dns_ttl": float64(30)},
		"dns_destination_ips_id": "dd1", "doh_subdomain": "office",
		"created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-02T00:00:00Z",
		"unmapped_location_field": "keep-me",
	}
}

func deviceJSON() map[string]any {
	return map[string]any{
		"id": "dev1", "name": "laptop", "device_type": "windows", "mac_address": "aa:bb:cc",
		"ip": "1.2.3.4", "last_seen": "2025-01-01T00:00:00Z",
		"created": "2024-01-01T00:00:00Z", "updated": "2025-01-02T00:00:00Z", "deleted": false,
		"key":  "S3CR3T-DEVICE-KEY",
		"user": map[string]any{"id": "u1", "email": "a@example.com", "name": "A"},
	}
}

func physicalDeviceJSON(id, name string) map[string]any {
	return map[string]any{
		"id": id, "name": name, "device_type": "windows", "os_version": "10.0.19045",
		"client_version": "2025.1.0", "last_seen_at": "2025-01-01T00:00:00Z",
		"last_seen_user":       map[string]any{"email": "a@example.com"},
		"active_registrations": float64(1), "hardware_id": "hw1",
	}
}

func devicePostureJSON() map[string]any {
	return map[string]any{
		"id": "post1", "name": "disk encrypted", "type": "disk_encryption", "enabled": true,
		"expiration": "24h", "schedule": "",
		"input":                  map[string]any{"requireAll": true},
		"match":                  []any{map[string]any{"platform": "windows"}},
		"unmapped_posture_field": "keep-me",
	}
}

func deviceSettingsJSON() map[string]any {
	return map[string]any{
		"gateway_proxy_enabled": true, "disable_for_time": float64(0),
		"use_zt_virtual_ip": false, "unmapped_setting": "keep-me",
	}
}

func v08API(t *testing.T) *apiStub {
	base := "/accounts/" + accountID
	gw := base + "/gateway"
	dev := base + "/devices"
	pd := dev + "/physical-devices"
	return newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		echoPUT := func() (int, string) {
			var body map[string]any
			_ = json.Unmarshal([]byte(r.Body), &body)
			return 200, envelope(body)
		}
		switch {
		// Gateway rules
		case method == "GET" && path == gw+"/rules":
			return 200, envelope([]any{gatewayRuleJSON("rule1", "block malware"), gatewayRuleJSON("rule2", "allow ops")})
		case method == "POST" && path == gw+"/rules":
			return 200, envelope(gatewayRuleJSON("rulenew", "new rule"))
		case path == gw+"/rules/rule1" && method == "GET":
			return 200, envelope(gatewayRuleJSON("rule1", "block malware"))
		case path == gw+"/rules/rule1" && method == "PUT":
			return echoPUT()
		case path == gw+"/rules/rule1" && method == "DELETE":
			return 200, envelope(gatewayRuleJSON("rule1", "block malware"))
		// Gateway lists
		case method == "GET" && path == gw+"/lists":
			return 200, envelope([]any{gatewayListJSON()})
		case method == "POST" && path == gw+"/lists":
			return 200, envelope(gatewayListJSON())
		case path == gw+"/lists/list1" && method == "GET":
			return 200, envelope(gatewayListJSON())
		case path == gw+"/lists/list1" && method == "PUT":
			return echoPUT()
		case path == gw+"/lists/list1" && method == "PATCH":
			return echoPUT()
		case path == gw+"/lists/list1" && method == "DELETE":
			return 200, envelope(gatewayListJSON())
		case method == "GET" && path == gw+"/lists/list1/items":
			return 200, envelope([]any{
				map[string]any{"value": "a.example.com", "description": "ads", "created_at": "2025-01-01T00:00:00Z"},
				map[string]any{"value": "b.example.com"},
			})
		// Gateway locations
		case method == "GET" && path == gw+"/locations":
			return 200, envelope([]any{gatewayLocationJSON()})
		case method == "POST" && path == gw+"/locations":
			return 200, envelope(gatewayLocationJSON())
		case path == gw+"/locations/loc1" && method == "GET":
			return 200, envelope(gatewayLocationJSON())
		case path == gw+"/locations/loc1" && method == "PUT":
			return echoPUT()
		case path == gw+"/locations/loc1" && method == "DELETE":
			return 200, envelope(gatewayLocationJSON())
		// Devices (legacy registrations)
		case method == "GET" && path == dev:
			return 200, envelope([]any{deviceJSON()})
		case path == dev+"/dev1" && method == "GET":
			return 200, envelope(deviceJSON())
		// Device fleet
		case method == "GET" && path == pd:
			if strings.Contains(r.Query, "cursor=page2") {
				return 200, envelopeWithInfo([]any{physicalDeviceJSON("pd2", "desktop")}, map[string]any{"count": float64(1)})
			}
			return 200, envelopeWithInfo([]any{physicalDeviceJSON("pd1", "laptop")}, map[string]any{
				"count":   float64(1),
				"cursors": map[string]any{"after": "page2"},
			})
		case path == pd+"/pd1" && method == "GET":
			return 200, envelope(physicalDeviceJSON("pd1", "laptop"))
		case path == pd+"/pd1" && method == "DELETE":
			return 200, envelope(physicalDeviceJSON("pd1", "laptop"))
		case path == pd+"/pd1/revoke" && method == "POST":
			return 200, envelope(map[string]any{})
		// Posture
		case method == "GET" && path == dev+"/posture":
			return 200, envelope([]any{devicePostureJSON()})
		case method == "POST" && path == dev+"/posture":
			return 200, envelope(devicePostureJSON())
		case path == dev+"/posture/post1" && method == "GET":
			return 200, envelope(devicePostureJSON())
		case path == dev+"/posture/post1" && method == "PUT":
			return echoPUT()
		case path == dev+"/posture/post1" && method == "DELETE":
			return 200, envelope(devicePostureJSON())
		// Settings
		case method == "GET" && path == dev+"/settings":
			return 200, envelope(deviceSettingsJSON())
		case method == "PUT" && path == dev+"/settings":
			var body map[string]any
			_ = json.Unmarshal([]byte(r.Body), &body)
			inner, _ := body["device_settings"].(map[string]any)
			return 200, envelope(inner)
		}
		s, b := apiErr(404, 7000, "not found")
		return s, b
	})
}

func TestGatewayRules(t *testing.T) {
	api := v08API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}
	prefix := "/accounts/" + accountID + "/gateway/rules"

	res := runCLI(t, base("zero-trust", "gateway", "rule", "list")...)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Path != prefix || req.Query != "" {
		t.Fatalf("list request = %+v", req)
	}
	if !strings.Contains(res.stdout, "block malware") || !strings.Contains(res.stdout, "block") {
		t.Fatalf("list output = %s", res.stdout)
	}
	res = runCLI(t, base("zero-trust", "gateway", "rule", "list", "--max-items", "1", "--json")...)
	if res.code != 0 {
		t.Fatalf("list --max-items: code=%d stderr=%q", res.code, res.stderr)
	}
	if strings.Contains(res.stdout, "allow ops") {
		t.Fatalf("--max-items did not truncate: %s", res.stdout)
	}

	res = runCLI(t, base("zero-trust", "gateway", "rule", "get", "rule1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "block malware") {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}

	res = runCLI(t, base("zero-trust", "gateway", "rule", "create", "--name", "new rule", "--action", "block",
		"--traffic", "any(dns.fqdn in $list)", "--enabled", "--precedence", "2",
		"--filters", `[{"expression":"dns.fqdn in $list"}]`,
		"--rule-settings", `{"block_page_enabled":true}`,
		"--schedule", `{"mon":"00:00-24:00"}`,
		"--expires-at", "2026-01-01T00:00:00Z", "--expiration-duration", "120")...)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "POST" || req.Path != prefix {
		t.Fatalf("create request = %+v", req)
	}
	want := map[string]any{
		"name": "new rule", "action": "block", "traffic": "any(dns.fqdn in $list)",
		"enabled": true, "precedence": float64(2),
		"filters":       []any{map[string]any{"expression": "dns.fqdn in $list"}},
		"rule_settings": map[string]any{"block_page_enabled": true},
		"schedule":      map[string]any{"mon": "00:00-24:00"},
		"expiration":    map[string]any{"expires_at": "2026-01-01T00:00:00Z", "duration": float64(120)},
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("create body mismatch\n got: %#v\nwant: %#v", got, want)
	}

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"create", "--action", "block"}, "--name is required"},
		{[]string{"create", "--name", "x"}, "--action is required"},
		{[]string{"create", "--name", "x", "--action", "explode"}, "invalid --action"},
		{[]string{"create", "--name", "x", "--action", "block", "--expiration-duration", "10"}, "--expires-at is required"},
		{[]string{"update", "rule1"}, "nothing to update"},
	} {
		res := runCLI(t, base(append([]string{"zero-trust", "gateway", "rule"}, tc.args...)...)...)
		if res.code != errors.CodeInvalid || !strings.Contains(res.stderr, tc.want) {
			t.Fatalf("%v: code=%d stderr=%q (want %q)", tc.args, res.code, res.stderr, tc.want)
		}
	}

	res = runCLI(t, base("zero-trust", "gateway", "rule", "update", "rule1", "--name", "renamed")...)
	if res.code != 0 {
		t.Fatalf("update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PUT" || req.Path != prefix+"/rule1" {
		t.Fatalf("update request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	if got["name"] != "renamed" || got["warning_status"] != "none" || got["action"] != "block" {
		t.Fatalf("update did not merge onto the current rule: %#v", got)
	}
	if res := runCLI(t, base("zero-trust", "gateway", "rule", "update", "rule1", "--name", "x", "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would update Gateway rule rule1") {
		t.Fatalf("dry-run update: code=%d stdout=%q", res.code, res.stdout)
	}

	del := base("zero-trust", "gateway", "rule", "delete", "rule1")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "DELETE" {
			t.Fatalf("DELETE without confirmation")
		}
	}
	if res := runCLI(t, append(append([]string{}, del...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete Gateway rule block malware") {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != prefix+"/rule1" {
		t.Fatalf("delete request = %+v", req)
	}

	api404 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(404, 7000, "rule not found")
		return s, b
	})
	if res := runCLI(t, "zero-trust", "gateway", "rule", "get", "rule1", "--account-id", accountID, "--endpoint-url", api404.srv.URL); res.code != errors.CodeNotFound {
		t.Fatalf("404: code=%d, want 5", res.code)
	}
	api403 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(403, 9109, "forbidden")
		return s, b
	})
	if res := runCLI(t, "zero-trust", "gateway", "rule", "list", "--account-id", accountID, "--endpoint-url", api403.srv.URL); res.code != errors.CodePermission {
		t.Fatalf("403: code=%d, want 4", res.code)
	}
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
	if res := runCLI(t, "zero-trust", "gateway", "rule", "list", "--endpoint-url", apiAmbig.srv.URL); res.code != errors.CodeInvalid {
		t.Fatalf("ambiguous account: code=%d, want 2 (stderr=%q)", res.code, res.stderr)
	}
}

func TestGatewayListsAndItems(t *testing.T) {
	api := v08API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}
	prefix := "/accounts/" + accountID + "/gateway/lists"

	res := runCLI(t, base("zero-trust", "gateway", "list", "list", "--type", "DOMAIN")...)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Path != prefix || !strings.Contains(req.Query, "type=DOMAIN") {
		t.Fatalf("list request = %+v", req)
	}
	if !strings.Contains(res.stdout, "blocked") || !strings.Contains(res.stdout, "DOMAIN") {
		t.Fatalf("list output = %s", res.stdout)
	}
	if res := runCLI(t, base("zero-trust", "gateway", "list", "list", "--type", "bogus")...); res.code != errors.CodeInvalid {
		t.Fatalf("invalid type: code=%d", res.code)
	}

	res = runCLI(t, base("zero-trust", "gateway", "list", "get", "list1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "list1") {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}

	res = runCLI(t, base("zero-trust", "gateway", "list", "create", "--name", "blocked", "--type", "DOMAIN",
		"--description", "blocked domains", "--items", `["a.example.com",{"value":"b.example.com","description":"ads"}]`)...)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "POST" || req.Path != prefix {
		t.Fatalf("create request = %+v", req)
	}
	want := map[string]any{
		"name": "blocked", "type": "DOMAIN", "description": "blocked domains",
		"items": []any{
			map[string]any{"value": "a.example.com"},
			map[string]any{"value": "b.example.com", "description": "ads"},
		},
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("create body mismatch\n got: %#v\nwant: %#v", got, want)
	}

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"create", "--type", "DOMAIN"}, "--name is required"},
		{[]string{"create", "--name", "x"}, "--type is required"},
		{[]string{"create", "--name", "x", "--type", "nope"}, "invalid --type"},
		{[]string{"create", "--name", "x", "--type", "DOMAIN", "--items", "not-json"}, "must be a JSON array"},
		{[]string{"create", "--name", "x", "--type", "DOMAIN", "--items", `[""]`}, "non-empty strings"},
		{[]string{"update", "list1"}, "nothing to update"},
	} {
		res := runCLI(t, base(append([]string{"zero-trust", "gateway", "list"}, tc.args...)...)...)
		if res.code != errors.CodeInvalid || !strings.Contains(res.stderr, tc.want) {
			t.Fatalf("%v: code=%d stderr=%q (want %q)", tc.args, res.code, res.stderr, tc.want)
		}
	}

	res = runCLI(t, base("zero-trust", "gateway", "list", "update", "list1", "--description", "updated")...)
	if res.code != 0 {
		t.Fatalf("update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PUT" || req.Path != prefix+"/list1" {
		t.Fatalf("update request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); got["description"] != "updated" || got["name"] != "blocked" {
		t.Fatalf("update body = %#v", got)
	}

	// items
	res = runCLI(t, base("zero-trust", "gateway", "list", "item", "list", "list1")...)
	if res.code != 0 {
		t.Fatalf("item list: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != prefix+"/list1/items" {
		t.Fatalf("item list path = %q", api.last().Path)
	}
	if !strings.Contains(res.stdout, "a.example.com") || !strings.Contains(res.stdout, "ads") {
		t.Fatalf("item list output = %s", res.stdout)
	}

	res = runCLI(t, base("zero-trust", "gateway", "list", "item", "create", "list1", "--items", `["c.example.com"]`)...)
	if res.code != 0 {
		t.Fatalf("item create: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PATCH" || req.Path != prefix+"/list1" {
		t.Fatalf("item create request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, map[string]any{"append": []any{map[string]any{"value": "c.example.com"}}}) {
		t.Fatalf("item create body = %#v", got)
	}
	if res := runCLI(t, base("zero-trust", "gateway", "list", "item", "create", "list1")...); res.code != errors.CodeInvalid {
		t.Fatalf("item create without --items: code=%d", res.code)
	}

	itemDel := base("zero-trust", "gateway", "list", "item", "delete", "list1", "--values", "a.example.com,b.example.com")
	if res := runCLI(t, itemDel...); res.code != errors.CodeInvalid {
		t.Fatalf("item delete refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "PATCH" {
			var body map[string]any
			_ = json.Unmarshal([]byte(r.Body), &body)
			if _, ok := body["remove"]; ok {
				t.Fatalf("remove PATCH issued without confirmation")
			}
		}
	}
	if res := runCLI(t, append(append([]string{}, itemDel...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would remove 2 item(s) from Gateway list list1") {
		t.Fatalf("item delete dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, itemDel...), "--yes")...); res.code != 0 {
		t.Fatalf("item delete: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PATCH" || req.Path != prefix+"/list1" {
		t.Fatalf("item delete request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, map[string]any{"remove": []any{"a.example.com", "b.example.com"}}) {
		t.Fatalf("item delete body = %#v", got)
	}

	del := base("zero-trust", "gateway", "list", "delete", "list1")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("list delete refusal: code=%d", res.code)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("list delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != prefix+"/list1" {
		t.Fatalf("list delete request = %+v", req)
	}
}

func TestGatewayLocations(t *testing.T) {
	api := v08API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}
	prefix := "/accounts/" + accountID + "/gateway/locations"

	res := runCLI(t, base("zero-trust", "gateway", "location", "list")...)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != prefix || !strings.Contains(res.stdout, "office") {
		t.Fatalf("list request = %+v stdout=%s", api.last(), res.stdout)
	}

	res = runCLI(t, base("zero-trust", "gateway", "location", "get", "loc1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "192.0.2.0/24") {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}

	res = runCLI(t, base("zero-trust", "gateway", "location", "create", "--name", "office",
		"--networks", "192.0.2.0/24,198.51.100.0/24", "--client-default",
		"--endpoints", `{"doh":{"enabled":true}}`, "--max-ttl", `{"dns_ttl":30}`)...)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || req.Path != prefix {
		t.Fatalf("create request = %+v", req)
	}
	want := map[string]any{
		"name": "office", "client_default": true,
		"networks":  []any{map[string]any{"network": "192.0.2.0/24"}, map[string]any{"network": "198.51.100.0/24"}},
		"endpoints": map[string]any{"doh": map[string]any{"enabled": true}},
		"max_ttl":   map[string]any{"dns_ttl": float64(30)},
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("create body mismatch\n got: %#v\nwant: %#v", got, want)
	}
	if res := runCLI(t, base("zero-trust", "gateway", "location", "create", "--networks", "10.0.0.0/8")...); res.code != errors.CodeInvalid {
		t.Fatalf("create without --name: code=%d", res.code)
	}

	res = runCLI(t, base("zero-trust", "gateway", "location", "update", "loc1", "--ecs-support")...)
	if res.code != 0 {
		t.Fatalf("update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PUT" || req.Path != prefix+"/loc1" {
		t.Fatalf("update request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	if got["ecs_support"] != true || got["unmapped_location_field"] != "keep-me" || got["name"] != "office" {
		t.Fatalf("update did not merge onto the current location: %#v", got)
	}
	if res := runCLI(t, base("zero-trust", "gateway", "location", "update", "loc1")...); res.code != errors.CodeInvalid {
		t.Fatalf("empty update: code=%d", res.code)
	}

	del := base("zero-trust", "gateway", "location", "delete", "loc1")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete Gateway location office") {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != prefix+"/loc1" {
		t.Fatalf("delete request = %+v", req)
	}
}

func TestDevices(t *testing.T) {
	api := v08API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}
	dev := "/accounts/" + accountID + "/devices"
	pd := dev + "/physical-devices"

	res := runCLI(t, base("zero-trust", "device", "list", "--json")...)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != dev {
		t.Fatalf("list path = %q", api.last().Path)
	}
	if !strings.Contains(res.stdout, "a@example.com") {
		t.Fatalf("list output = %s", res.stdout)
	}
	if strings.Contains(res.stdout, "S3CR3T-DEVICE-KEY") {
		t.Fatalf("device key leaked into normalized output: %s", res.stdout)
	}

	res = runCLI(t, base("zero-trust", "device", "get", "dev1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "laptop") {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}
	if strings.Contains(res.stdout, "S3CR3T-DEVICE-KEY") || strings.Contains(res.stderr, "S3CR3T-DEVICE-KEY") {
		t.Fatalf("device key leaked")
	}

	// the fleet list follows the cursor until exhaustion
	res = runCLI(t, base("zero-trust", "device", "physical-device", "list", "--search", "laptop",
		"--sort-by", "last_seen_at", "--sort-order", "desc", "--active-registrations", "include")...)
	if res.code != 0 {
		t.Fatalf("fleet list: code=%d stderr=%q", res.code, res.stderr)
	}
	var reqs []recordedRequest
	for _, r := range api.requests() {
		if r.Path == pd {
			reqs = append(reqs, r)
		}
	}
	if len(reqs) != 2 {
		t.Fatalf("expected 2 cursor pages, got %d requests", len(reqs))
	}
	if reqs[0].Path != pd || !strings.Contains(reqs[0].Query, "search=laptop") ||
		!strings.Contains(reqs[0].Query, "sort_by=last_seen_at") || !strings.Contains(reqs[0].Query, "sort_order=desc") ||
		!strings.Contains(reqs[0].Query, "active_registrations=include") || !strings.Contains(reqs[0].Query, "per_page=") {
		t.Fatalf("fleet list query = %q", reqs[0].Query)
	}
	if !strings.Contains(reqs[1].Query, "cursor=page2") {
		t.Fatalf("second page missing cursor: %q", reqs[1].Query)
	}
	if !strings.Contains(res.stdout, "laptop") || !strings.Contains(res.stdout, "desktop") {
		t.Fatalf("fleet list output = %s", res.stdout)
	}

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"physical-device", "list", "--active-registrations", "sometimes"}, "invalid --active-registrations"},
		{[]string{"physical-device", "list", "--sort-by", "color"}, "invalid --sort-by"},
		{[]string{"physical-device", "list", "--sort-order", "sideways"}, "invalid --sort-order"},
	} {
		res := runCLI(t, base(append([]string{"zero-trust", "device"}, tc.args...)...)...)
		if res.code != errors.CodeInvalid || !strings.Contains(res.stderr, tc.want) {
			t.Fatalf("%v: code=%d stderr=%q", tc.args, res.code, res.stderr)
		}
	}

	res = runCLI(t, base("zero-trust", "device", "physical-device", "get", "pd1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "laptop") {
		t.Fatalf("fleet get: code=%d stdout=%q", res.code, res.stdout)
	}

	rev := base("zero-trust", "device", "physical-device", "revoke", "pd1")
	if res := runCLI(t, rev...); res.code != errors.CodeInvalid {
		t.Fatalf("revoke refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "POST" && strings.HasSuffix(r.Path, "/revoke") {
			t.Fatalf("revoke without confirmation")
		}
	}
	if res := runCLI(t, append(append([]string{}, rev...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would revoke device laptop") {
		t.Fatalf("revoke dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, rev...), "--yes")...); res.code != 0 {
		t.Fatalf("revoke: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "POST" || req.Path != pd+"/pd1/revoke" {
		t.Fatalf("revoke request = %+v", req)
	}

	del := base("zero-trust", "device", "physical-device", "delete", "pd1")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("delete refusal: code=%d", res.code)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != pd+"/pd1" {
		t.Fatalf("delete request = %+v", req)
	}
}

func TestDevicePostureAndSettings(t *testing.T) {
	api := v08API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}
	dev := "/accounts/" + accountID + "/devices"

	res := runCLI(t, base("zero-trust", "device", "posture", "list")...)
	if res.code != 0 {
		t.Fatalf("posture list: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != dev+"/posture" || !strings.Contains(res.stdout, "disk encrypted") {
		t.Fatalf("posture list request = %+v stdout=%s", api.last(), res.stdout)
	}

	res = runCLI(t, base("zero-trust", "device", "posture", "get", "post1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "disk_encryption") {
		t.Fatalf("posture get: code=%d stdout=%q", res.code, res.stdout)
	}

	res = runCLI(t, base("zero-trust", "device", "posture", "create", "--name", "disk encrypted",
		"--type", "disk_encryption", "--input", `{"requireAll":true}`, "--match", `[{"platform":"windows"}]`,
		"--expiration", "24h")...)
	if res.code != 0 {
		t.Fatalf("posture create: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || req.Path != dev+"/posture" {
		t.Fatalf("posture create request = %+v", req)
	}
	want := map[string]any{
		"name": "disk encrypted", "type": "disk_encryption", "expiration": "24h",
		"input": map[string]any{"requireAll": true},
		"match": []any{map[string]any{"platform": "windows"}},
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("posture create body mismatch\n got: %#v\nwant: %#v", got, want)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"create", "--type", "disk_encryption"}, "--name is required"},
		{[]string{"create", "--name", "x"}, "--type is required"},
		{[]string{"create", "--name", "x", "--type", "vibes"}, "invalid --type"},
		{[]string{"update", "post1"}, "nothing to update"},
	} {
		res := runCLI(t, base(append([]string{"zero-trust", "device", "posture"}, tc.args...)...)...)
		if res.code != errors.CodeInvalid || !strings.Contains(res.stderr, tc.want) {
			t.Fatalf("%v: code=%d stderr=%q (want %q)", tc.args, res.code, res.stderr, tc.want)
		}
	}

	res = runCLI(t, base("zero-trust", "device", "posture", "update", "post1", "--expiration", "48h")...)
	if res.code != 0 {
		t.Fatalf("posture update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PUT" || req.Path != dev+"/posture/post1" {
		t.Fatalf("posture update request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	if got["expiration"] != "48h" || got["unmapped_posture_field"] != "keep-me" {
		t.Fatalf("posture update did not merge: %#v", got)
	}

	pdel := base("zero-trust", "device", "posture", "delete", "post1")
	if res := runCLI(t, pdel...); res.code != errors.CodeInvalid {
		t.Fatalf("posture delete refusal: code=%d", res.code)
	}
	if res := runCLI(t, append(append([]string{}, pdel...), "--yes")...); res.code != 0 {
		t.Fatalf("posture delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != dev+"/posture/post1" {
		t.Fatalf("posture delete request = %+v", req)
	}

	// settings
	res = runCLI(t, base("zero-trust", "device", "settings", "get", "--json")...)
	if res.code != 0 {
		t.Fatalf("settings get: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != dev+"/settings" {
		t.Fatalf("settings get path = %q", api.last().Path)
	}
	if !strings.Contains(res.stdout, "unmapped_setting") {
		t.Fatalf("settings get dropped unmapped fields: %s", res.stdout)
	}
	res = runCLI(t, base("zero-trust", "device", "settings", "get")...)
	if res.code != 0 || !strings.Contains(res.stdout, "gateway_proxy_enabled") || !strings.Contains(res.stdout, "unmapped_setting") {
		t.Fatalf("settings table: code=%d stdout=%q", res.code, res.stdout)
	}

	res = runCLI(t, base("zero-trust", "device", "settings", "update",
		"--gateway-udp-proxy-enabled", "--settings", `{"external_emergency_signal_enabled":true}`)...)
	if res.code != 0 {
		t.Fatalf("settings update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PUT" || req.Path != dev+"/settings" {
		t.Fatalf("settings update request = %+v", req)
	}
	got = decodeRequestBody(t, req.Body)
	inner, ok := got["device_settings"].(map[string]any)
	if !ok {
		t.Fatalf("settings update body = %#v", got)
	}
	if inner["gateway_udp_proxy_enabled"] != true || inner["external_emergency_signal_enabled"] != true ||
		inner["gateway_proxy_enabled"] != true || inner["unmapped_setting"] != "keep-me" {
		t.Fatalf("settings update did not merge: %#v", inner)
	}

	if res := runCLI(t, base("zero-trust", "device", "settings", "update")...); res.code != errors.CodeInvalid {
		t.Fatalf("empty settings update: code=%d", res.code)
	}
	if res := runCLI(t, base("zero-trust", "device", "settings", "update", "--gateway-proxy-enabled", "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would update account device settings") {
		t.Fatalf("settings dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
}

// ---- v0.5: Workers and Pages ----------------------------------------------

func workerScriptJSON() map[string]any {
	return map[string]any{
		"id": "hello", "created_on": "2025-01-01T00:00:00Z", "modified_on": "2025-01-02T00:00:00Z",
		"etag": "etag1", "handlers": []any{"fetch"}, "compatibility_date": "2026-01-01",
		"compatibility_flags": []any{"nodejs_compat"}, "usage_model": "standard",
		"has_modules": true, "tags": []any{"team-a"}, "last_deployed_from": "api",
	}
}

func workerSettingsJSON() map[string]any {
	return map[string]any{
		"compatibility_date": "2026-01-01",
		"bindings":           []any{map[string]any{"type": "plain_text", "name": "API_BASE", "text": "https://api.example.com"}},
		"limits":             map[string]any{"cpu_ms": float64(50)},
		"unmodeled_setting":  "keep-me",
	}
}

func workerVersionJSON(id string, number int) map[string]any {
	return map[string]any{"id": id, "number": float64(number), "metadata": map[string]any{"main_module": "main"}}
}

func workerDeploymentJSON() map[string]any {
	return map[string]any{
		"id": "dep1", "created_on": "2025-01-03T00:00:00Z", "strategy": "percentage",
		"versions":     []any{map[string]any{"version_id": "v1", "percentage": float64(100)}},
		"author_email": "a@example.com", "annotations": map[string]any{"workers/triggered_by": "api"},
	}
}

func pagesProjectJSON() map[string]any {
	return map[string]any{
		"id": "p1", "name": "docs", "subdomain": "docs.pages.dev", "production_branch": "main",
		"framework": "none", "framework_version": "", "created_on": "2025-01-01T00:00:00Z",
		"uses_functions": false, "domains": []any{"docs.example.com"},
		"build_config": map[string]any{"build_command": "npm run build", "destination_dir": "dist"},
		"deployment_configs": map[string]any{
			"production": map[string]any{"env_vars": map[string]any{"SECRET_TOKEN": map[string]any{"value": "S3CR3T-ENV-VALUE"}}},
			"preview":    map[string]any{"env_vars": map[string]any{"SECRET_TOKEN": map[string]any{"value": "S3CR3T-ENV-VALUE"}}},
		},
		"source": map[string]any{"type": "github", "config": map[string]any{"owner": "acme", "repo_name": "docs"}},
	}
}

func pagesDeploymentJSON() map[string]any {
	return map[string]any{
		"id": "dep1", "short_id": "abc123", "project_id": "p1", "project_name": "docs",
		"environment": "production", "url": "https://abc123.docs.pages.dev",
		"created_on": "2025-01-03T00:00:00Z", "modified_on": "2025-01-03T00:05:00Z",
		"is_skipped": false, "aliases": []any{"docs.example.com"},
		"latest_stage": map[string]any{"name": "deploy", "status": "success"},
	}
}

func pagesDomainJSON() map[string]any {
	return map[string]any{
		"id": "pd1", "domain_id": "dmn1", "name": "docs.example.com", "status": "active",
		"certificate_authority": "google", "zone_tag": zoneID, "created_on": "2025-01-01T00:00:00Z",
	}
}

// multipartForm parses a recorded multipart request body.
func multipartForm(t *testing.T, contentType, body string) (map[string]string, map[string]string) {
	t.Helper()
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		t.Fatalf("content type %q: %v", contentType, err)
	}
	if !strings.HasPrefix(mediaType, "multipart/") {
		t.Fatalf("content type = %q, want multipart/form-data", contentType)
	}
	fields := map[string]string{}
	files := map[string]string{}
	reader := multipart.NewReader(strings.NewReader(body), params["boundary"])
	for {
		part, err := reader.NextPart()
		if err != nil {
			break
		}
		data, _ := io.ReadAll(part)
		name := part.FormName()
		if part.FileName() != "" {
			files[name] = string(data)
			continue
		}
		fields[name] = string(data)
	}
	return fields, files
}

func v09API(t *testing.T) *apiStub {
	acc := "/accounts/" + accountID
	zs := "/zones/" + zoneID
	return newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		echoBody := func(prefix string) (int, string) {
			var body map[string]any
			_ = json.Unmarshal([]byte(r.Body), &body)
			if prefix != "" {
				if inner, ok := body[prefix].(map[string]any); ok {
					return 200, envelope(inner)
				}
			}
			return 200, envelope(body)
		}
		switch {
		// scripts
		case method == "GET" && path == acc+"/workers/scripts":
			return 200, envelope([]any{workerScriptJSON()})
		case method == "PUT" && path == acc+"/workers/scripts/hello":
			return 200, envelope(workerScriptJSON())
		case method == "DELETE" && path == acc+"/workers/scripts/hello":
			return 200, envelope(map[string]any{})
		case method == "GET" && path == acc+"/workers/scripts/hello/content/v2":
			return 200, "export default { fetch() { return new Response(\"hi\") } }\n"
		// settings
		case method == "GET" && path == acc+"/workers/scripts/hello/settings":
			return 200, envelope(workerSettingsJSON())
		case method == "PATCH" && path == acc+"/workers/scripts/hello/settings":
			return echoBody("settings")
		// secrets
		case method == "GET" && path == acc+"/workers/scripts/hello/secrets":
			return 200, envelope([]any{map[string]any{"name": "API_KEY", "type": "secret_text"}})
		case method == "GET" && path == acc+"/workers/scripts/hello/secrets/API_KEY":
			return 200, envelope(map[string]any{"name": "API_KEY", "type": "secret_text"})
		case method == "PUT" && path == acc+"/workers/scripts/hello/secrets":
			var body map[string]any
			_ = json.Unmarshal([]byte(r.Body), &body)
			return 200, envelope(map[string]any{"name": body["name"], "type": body["type"]})
		case method == "DELETE" && path == acc+"/workers/scripts/hello/secrets/API_KEY":
			return 200, envelope(map[string]any{})
		// versions
		case method == "GET" && path == acc+"/workers/scripts/hello/versions":
			return 200, envelopeWithInfo([]any{workerVersionJSON("v1", 1)}, map[string]any{"page": float64(1), "per_page": float64(100), "count": float64(1), "total_count": float64(1), "total_pages": float64(1)})
		case method == "GET" && path == acc+"/workers/scripts/hello/versions/v1":
			return 200, envelope(workerVersionJSON("v1", 1))
		case method == "POST" && path == acc+"/workers/scripts/hello/versions":
			return 200, envelope(workerVersionJSON("v2", 2))
		// deployments
		case method == "GET" && path == acc+"/workers/scripts/hello/deployments":
			return 200, envelope(map[string]any{"deployments": []any{workerDeploymentJSON()}})
		case method == "GET" && path == acc+"/workers/scripts/hello/deployments/dep1":
			return 200, envelope(workerDeploymentJSON())
		case method == "POST" && path == acc+"/workers/scripts/hello/deployments":
			return 200, envelope(workerDeploymentJSON())
		case method == "DELETE" && path == acc+"/workers/scripts/hello/deployments/dep1":
			return 200, envelope(map[string]any{})
		// schedules
		case method == "GET" && path == acc+"/workers/scripts/hello/schedules":
			return 200, envelope(map[string]any{"schedules": []any{map[string]any{"cron": "*/5 * * * *"}}})
		case method == "PUT" && path == acc+"/workers/scripts/hello/schedules":
			var body []map[string]any
			_ = json.Unmarshal([]byte(r.Body), &body)
			return 200, envelope(map[string]any{"schedules": body})
		// script subdomain
		case method == "GET" && path == acc+"/workers/scripts/hello/subdomain":
			return 200, envelope(map[string]any{"enabled": true, "previews_enabled": false})
		case method == "POST" && path == acc+"/workers/scripts/hello/subdomain":
			return 200, envelope(map[string]any{"enabled": true, "previews_enabled": true})
		case method == "DELETE" && path == acc+"/workers/scripts/hello/subdomain":
			return 200, envelope(map[string]any{"enabled": false, "previews_enabled": false})
		// routes
		case method == "GET" && path == zs+"/workers/routes":
			return 200, envelope([]any{map[string]any{"id": "r1", "pattern": "example.com/api/*", "script": "api"}})
		case method == "POST" && path == zs+"/workers/routes":
			return 200, envelope(map[string]any{"id": "rnew", "pattern": "example.com/new/*", "script": "api"})
		case method == "GET" && path == zs+"/workers/routes/r1":
			return 200, envelope(map[string]any{"id": "r1", "pattern": "example.com/api/*", "script": "api"})
		case method == "PUT" && path == zs+"/workers/routes/r1":
			return echoBody("")
		case method == "DELETE" && path == zs+"/workers/routes/r1":
			return 200, envelope(map[string]any{})
		// custom domains
		case method == "GET" && path == acc+"/workers/domains":
			return 200, envelope([]any{workerDomainJSON()})
		case method == "PUT" && path == acc+"/workers/domains":
			return 200, envelope(workerDomainJSON())
		case method == "GET" && path == acc+"/workers/domains/wd1":
			return 200, envelope(workerDomainJSON())
		case method == "DELETE" && path == acc+"/workers/domains/wd1":
			return 200, envelope(map[string]any{})
		// account subdomain and settings
		case method == "GET" && path == acc+"/workers/subdomain":
			return 200, envelope(map[string]any{"subdomain": "acme"})
		case method == "PUT" && path == acc+"/workers/subdomain":
			var body map[string]any
			_ = json.Unmarshal([]byte(r.Body), &body)
			return 200, envelope(map[string]any{"subdomain": body["subdomain"]})
		case method == "DELETE" && path == acc+"/workers/subdomain":
			return 200, envelope(map[string]any{})
		case method == "GET" && path == acc+"/workers/account-settings":
			return 200, envelope(map[string]any{"default_usage_model": "standard", "green_compute": false, "unmodeled": "keep-me"})
		case method == "PUT" && path == acc+"/workers/account-settings":
			return echoBody("")
		// pages projects
		case method == "GET" && path == acc+"/pages/projects":
			return 200, envelopeWithInfo([]any{pagesProjectJSON()}, map[string]any{"page": float64(1), "per_page": float64(100), "count": float64(1), "total_count": float64(1), "total_pages": float64(1)})
		case method == "POST" && path == acc+"/pages/projects":
			return 200, envelope(pagesProjectJSON())
		case method == "GET" && path == acc+"/pages/projects/docs":
			return 200, envelope(pagesProjectJSON())
		case method == "PATCH" && path == acc+"/pages/projects/docs":
			return echoBody("")
		case method == "DELETE" && path == acc+"/pages/projects/docs":
			return 200, envelope(pagesProjectJSON())
		// pages deployments
		case method == "GET" && path == acc+"/pages/projects/docs/deployments":
			return 200, envelopeWithInfo([]any{pagesDeploymentJSON()}, map[string]any{"page": float64(1), "per_page": float64(100), "count": float64(1), "total_count": float64(1), "total_pages": float64(1)})
		case method == "GET" && path == acc+"/pages/projects/docs/deployments/dep1":
			return 200, envelope(pagesDeploymentJSON())
		case method == "DELETE" && path == acc+"/pages/projects/docs/deployments/dep1":
			return 200, envelope(pagesDeploymentJSON())
		// pages domains
		case method == "GET" && path == acc+"/pages/projects/docs/domains":
			return 200, envelope([]any{pagesDomainJSON()})
		case method == "POST" && path == acc+"/pages/projects/docs/domains":
			return 200, envelope(pagesDomainJSON())
		case method == "GET" && path == acc+"/pages/projects/docs/domains/docs.example.com":
			return 200, envelope(pagesDomainJSON())
		case method == "PATCH" && path == acc+"/pages/projects/docs/domains/docs.example.com":
			return 200, envelope(pagesDomainJSON())
		case method == "DELETE" && path == acc+"/pages/projects/docs/domains/docs.example.com":
			return 200, envelope(map[string]any{})
		}
		s, b := apiErr(404, 7000, "not found")
		return s, b
	})
}

func workerDomainJSON() map[string]any {
	return map[string]any{
		"id": "wd1", "hostname": "api.example.com", "service": "api", "environment": "production",
		"zone_id": zoneID, "zone_name": "example.com",
	}
}

func TestWorkerScriptLifecycle(t *testing.T) {
	api := v09API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}
	prefix := "/accounts/" + accountID + "/workers/scripts"

	res := runCLI(t, base("workers", "script", "list", "--tags", "team-a")...)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Path != prefix || !strings.Contains(req.Query, "tags=team-a") {
		t.Fatalf("list request = %+v", req)
	}
	if !strings.Contains(res.stdout, "hello") || !strings.Contains(res.stdout, "2026-01-01") {
		t.Fatalf("list output = %s", res.stdout)
	}

	metadataFile := filepath.Join(t.TempDir(), "metadata.json")
	_ = os.WriteFile(metadataFile, []byte(`{"main_module":"main","compatibility_date":"2026-01-01","bindings":[{"type":"secret_text","name":"API_KEY","text":"S3CR3T-BINDING-VALUE"}]}`), 0o600)
	moduleFile := filepath.Join(t.TempDir(), "hello.js")
	_ = os.WriteFile(moduleFile, []byte(`export default { fetch() {} }`), 0o600)

	res = runCLI(t, base("workers", "script", "update", "hello", "--metadata", "@"+metadataFile, "--file", "main=@"+moduleFile)...)
	if res.code != 0 {
		t.Fatalf("update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PUT" || req.Path != prefix+"/hello" {
		t.Fatalf("update request = %+v", req)
	}
	fields, files := multipartForm(t, req.ContentType, req.Body)
	if got := fields["metadata"]; !strings.Contains(got, `"main_module":"main"`) {
		t.Fatalf("metadata part = %q", got)
	}
	if got := files["main"]; got != `export default { fetch() {} }` {
		t.Fatalf("file part = %q", got)
	}
	if strings.Contains(res.stderr, "S3CR3T-BINDING-VALUE") {
		t.Fatalf("binding secret leaked to stderr: %q", res.stderr)
	}

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"update", "hello", "--file", "main=@" + moduleFile}, "--metadata is required"},
		{[]string{"update", "hello", "--metadata", "@" + metadataFile}, "at least one --file"},
		{[]string{"update", "hello", "--metadata", `{"main_module":"main"}`, "--file", "main=@" + moduleFile}, "@file form"},
		{[]string{"update", "hello", "--metadata", "@" + metadataFile, "--file", "other=@" + moduleFile}, "references \"main\""},
		{[]string{"update", "hello", "--metadata", "@" + metadataFile, "--file", "main=" + moduleFile}, "only the @file form"},
	} {
		res := runCLI(t, base(append([]string{"workers", "script"}, tc.args...)...)...)
		if res.code != errors.CodeInvalid || !strings.Contains(res.stderr, tc.want) {
			t.Fatalf("%v: code=%d stderr=%q (want %q)", tc.args, res.code, res.stderr, tc.want)
		}
	}

	before := api.count()
	res = runCLI(t, base("workers", "script", "update", "hello", "--metadata", "@"+metadataFile, "--file", "main=@"+moduleFile, "--dry-run")...)
	if res.code != 0 || !strings.Contains(res.stdout, "Would upload script hello (1 file(s)") || api.count() != before {
		t.Fatalf("update dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if strings.Contains(res.stdout, "export default") || strings.Contains(res.stdout, "S3CR3T-BINDING-VALUE") {
		t.Fatalf("dry-run leaked upload content: %q", res.stdout)
	}

	res = runCLI(t, base("workers", "script", "content", "get", "hello")...)
	if res.code != 0 {
		t.Fatalf("content get: code=%d stderr=%q", res.code, res.stderr)
	}
	if res.stdout != "export default { fetch() { return new Response(\"hi\") } }\n" {
		t.Fatalf("content stdout = %q", res.stdout)
	}
	if api.last().Path != prefix+"/hello/content/v2" {
		t.Fatalf("content path = %q", api.last().Path)
	}

	del := base("workers", "script", "delete", "hello")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "DELETE" && r.Path == prefix+"/hello" {
			t.Fatalf("DELETE without confirmation")
		}
	}
	if res := runCLI(t, append(append([]string{}, del...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete script hello") {
		t.Fatalf("delete dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes", "--force")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "DELETE" || req.Path != prefix+"/hello" || !strings.Contains(req.Query, "force=true") {
		t.Fatalf("delete request = %+v", req)
	}

	api404 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(404, 7000, "script not found")
		return s, b
	})
	if res := runCLI(t, "workers", "script", "list", "--account-id", accountID, "--endpoint-url", api404.srv.URL); res.code != errors.CodeNotFound {
		t.Fatalf("404: code=%d, want 5", res.code)
	}
	api403 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(403, 9109, "forbidden")
		return s, b
	})
	if res := runCLI(t, "workers", "script", "list", "--account-id", accountID, "--endpoint-url", api403.srv.URL); res.code != errors.CodePermission {
		t.Fatalf("403: code=%d, want 4", res.code)
	}
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
	if res := runCLI(t, "workers", "script", "list", "--endpoint-url", apiAmbig.srv.URL); res.code != errors.CodeInvalid {
		t.Fatalf("ambiguous account: code=%d, want 2 (stderr=%q)", res.code, res.stderr)
	}
}

func TestWorkerScriptSettingsAndSecrets(t *testing.T) {
	api := v09API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}
	prefix := "/accounts/" + accountID + "/workers/scripts/hello"

	res := runCLI(t, base("workers", "script", "settings", "get", "hello")...)
	if res.code != 0 {
		t.Fatalf("settings get: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != prefix+"/settings" || !strings.Contains(res.stdout, "2026-01-01") {
		t.Fatalf("settings get request = %+v stdout=%s", api.last(), res.stdout)
	}

	res = runCLI(t, base("workers", "script", "settings", "update", "hello", "--usage-model", "bundled",
		"--compatibility-flags", "nodejs_compat,workers_dev")...)
	if res.code != 0 {
		t.Fatalf("settings update: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "PATCH" || req.Path != prefix+"/settings" {
		t.Fatalf("settings update request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	inner, ok := got["settings"].(map[string]any)
	if !ok {
		t.Fatalf("settings update body = %#v", got)
	}
	if inner["usage_model"] != "bundled" || inner["unmodeled_setting"] != "keep-me" {
		t.Fatalf("settings merge failed: %#v", inner)
	}
	if flags, ok := inner["compatibility_flags"].([]any); !ok || len(flags) != 2 {
		t.Fatalf("compatibility flags = %#v", inner["compatibility_flags"])
	}
	// bindings are @file-only
	bindingsFile := filepath.Join(t.TempDir(), "bindings.json")
	_ = os.WriteFile(bindingsFile, []byte(`[{"type":"secret_text","name":"API_KEY","text":"S3CR3T-BINDING"}]`), 0o600)
	res = runCLI(t, base("workers", "script", "settings", "update", "hello", "--bindings", "@"+bindingsFile)...)
	if res.code != 0 {
		t.Fatalf("bindings update: code=%d stderr=%q", res.code, res.stderr)
	}
	if got := decodeRequestBody(t, api.last().Body); got["settings"].(map[string]any)["bindings"] == nil {
		t.Fatalf("bindings not sent: %#v", got)
	}
	if strings.Contains(res.stderr, "S3CR3T-BINDING") {
		t.Fatalf("binding secret leaked: %q", res.stderr)
	}
	if res := runCLI(t, base("workers", "script", "settings", "update", "hello")...); res.code != errors.CodeInvalid {
		t.Fatalf("empty settings update: code=%d", res.code)
	}
	if res := runCLI(t, base("workers", "script", "settings", "update", "hello", "--bindings", `[{"type":"secret_text","name":"X","text":"y"}]`)...); res.code != errors.CodeInvalid || !strings.Contains(res.stderr, "@file form") {
		t.Fatalf("inline bindings: code=%d stderr=%q", res.code, res.stderr)
	}

	// secrets
	res = runCLI(t, base("workers", "script", "secret", "list", "hello")...)
	if res.code != 0 || !strings.Contains(res.stdout, "API_KEY") {
		t.Fatalf("secret list: code=%d stdout=%q", res.code, res.stdout)
	}
	if api.last().Path != prefix+"/secrets" {
		t.Fatalf("secret list path = %q", api.last().Path)
	}
	res = runCLI(t, base("workers", "script", "secret", "get", "hello", "API_KEY")...)
	if res.code != 0 || !strings.Contains(res.stdout, "secret_text") {
		t.Fatalf("secret get: code=%d stdout=%q", res.code, res.stdout)
	}

	secretFile := filepath.Join(t.TempDir(), "secret.txt")
	_ = os.WriteFile(secretFile, []byte("S3CR3T-SECRET-VALUE"), 0o600)
	res = runCLI(t, base("workers", "script", "secret", "create", "hello", "--name", "API_KEY", "--text", "@"+secretFile, "--debug")...)
	if res.code != 0 {
		t.Fatalf("secret create: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PUT" || req.Path != prefix+"/secrets" {
		t.Fatalf("secret create request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); got["name"] != "API_KEY" || got["type"] != "secret_text" || got["text"] != "S3CR3T-SECRET-VALUE" {
		t.Fatalf("secret create body = %#v", got)
	}
	if !strings.Contains(res.stderr, "debug:") {
		t.Fatalf("expected debug diagnostics active: %q", res.stderr)
	}
	if strings.Contains(res.stderr, "S3CR3T-SECRET-VALUE") {
		t.Fatalf("secret value leaked into --debug output: %q", res.stderr)
	}
	if res := runCLI(t, base("workers", "script", "secret", "create", "hello", "--name", "X", "--text", "S3CR3T-INLINE")...); res.code != errors.CodeInvalid || !strings.Contains(res.stderr, "@file form") {
		t.Fatalf("inline secret: code=%d stderr=%q", res.code, res.stderr)
	}
	if strings.Contains(res.stderr, "S3CR3T-INLINE") {
		t.Fatalf("inline secret value echoed: %q", res.stderr)
	}
	if res := runCLI(t, base("workers", "script", "secret", "create", "hello", "--name", "X")...); res.code != errors.CodeInvalid || !strings.Contains(res.stderr, "--text is required") {
		t.Fatalf("missing secret value: code=%d stderr=%q", res.code, res.stderr)
	}
	before := api.count()
	res = runCLI(t, base("workers", "script", "secret", "create", "hello", "--name", "API_KEY", "--text", "@"+secretFile, "--dry-run")...)
	if res.code != 0 || !strings.Contains(res.stdout, "value hidden") || api.count() != before {
		t.Fatalf("secret dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if strings.Contains(res.stdout, "S3CR3T-SECRET-VALUE") {
		t.Fatalf("dry-run leaked the secret value: %q", res.stdout)
	}

	del := base("workers", "script", "secret", "delete", "hello", "API_KEY")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("secret delete refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "DELETE" && r.Path == prefix+"/secrets/API_KEY" {
			t.Fatalf("DELETE without confirmation")
		}
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("secret delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != prefix+"/secrets/API_KEY" {
		t.Fatalf("secret delete request = %+v", req)
	}

	// An API error that echoes the request body must not leak the secret: the
	// value is registered with ProtectSecret before the request is made.
	apiEcho := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		var body map[string]any
		_ = json.Unmarshal([]byte(r.Body), &body)
		s, b := apiErr(400, 6003, fmt.Sprintf("invalid secret %v", body["text"]))
		return s, b
	})
	res = runCLI(t, "workers", "script", "secret", "create", "hello", "--name", "API_KEY",
		"--text", "@"+secretFile, "--account-id", accountID, "--endpoint-url", apiEcho.srv.URL)
	if res.code == 0 {
		t.Fatalf("echo stub should fail the command")
	}
	if strings.Contains(res.stderr, "S3CR3T-SECRET-VALUE") {
		t.Fatalf("secret leaked into API error text: %q", res.stderr)
	}
}

func TestWorkerVersionsAndDeployments(t *testing.T) {
	api := v09API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}
	prefix := "/accounts/" + accountID + "/workers/scripts/hello"

	res := runCLI(t, base("workers", "script", "version", "list", "hello", "--deployable")...)
	if res.code != 0 {
		t.Fatalf("version list: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Path != prefix+"/versions" || !strings.Contains(req.Query, "deployable=true") || !strings.Contains(req.Query, "page=1") {
		t.Fatalf("version list request = %+v", req)
	}
	if !strings.Contains(res.stdout, "v1") {
		t.Fatalf("version list output = %s", res.stdout)
	}

	res = runCLI(t, base("workers", "script", "version", "get", "hello", "v1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "v1") {
		t.Fatalf("version get: code=%d stdout=%q", res.code, res.stdout)
	}

	metadataFile := filepath.Join(t.TempDir(), "metadata.json")
	_ = os.WriteFile(metadataFile, []byte(`{"main_module":"main","compatibility_date":"2026-01-01"}`), 0o600)
	moduleFile := filepath.Join(t.TempDir(), "hello.js")
	_ = os.WriteFile(moduleFile, []byte("export default {}"), 0o600)
	res = runCLI(t, base("workers", "script", "version", "create", "hello", "--metadata", "@"+metadataFile, "--file", "main=@"+moduleFile)...)
	if res.code != 0 {
		t.Fatalf("version create: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "POST" || req.Path != prefix+"/versions" {
		t.Fatalf("version create request = %+v", req)
	}
	fields, files := multipartForm(t, req.ContentType, req.Body)
	if !strings.Contains(fields["metadata"], "main_module") || files["main"] != "export default {}" {
		t.Fatalf("version upload parts = %#v/%#v", fields, files)
	}

	res = runCLI(t, base("workers", "script", "deployment", "list", "hello")...)
	if res.code != 0 {
		t.Fatalf("deployment list: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != prefix+"/deployments" || !strings.Contains(res.stdout, "dep1") || !strings.Contains(res.stdout, "percentage") {
		t.Fatalf("deployment list request = %+v stdout=%s", api.last(), res.stdout)
	}
	res = runCLI(t, base("workers", "script", "deployment", "get", "hello", "dep1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "dep1") {
		t.Fatalf("deployment get: code=%d stdout=%q", res.code, res.stdout)
	}

	res = runCLI(t, base("workers", "script", "deployment", "create", "hello", "--version", "v1=100")...)
	if res.code != 0 {
		t.Fatalf("deployment create: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "POST" || req.Path != prefix+"/deployments" {
		t.Fatalf("deployment create request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	dep, ok := got["deployment"].(map[string]any)
	if !ok {
		t.Fatalf("deployment create body = %#v", got)
	}
	versions, ok := dep["versions"].([]any)
	if !ok || len(versions) != 1 {
		t.Fatalf("deployment versions = %#v", dep)
	}
	if entry := versions[0].(map[string]any); entry["version_id"] != "v1" || entry["percentage"] != float64(100) {
		t.Fatalf("deployment version entry = %#v", entry)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"deployment", "create", "hello"}, "at least one --version"},
		{[]string{"deployment", "create", "hello", "--version", "v1"}, "VERSION_ID=PERCENTAGE"},
		{[]string{"deployment", "create", "hello", "--version", "v1=abc"}, "invalid percentage"},
	} {
		res := runCLI(t, base(append([]string{"workers", "script"}, tc.args...)...)...)
		if res.code != errors.CodeInvalid || !strings.Contains(res.stderr, tc.want) {
			t.Fatalf("%v: code=%d stderr=%q (want %q)", tc.args, res.code, res.stderr, tc.want)
		}
	}

	res = runCLI(t, base("workers", "script", "deployment", "create", "hello", "--version", "v1=100", "--force", "--dry-run")...)
	if res.code != 0 || !strings.Contains(res.stdout, "Would deploy script hello (v1=100%)") {
		t.Fatalf("deployment dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, base("workers", "script", "deployment", "create", "hello", "--version", "v1=100", "--force")...); res.code != 0 {
		t.Fatalf("deployment force: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); !strings.Contains(req.Query, "force=true") {
		t.Fatalf("deployment force query = %q", req.Query)
	}

	del := base("workers", "script", "deployment", "delete", "hello", "dep1")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("deployment delete refusal: code=%d", res.code)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("deployment delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != prefix+"/deployments/dep1" {
		t.Fatalf("deployment delete request = %+v", req)
	}
}

func TestWorkerSchedulesSubdomainsAndSettings(t *testing.T) {
	api := v09API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}
	acc := "/accounts/" + accountID
	prefix := acc + "/workers/scripts/hello"

	res := runCLI(t, base("workers", "script", "schedule", "get", "hello")...)
	if res.code != 0 || !strings.Contains(res.stdout, "*/5 * * * *") {
		t.Fatalf("schedule get: code=%d stdout=%q", res.code, res.stdout)
	}
	res = runCLI(t, base("workers", "script", "schedule", "update", "hello", "--cron", "0 3 * * *", "--cron", "0 4 * * *")...)
	if res.code != 0 {
		t.Fatalf("schedule update: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "PUT" || req.Path != prefix+"/schedules" {
		t.Fatalf("schedule update request = %+v", req)
	}
	var crons []map[string]string
	if err := json.Unmarshal([]byte(req.Body), &crons); err != nil {
		t.Fatalf("schedule body: %v (%s)", err, req.Body)
	}
	if len(crons) != 2 || crons[0]["cron"] != "0 3 * * *" {
		t.Fatalf("schedule body = %#v", crons)
	}
	if res := runCLI(t, base("workers", "script", "schedule", "update", "hello", "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would clear the cron schedule of script hello") {
		t.Fatalf("schedule clear dry-run: code=%d stdout=%q", res.code, res.stdout)
	}

	res = runCLI(t, base("workers", "script", "subdomain", "get", "hello")...)
	if res.code != 0 || !strings.Contains(res.stdout, "true") {
		t.Fatalf("subdomain get: code=%d stdout=%q", res.code, res.stdout)
	}
	res = runCLI(t, base("workers", "script", "subdomain", "enable", "hello", "--previews")...)
	if res.code != 0 {
		t.Fatalf("subdomain enable: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "POST" || req.Path != prefix+"/subdomain" {
		t.Fatalf("subdomain enable request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); got["enabled"] != true || got["previews_enabled"] != true {
		t.Fatalf("subdomain enable body = %#v", got)
	}
	dis := base("workers", "script", "subdomain", "disable", "hello")
	if res := runCLI(t, dis...); res.code != errors.CodeInvalid {
		t.Fatalf("subdomain disable refusal: code=%d", res.code)
	}
	if res := runCLI(t, append(append([]string{}, dis...), "--yes")...); res.code != 0 {
		t.Fatalf("subdomain disable: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != prefix+"/subdomain" {
		t.Fatalf("subdomain disable request = %+v", req)
	}

	res = runCLI(t, base("workers", "subdomain", "get")...)
	if res.code != 0 || !strings.Contains(res.stdout, "acme") {
		t.Fatalf("account subdomain get: code=%d stdout=%q", res.code, res.stdout)
	}
	res = runCLI(t, base("workers", "subdomain", "update", "--name", "acme2")...)
	if res.code != 0 {
		t.Fatalf("account subdomain update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PUT" || req.Path != acc+"/workers/subdomain" {
		t.Fatalf("account subdomain request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); got["subdomain"] != "acme2" {
		t.Fatalf("account subdomain body = %#v", got)
	}
	subDel := base("workers", "subdomain", "delete")
	if res := runCLI(t, subDel...); res.code != errors.CodeInvalid {
		t.Fatalf("account subdomain delete refusal: code=%d", res.code)
	}
	if res := runCLI(t, append(append([]string{}, subDel...), "--yes")...); res.code != 0 {
		t.Fatalf("account subdomain delete: code=%d stderr=%q", res.code, res.stderr)
	}

	res = runCLI(t, base("workers", "account-settings", "get")...)
	if res.code != 0 || !strings.Contains(res.stdout, "standard") {
		t.Fatalf("account settings get: code=%d stdout=%q", res.code, res.stdout)
	}
	res = runCLI(t, base("workers", "account-settings", "update", "--default-usage-model", "unbound")...)
	if res.code != 0 {
		t.Fatalf("account settings update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PUT" || req.Path != acc+"/workers/account-settings" {
		t.Fatalf("account settings request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	if got["default_usage_model"] != "unbound" || got["unmodeled"] != "keep-me" {
		t.Fatalf("account settings merge failed: %#v", got)
	}
	if res := runCLI(t, base("workers", "account-settings", "update")...); res.code != errors.CodeInvalid {
		t.Fatalf("empty account settings update: code=%d", res.code)
	}
}

func TestWorkerRoutesAndDomains(t *testing.T) {
	api := v09API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--zone", zoneID, "--endpoint-url", ep)
	}
	routes := "/zones/" + zoneID + "/workers/routes"
	acc := "/accounts/" + accountID

	res := runCLI(t, base("workers", "route", "list")...)
	if res.code != 0 {
		t.Fatalf("route list: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != routes || !strings.Contains(res.stdout, "example.com/api/*") {
		t.Fatalf("route list request = %+v stdout=%s", api.last(), res.stdout)
	}
	res = runCLI(t, base("workers", "route", "get", "r1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "api") {
		t.Fatalf("route get: code=%d stdout=%q", res.code, res.stdout)
	}

	res = runCLI(t, base("workers", "route", "create", "--pattern", "example.com/new/*", "--script", "api")...)
	if res.code != 0 {
		t.Fatalf("route create: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || req.Path != routes {
		t.Fatalf("route create request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, map[string]any{"pattern": "example.com/new/*", "script": "api"}) {
		t.Fatalf("route create body = %#v", got)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"create", "--script", "api"}, "--pattern is required"},
		{[]string{"create", "--pattern", "x/*"}, "--script is required"},
		{[]string{"update", "r1"}, "nothing to update"},
	} {
		res := runCLI(t, base(append([]string{"workers", "route"}, tc.args...)...)...)
		if res.code != errors.CodeInvalid || !strings.Contains(res.stderr, tc.want) {
			t.Fatalf("%v: code=%d stderr=%q (want %q)", tc.args, res.code, res.stderr, tc.want)
		}
	}

	res = runCLI(t, base("workers", "route", "update", "r1", "--script", "api2")...)
	if res.code != 0 {
		t.Fatalf("route update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PUT" || req.Path != routes+"/r1" {
		t.Fatalf("route update request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); got["script"] != "api2" {
		t.Fatalf("route update body = %#v", got)
	}
	del := base("workers", "route", "delete", "r1")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("route delete refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "DELETE" && r.Path == routes+"/r1" {
			t.Fatalf("DELETE without confirmation")
		}
	}
	if res := runCLI(t, append(append([]string{}, del...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete route example.com/api/*") {
		t.Fatalf("route delete dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("route delete: code=%d stderr=%q", res.code, res.stderr)
	}

	res = runCLI(t, base("workers", "domain", "list", "--hostname", "api.example.com", "--service", "api")...)
	if res.code != 0 {
		t.Fatalf("domain list: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Path != acc+"/workers/domains" || !strings.Contains(req.Query, "hostname=api.example.com") || !strings.Contains(req.Query, "service=api") {
		t.Fatalf("domain list request = %+v", req)
	}
	res = runCLI(t, base("workers", "domain", "get", "wd1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "api.example.com") {
		t.Fatalf("domain get: code=%d stdout=%q", res.code, res.stdout)
	}

	res = runCLI(t, base("workers", "domain", "create", "--hostname", "api.example.com", "--service", "api", "--zone-name", "example.com", "--environment", "production")...)
	if res.code != 0 {
		t.Fatalf("domain create: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PUT" || req.Path != acc+"/workers/domains" {
		t.Fatalf("domain create request = %+v", req)
	}
	want := map[string]any{"hostname": "api.example.com", "service": "api", "zone_name": "example.com", "environment": "production"}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("domain create body = %#v (want %#v)", got, want)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"create", "--service", "api"}, "--hostname is required"},
		{[]string{"create", "--hostname", "x.example.com"}, "--service is required"},
	} {
		res := runCLI(t, base(append([]string{"workers", "domain"}, tc.args...)...)...)
		if res.code != errors.CodeInvalid || !strings.Contains(res.stderr, tc.want) {
			t.Fatalf("%v: code=%d stderr=%q", tc.args, res.code, res.stderr)
		}
	}
	domDel := base("workers", "domain", "delete", "wd1")
	if res := runCLI(t, domDel...); res.code != errors.CodeInvalid {
		t.Fatalf("domain delete refusal: code=%d", res.code)
	}
	if res := runCLI(t, append(append([]string{}, domDel...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would detach domain api.example.com") {
		t.Fatalf("domain delete dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, domDel...), "--yes")...); res.code != 0 {
		t.Fatalf("domain delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != acc+"/workers/domains/wd1" {
		t.Fatalf("domain delete request = %+v", req)
	}

	// route commands need a zone
	res = runCLI(t, "workers", "route", "list", "--account-id", accountID, "--endpoint-url", ep)
	if res.code != errors.CodeInvalid {
		t.Fatalf("missing zone: code=%d, want 2 (stderr=%q)", res.code, res.stderr)
	}
}

func TestPagesProjects(t *testing.T) {
	api := v09API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}
	acc := "/accounts/" + accountID
	projects := acc + "/pages/projects"

	res := runCLI(t, base("pages", "project", "list")...)
	if res.code != 0 {
		t.Fatalf("project list: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != projects || !strings.Contains(res.stdout, "docs") || !strings.Contains(res.stdout, "main") {
		t.Fatalf("project list request = %+v stdout=%s", api.last(), res.stdout)
	}
	res = runCLI(t, base("pages", "project", "get", "docs", "--json")...)
	if res.code != 0 {
		t.Fatalf("project get: code=%d stderr=%q", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "docs.pages.dev") {
		t.Fatalf("project get output = %s", res.stdout)
	}

	res = runCLI(t, base("pages", "project", "create", "--name", "docs", "--production-branch", "main",
		"--build-config", `{"build_command":"npm run build"}`)...)
	if res.code != 0 {
		t.Fatalf("project create: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || req.Path != projects {
		t.Fatalf("project create request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	if got["name"] != "docs" || got["production_branch"] != "main" || got["build_config"] == nil {
		t.Fatalf("project create body = %#v", got)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"create", "--production-branch", "main"}, "--name is required"},
		{[]string{"create", "--name", "docs"}, "--production-branch is required"},
		{[]string{"update", "docs"}, "nothing to update"},
	} {
		res := runCLI(t, base(append([]string{"pages", "project"}, tc.args...)...)...)
		if res.code != errors.CodeInvalid || !strings.Contains(res.stderr, tc.want) {
			t.Fatalf("%v: code=%d stderr=%q (want %q)", tc.args, res.code, res.stderr, tc.want)
		}
	}

	res = runCLI(t, base("pages", "project", "update", "docs", "--production-branch", "release")...)
	if res.code != 0 {
		t.Fatalf("project update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PATCH" || req.Path != projects+"/docs" {
		t.Fatalf("project update request = %+v", req)
	}
	got = decodeRequestBody(t, req.Body)
	if got["production_branch"] != "release" || got["build_config"] == nil {
		t.Fatalf("project update did not merge: %#v", got)
	}

	// deployment configs are @file-only and their env values are protected
	configsFile := filepath.Join(t.TempDir(), "configs.json")
	_ = os.WriteFile(configsFile, []byte(`{"production":{"env_vars":{"SECRET_TOKEN":{"value":"S3CR3T-ENV-VALUE"}}}}`), 0o600)
	res = runCLI(t, base("pages", "project", "update", "docs", "--deployment-configs", "@"+configsFile)...)
	if res.code != 0 {
		t.Fatalf("project update configs: code=%d stderr=%q", res.code, res.stderr)
	}
	if strings.Contains(res.stderr, "S3CR3T-ENV-VALUE") || strings.Contains(res.stdout, "S3CR3T-ENV-VALUE") {
		t.Fatalf("env value leaked: stdout=%q stderr=%q", res.stdout, res.stderr)
	}
	if res := runCLI(t, base("pages", "project", "update", "docs", "--deployment-configs", `{"production":{}}`)...); res.code != errors.CodeInvalid || !strings.Contains(res.stderr, "@file form") {
		t.Fatalf("inline deployment configs: code=%d stderr=%q", res.code, res.stderr)
	}
	// an API error echoing the request body must not leak the env value
	apiEcho := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(400, 6003, "invalid body "+r.Body)
		return s, b
	})
	res = runCLI(t, "pages", "project", "update", "docs", "--deployment-configs", "@"+configsFile,
		"--account-id", accountID, "--endpoint-url", apiEcho.srv.URL)
	if res.code == 0 {
		t.Fatalf("echo stub should fail the command")
	}
	if strings.Contains(res.stderr, "S3CR3T-ENV-VALUE") {
		t.Fatalf("env value leaked into API error text: %q", res.stderr)
	}

	projDel := base("pages", "project", "delete", "docs")
	if res := runCLI(t, projDel...); res.code != errors.CodeInvalid {
		t.Fatalf("project delete refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "DELETE" && r.Path == projects+"/docs" {
			t.Fatalf("DELETE without confirmation")
		}
	}
	if res := runCLI(t, append(append([]string{}, projDel...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete Pages project docs") {
		t.Fatalf("project delete dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, projDel...), "--yes")...); res.code != 0 {
		t.Fatalf("project delete: code=%d stderr=%q", res.code, res.stderr)
	}

	// deployments
	res = runCLI(t, base("pages", "project", "deployment", "list", "docs", "--env", "production")...)
	if res.code != 0 {
		t.Fatalf("deployment list: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Path != projects+"/docs/deployments" || !strings.Contains(req.Query, "env=production") {
		t.Fatalf("deployment list request = %+v", req)
	}
	if !strings.Contains(res.stdout, "dep1") || !strings.Contains(res.stdout, "deploy (success)") {
		t.Fatalf("deployment list output = %s", res.stdout)
	}
	res = runCLI(t, base("pages", "project", "deployment", "get", "docs", "dep1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "production") {
		t.Fatalf("deployment get: code=%d stdout=%q", res.code, res.stdout)
	}
	depDel := base("pages", "project", "deployment", "delete", "docs", "dep1")
	if res := runCLI(t, depDel...); res.code != errors.CodeInvalid {
		t.Fatalf("deployment delete refusal: code=%d", res.code)
	}
	if res := runCLI(t, append(append([]string{}, depDel...), "--yes")...); res.code != 0 {
		t.Fatalf("deployment delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != projects+"/docs/deployments/dep1" {
		t.Fatalf("deployment delete request = %+v", req)
	}

	// project domains
	res = runCLI(t, base("pages", "project", "domain", "list", "docs")...)
	if res.code != 0 || !strings.Contains(res.stdout, "docs.example.com") {
		t.Fatalf("domain list: code=%d stdout=%q", res.code, res.stdout)
	}
	if api.last().Path != projects+"/docs/domains" {
		t.Fatalf("domain list path = %q", api.last().Path)
	}
	res = runCLI(t, base("pages", "project", "domain", "get", "docs", "docs.example.com")...)
	if res.code != 0 || !strings.Contains(res.stdout, "active") {
		t.Fatalf("domain get: code=%d stdout=%q", res.code, res.stdout)
	}
	res = runCLI(t, base("pages", "project", "domain", "create", "docs", "--name", "docs.example.com")...)
	if res.code != 0 {
		t.Fatalf("domain create: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "POST" || req.Path != projects+"/docs/domains" {
		t.Fatalf("domain create request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); got["name"] != "docs.example.com" {
		t.Fatalf("domain create body = %#v", got)
	}
	if res := runCLI(t, base("pages", "project", "domain", "create", "docs")...); res.code != errors.CodeInvalid {
		t.Fatalf("domain create without name: code=%d", res.code)
	}
	res = runCLI(t, base("pages", "project", "domain", "update", "docs", "docs.example.com")...)
	if res.code != 0 {
		t.Fatalf("domain update: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "PATCH" || req.Path != projects+"/docs/domains/docs.example.com" {
		t.Fatalf("domain update request = %+v", req)
	}
	pageDomDel := base("pages", "project", "domain", "delete", "docs", "docs.example.com")
	if res := runCLI(t, pageDomDel...); res.code != errors.CodeInvalid {
		t.Fatalf("domain delete refusal: code=%d", res.code)
	}
	if res := runCLI(t, append(append([]string{}, pageDomDel...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would detach domain docs.example.com") {
		t.Fatalf("domain delete dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, pageDomDel...), "--yes")...); res.code != 0 {
		t.Fatalf("domain delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != projects+"/docs/domains/docs.example.com" {
		t.Fatalf("domain delete request = %+v", req)
	}

	// account resolution applies to Pages too: with no account in scope the
	// command fails with a usage error rather than guessing.
	apiNone := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		if method == "GET" && path == "/accounts" {
			return 200, envelope([]any{})
		}
		s, b := apiErr(404, 7000, "not found")
		return s, b
	})
	// no accessible account maps to the permission exit code
	res = runCLI(t, "pages", "project", "list", "--endpoint-url", apiNone.srv.URL)
	if res.code != errors.CodePermission {
		t.Fatalf("missing account: code=%d, want 4 (stderr=%q)", res.code, res.stderr)
	}
}

// ---- v0.6 slice 1: Logpush, health checks, load balancing ------------------

func logpushJobJSON() map[string]any {
	return map[string]any{
		"id": float64(11), "name": "requests", "dataset": "http_requests", "enabled": true,
		"frequency": "high", "kind": "edge",
		"destination_conf": "s3://bucket/path?access_key_id=AKIA&secret_access_key=S3CR3T-AWS-KEY",
		"last_complete":    "2025-01-01T00:00:00Z", "last_error": "", "logpull_options": "fields=ClientIP",
		"max_upload_bytes": float64(1000), "max_upload_interval_seconds": float64(30), "max_upload_records": float64(100),
	}
}

func healthcheckJSON() map[string]any {
	return map[string]any{
		"id": "hc1", "name": "web", "address": "example.com", "type": "HTTPS",
		"status": "healthy", "suspended": false, "interval": float64(60), "retries": float64(2),
		"timeout": float64(5), "check_regions": []any{"WEU"}, "consecutive_fails": float64(3),
		"consecutive_successes": float64(2), "http_config": map[string]any{"path": "/health"},
		"created_on": "2025-01-01T00:00:00Z", "modified_on": "2025-01-02T00:00:00Z",
	}
}

func loadBalancerJSON() map[string]any {
	return map[string]any{
		"id": "lb1", "name": "www", "enabled": true, "proxied": true, "steering_policy": "dynamic",
		"default_pools": []any{"pool-a", "pool-b"}, "fallback_pool": "pool-c", "ttl": float64(30),
		"zone_name": "example.com", "created_on": "2025-01-01T00:00:00Z",
	}
}

func poolJSON() map[string]any {
	return map[string]any{
		"id": "pool-a", "name": "primary", "enabled": true, "monitor": "mon1", "minimum_origins": float64(1),
		"origins": []any{map[string]any{"name": "o1", "address": "192.0.2.1", "weight": float64(1), "enabled": true}},
	}
}

func monitorJSON() map[string]any {
	return map[string]any{
		"id": "mon1", "type": "https", "method": "GET", "path": "/health", "interval": float64(60),
		"timeout": float64(5), "retries": float64(2), "expected_codes": "2xx", "probe_zone": "example.com",
		"header": map[string]any{"Authorization": "S3CR3T-MONITOR-HEADER"},
	}
}

func v10API(t *testing.T) *apiStub {
	acc := "/accounts/" + accountID
	zns := "/zones/" + zoneID
	return newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		echoBody := func(prefix string) (int, string) {
			var body map[string]any
			_ = json.Unmarshal([]byte(r.Body), &body)
			if prefix != "" {
				if inner, ok := body[prefix].(map[string]any); ok {
					return 200, envelope(inner)
				}
			}
			return 200, envelope(body)
		}
		switch {
		// logpush jobs
		case method == "GET" && (path == acc+"/logpush/jobs" || path == zns+"/logpush/jobs"):
			return 200, envelope([]any{logpushJobJSON()})
		case method == "POST" && (path == acc+"/logpush/jobs" || path == zns+"/logpush/jobs"):
			return 200, envelope(logpushJobJSON())
		case method == "GET" && (path == acc+"/logpush/jobs/11" || path == zns+"/logpush/jobs/11"):
			return 200, envelope(logpushJobJSON())
		case method == "PUT" && (path == acc+"/logpush/jobs/11" || path == zns+"/logpush/jobs/11"):
			return echoBody("")
		case method == "DELETE" && (path == acc+"/logpush/jobs/11" || path == zns+"/logpush/jobs/11"):
			return 200, envelope(map[string]any{})
		// datasets
		case method == "GET" && path == acc+"/logpush/datasets/http_requests/fields":
			return 200, envelope(map[string]any{"ClientIP": "string", "EdgeResponseStatus": "int"})
		case method == "GET" && path == zns+"/logpush/datasets/http_requests/fields":
			return 200, envelope(map[string]any{"ClientIP": "string"})
		case method == "GET" && path == acc+"/logpush/datasets/http_requests/jobs":
			return 200, envelope([]any{logpushJobJSON()})
		// transformers
		case method == "GET" && path == acc+"/logpush/transformers":
			return 200, envelope([]any{map[string]any{"id": float64(5), "name": "redact", "dataset": "http_requests", "associated_jobs": float64(1), "updated_at": "2025-01-02T00:00:00Z"}})
		case method == "POST" && path == acc+"/logpush/transformers":
			return 200, envelope(map[string]any{"id": float64(6), "name": "redact", "dataset": "", "associated_jobs": float64(0)})
		case method == "GET" && path == acc+"/logpush/transformers/5":
			return 200, envelope(map[string]any{"id": float64(5), "name": "redact", "dataset": "http_requests", "associated_jobs": float64(1)})
		case method == "PUT" && path == acc+"/logpush/transformers/5":
			return echoBody("")
		case method == "DELETE" && path == acc+"/logpush/transformers/5":
			return 200, envelope(map[string]any{})
		case method == "GET" && path == acc+"/logpush/transformers/5/content":
			return 200, envelope(map[string]any{"content": "export default function(payload) { return payload }\n"})
		case method == "GET" && path == acc+"/logpush/transformers/5/versions":
			return 200, envelope([]any{map[string]any{"id": float64(1), "version": float64(1)}})
		// health checks
		case method == "GET" && path == zns+"/healthchecks":
			return 200, envelopeWithInfo([]any{healthcheckJSON()}, map[string]any{"page": float64(1), "per_page": float64(100), "count": float64(1), "total_count": float64(1), "total_pages": float64(1)})
		case method == "POST" && path == zns+"/healthchecks":
			return echoBody("query_healthcheck")
		case method == "GET" && path == zns+"/healthchecks/hc1":
			return 200, envelope(healthcheckJSON())
		case method == "PUT" && path == zns+"/healthchecks/hc1":
			return echoBody("query_healthcheck")
		case method == "DELETE" && path == zns+"/healthchecks/hc1":
			return 200, envelope(map[string]any{})
		case method == "POST" && path == zns+"/healthchecks/preview":
			return echoBody("query_healthcheck")
		case method == "GET" && path == zns+"/healthchecks/preview/hcprev":
			return 200, envelope(healthcheckJSON())
		case method == "DELETE" && path == zns+"/healthchecks/preview/hcprev":
			return 200, envelope(map[string]any{})
		// load balancers
		case method == "GET" && (path == acc+"/load_balancers" || path == zns+"/load_balancers"):
			return 200, envelope([]any{loadBalancerJSON()})
		case method == "POST" && (path == acc+"/load_balancers" || path == zns+"/load_balancers"):
			return 200, envelope(loadBalancerJSON())
		case method == "GET" && (path == acc+"/load_balancers/lb1" || path == zns+"/load_balancers/lb1"):
			return 200, envelope(loadBalancerJSON())
		case method == "PATCH" && (path == acc+"/load_balancers/lb1" || path == zns+"/load_balancers/lb1"):
			return echoBody("")
		case method == "DELETE" && (path == acc+"/load_balancers/lb1" || path == zns+"/load_balancers/lb1"):
			return 200, envelope(map[string]any{})
		// pools
		case method == "GET" && path == acc+"/load_balancers/pools":
			return 200, envelope([]any{poolJSON()})
		case method == "POST" && path == acc+"/load_balancers/pools":
			return echoBody("")
		case method == "GET" && path == acc+"/load_balancers/pools/pool-a":
			return 200, envelope(poolJSON())
		case method == "PATCH" && path == acc+"/load_balancers/pools/pool-a":
			return echoBody("")
		case method == "DELETE" && path == acc+"/load_balancers/pools/pool-a":
			return 200, envelope(map[string]any{})
		case method == "GET" && path == acc+"/load_balancers/pools/pool-a/health":
			return 200, envelope(map[string]any{"pool_id": "pool-a", "pop_health": map[string]any{"WEU": map[string]any{"healthy": true}}})
		// monitors
		case method == "GET" && path == acc+"/load_balancers/monitors":
			return 200, envelope([]any{monitorJSON()})
		case method == "POST" && path == acc+"/load_balancers/monitors":
			return echoBody("")
		case method == "GET" && path == acc+"/load_balancers/monitors/mon1":
			return 200, envelope(monitorJSON())
		case method == "PATCH" && path == acc+"/load_balancers/monitors/mon1":
			return echoBody("")
		case method == "DELETE" && path == acc+"/load_balancers/monitors/mon1":
			return 200, envelope(map[string]any{})
		// regions
		case method == "GET" && path == acc+"/load_balancers/regions":
			return 200, envelope([]any{map[string]any{"id": "WEU", "name": "Western Europe"}})
		case method == "GET" && path == acc+"/load_balancers/regions/WEU":
			return 200, envelope(map[string]any{"id": "WEU", "name": "Western Europe"})
		}
		s, b := apiErr(404, 7000, "not found")
		return s, b
	})
}

func TestLogpushJobs(t *testing.T) {
	api := v10API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}
	acc := "/accounts/" + accountID
	zns := "/zones/" + zoneID

	res := runCLI(t, base("logpush", "job", "list")...)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != acc+"/logpush/jobs" || !strings.Contains(res.stdout, "requests") || !strings.Contains(res.stdout, "http_requests") {
		t.Fatalf("list request = %+v stdout=%s", api.last(), res.stdout)
	}
	if strings.Contains(res.stdout, "S3CR3T-AWS-KEY") {
		t.Fatalf("destination credentials leaked into normalized output: %s", res.stdout)
	}
	res = runCLI(t, base("logpush", "job", "get", "11")...)
	if res.code != 0 || !strings.Contains(res.stdout, "requests") {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}
	if strings.Contains(res.stdout, "S3CR3T-AWS-KEY") {
		t.Fatalf("destination credentials leaked from get: %s", res.stdout)
	}

	destFile := filepath.Join(t.TempDir(), "dest.txt")
	_ = os.WriteFile(destFile, []byte("s3://bucket/path?access_key_id=AKIA&secret_access_key=S3CR3T-AWS-KEY"), 0o600)
	res = runCLI(t, base("logpush", "job", "create", "--destination-conf", "@"+destFile,
		"--dataset", "http_requests", "--name", "requests", "--enabled", "--max-upload-records", "100")...)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || req.Path != acc+"/logpush/jobs" {
		t.Fatalf("create request = %+v", req)
	}
	want := map[string]any{
		"destination_conf": "s3://bucket/path?access_key_id=AKIA&secret_access_key=S3CR3T-AWS-KEY",
		"dataset":          "http_requests", "name": "requests", "enabled": true, "max_upload_records": float64(100),
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("create body mismatch\n got: %#v\nwant: %#v", got, want)
	}
	if strings.Contains(res.stderr, "S3CR3T-AWS-KEY") {
		t.Fatalf("destination credentials leaked to stderr")
	}

	before := api.count()
	res = runCLI(t, base("logpush", "job", "create", "--destination-conf", "@"+destFile,
		"--dataset", "http_requests", "--name", "requests", "--dry-run")...)
	if res.code != 0 || !strings.Contains(res.stdout, "Would create Logpush job requests for dataset http_requests (destination hidden)") || api.count() != before {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if strings.Contains(res.stdout, "S3CR3T-AWS-KEY") {
		t.Fatalf("dry-run leaked the destination: %q", res.stdout)
	}

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"create", "--dataset", "http_requests"}, "--destination-conf is required"},
		{[]string{"create", "--destination-conf", "@" + destFile}, "--dataset is required"},
		{[]string{"create", "--destination-conf", "s3://inline", "--dataset", "x"}, "@file form"},
		{[]string{"update", "abc", "--enabled"}, "JOB_ID must be a positive integer"},
		{[]string{"update", "11"}, "nothing to update"},
	} {
		res := runCLI(t, base(append([]string{"logpush", "job"}, tc.args...)...)...)
		if res.code != errors.CodeInvalid || !strings.Contains(res.stderr, tc.want) {
			t.Fatalf("%v: code=%d stderr=%q (want %q)", tc.args, res.code, res.stderr, tc.want)
		}
	}

	res = runCLI(t, base("logpush", "job", "update", "11", "--enabled=false", "--frequency", "5m")...)
	if res.code != 0 {
		t.Fatalf("update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PUT" || req.Path != acc+"/logpush/jobs/11" {
		t.Fatalf("update request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	if got["enabled"] != false || got["frequency"] != "5m" {
		t.Fatalf("update body = %#v", got)
	}
	if _, ok := got["destination_conf"]; !ok {
		t.Fatalf("read-modify-PUT should preserve the existing destination: %#v", got)
	}

	del := base("logpush", "job", "delete", "11")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "DELETE" && r.Path == acc+"/logpush/jobs/11" {
			t.Fatalf("DELETE without confirmation")
		}
	}
	if res := runCLI(t, append(append([]string{}, del...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete Logpush job 11") {
		t.Fatalf("delete dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}

	// zone scope with --zone
	res = runCLI(t, base("logpush", "job", "list", "--zone", zoneID)...)
	if res.code != 0 {
		t.Fatalf("zone list: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != zns+"/logpush/jobs" {
		t.Fatalf("zone-scoped path = %q", api.last().Path)
	}

	// an API error echoing the request body must not leak the destination
	apiEcho := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(400, 6003, "invalid body "+r.Body)
		return s, b
	})
	res = runCLI(t, "logpush", "job", "create", "--destination-conf", "@"+destFile, "--dataset", "http_requests",
		"--name", "requests", "--account-id", accountID, "--endpoint-url", apiEcho.srv.URL)
	if res.code == 0 {
		t.Fatalf("echo stub should fail the command")
	}
	if strings.Contains(res.stderr, "S3CR3T-AWS-KEY") {
		t.Fatalf("destination leaked into API error text: %q", res.stderr)
	}
}

func TestLogpushDatasetsAndTransformers(t *testing.T) {
	api := v10API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}
	acc := "/accounts/" + accountID

	res := runCLI(t, base("logpush", "dataset", "field", "list", "http_requests")...)
	if res.code != 0 {
		t.Fatalf("field list: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != acc+"/logpush/datasets/http_requests/fields" {
		t.Fatalf("field list path = %q", api.last().Path)
	}
	if !strings.Contains(res.stdout, "ClientIP") || !strings.Contains(res.stdout, "string") {
		t.Fatalf("field list output = %s", res.stdout)
	}
	res = runCLI(t, base("logpush", "dataset", "field", "list", "http_requests", "--json")...)
	if res.code != 0 || !strings.Contains(res.stdout, "\"EdgeResponseStatus\"") {
		t.Fatalf("field list json: code=%d stdout=%q", res.code, res.stdout)
	}

	res = runCLI(t, base("logpush", "dataset", "job", "list", "http_requests")...)
	if res.code != 0 {
		t.Fatalf("dataset job list: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != acc+"/logpush/datasets/http_requests/jobs" || !strings.Contains(res.stdout, "requests") {
		t.Fatalf("dataset job list request = %+v stdout=%s", api.last(), res.stdout)
	}

	res = runCLI(t, base("logpush", "dataset", "field", "list", "http_requests", "--zone", zoneID)...)
	if res.code != 0 {
		t.Fatalf("zone field list: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != "/zones/"+zoneID+"/logpush/datasets/http_requests/fields" {
		t.Fatalf("zone field path = %q", api.last().Path)
	}

	// transformers
	res = runCLI(t, base("logpush", "transformer", "list")...)
	if res.code != 0 || !strings.Contains(res.stdout, "redact") {
		t.Fatalf("transformer list: code=%d stdout=%q", res.code, res.stdout)
	}
	if api.last().Path != acc+"/logpush/transformers" {
		t.Fatalf("transformer list path = %q", api.last().Path)
	}
	res = runCLI(t, base("logpush", "transformer", "get", "5")...)
	if res.code != 0 || !strings.Contains(res.stdout, "redact") {
		t.Fatalf("transformer get: code=%d stdout=%q", res.code, res.stdout)
	}

	codeFile := filepath.Join(t.TempDir(), "transform.js")
	_ = os.WriteFile(codeFile, []byte("export default function(payload) { return payload }"), 0o600)
	res = runCLI(t, base("logpush", "transformer", "create", "--name", "redact", "--code", "@"+codeFile)...)
	if res.code != 0 {
		t.Fatalf("transformer create: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || req.Path != acc+"/logpush/transformers" {
		t.Fatalf("transformer create request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	if got["name"] != "redact" || got["code"] != "export default function(payload) { return payload }" {
		t.Fatalf("transformer create body = %#v", got)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"create", "--code", "@" + codeFile}, "--name is required"},
		{[]string{"create", "--name", "x"}, "--code is required"},
		{[]string{"update", "5"}, "nothing to update"},
		{[]string{"get", "abc"}, "TRANSFORMER_ID must be a positive integer"},
	} {
		res := runCLI(t, base(append([]string{"logpush", "transformer"}, tc.args...)...)...)
		if res.code != errors.CodeInvalid || !strings.Contains(res.stderr, tc.want) {
			t.Fatalf("%v: code=%d stderr=%q (want %q)", tc.args, res.code, res.stderr, tc.want)
		}
	}

	res = runCLI(t, base("logpush", "transformer", "update", "5", "--description", "cleans payloads")...)
	if res.code != 0 {
		t.Fatalf("transformer update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PUT" || req.Path != acc+"/logpush/transformers/5" {
		t.Fatalf("transformer update request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); got["description"] != "cleans payloads" {
		t.Fatalf("transformer update body = %#v", got)
	}

	res = runCLI(t, base("logpush", "transformer", "content", "get", "5")...)
	if res.code != 0 {
		t.Fatalf("transformer content: code=%d stderr=%q", res.code, res.stderr)
	}
	if res.stdout != "export default function(payload) { return payload }\n" {
		t.Fatalf("transformer content stdout = %q", res.stdout)
	}

	res = runCLI(t, base("logpush", "transformer", "version", "list", "5")...)
	if res.code != 0 {
		t.Fatalf("transformer versions: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != acc+"/logpush/transformers/5/versions" || !strings.Contains(res.stdout, "\"version\"") {
		t.Fatalf("transformer versions request = %+v stdout=%s", api.last(), res.stdout)
	}

	tdel := base("logpush", "transformer", "delete", "5")
	if res := runCLI(t, tdel...); res.code != errors.CodeInvalid {
		t.Fatalf("transformer delete refusal: code=%d", res.code)
	}
	if res := runCLI(t, append(append([]string{}, tdel...), "--yes")...); res.code != 0 {
		t.Fatalf("transformer delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != acc+"/logpush/transformers/5" {
		t.Fatalf("transformer delete request = %+v", req)
	}
}

func TestHealthchecks(t *testing.T) {
	api := v10API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--zone", zoneID, "--endpoint-url", ep)
	}
	zns := "/zones/" + zoneID

	res := runCLI(t, base("healthcheck", "list")...)
	if res.code != 0 {
		t.Fatalf("list: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Path != zns+"/healthchecks" || !strings.Contains(req.Query, "page=1") {
		t.Fatalf("list request = %+v", req)
	}
	if !strings.Contains(res.stdout, "example.com") || !strings.Contains(res.stdout, "healthy") {
		t.Fatalf("list output = %s", res.stdout)
	}
	res = runCLI(t, base("healthcheck", "get", "hc1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "web") {
		t.Fatalf("get: code=%d stdout=%q", res.code, res.stdout)
	}

	res = runCLI(t, base("healthcheck", "create", "--name", "web", "--address", "example.com", "--type", "HTTPS",
		"--check-regions", "WEU,EEU", "--http-config", `{"path":"/health","header":{"Authorization":"S3CR3T-HC-HEADER"}}`,
		"--interval", "60")...)
	if res.code != 0 {
		t.Fatalf("create: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "POST" || req.Path != zns+"/healthchecks" {
		t.Fatalf("create request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	inner, ok := got["query_healthcheck"].(map[string]any)
	if !ok {
		t.Fatalf("create body = %#v", got)
	}
	if inner["name"] != "web" || inner["address"] != "example.com" || inner["type"] != "HTTPS" || inner["interval"] != float64(60) {
		t.Fatalf("wrapped body = %#v", inner)
	}
	if regions, ok := inner["check_regions"].([]any); !ok || len(regions) != 2 {
		t.Fatalf("check regions = %#v", inner["check_regions"])
	}
	if strings.Contains(res.stderr, "S3CR3T-HC-HEADER") {
		t.Fatalf("header credential leaked to stderr")
	}

	before := api.count()
	res = runCLI(t, base("healthcheck", "create", "--name", "web", "--address", "example.com", "--type", "HTTPS", "--dry-run")...)
	if res.code != 0 || !strings.Contains(res.stdout, "Would create health check web for example.com") || api.count() != before {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"create", "--address", "example.com", "--type", "HTTPS"}, "--name is required"},
		{[]string{"create", "--name", "web", "--type", "HTTPS"}, "--address is required"},
		{[]string{"create", "--name", "web", "--address", "example.com"}, "--type is required"},
		{[]string{"update", "hc1"}, "nothing to update"},
	} {
		res := runCLI(t, base(append([]string{"healthcheck"}, tc.args...)...)...)
		if res.code != errors.CodeInvalid || !strings.Contains(res.stderr, tc.want) {
			t.Fatalf("%v: code=%d stderr=%q (want %q)", tc.args, res.code, res.stderr, tc.want)
		}
	}

	res = runCLI(t, base("healthcheck", "update", "hc1", "--interval", "120")...)
	if res.code != 0 {
		t.Fatalf("update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PUT" || req.Path != zns+"/healthchecks/hc1" {
		t.Fatalf("update request = %+v", req)
	}
	got = decodeRequestBody(t, req.Body)
	inner, ok = got["query_healthcheck"].(map[string]any)
	if !ok {
		t.Fatalf("update body = %#v", got)
	}
	if inner["interval"] != float64(120) || inner["name"] != "web" || inner["address"] != "example.com" {
		t.Fatalf("update merge failed: %#v", inner)
	}

	del := base("healthcheck", "delete", "hc1")
	if res := runCLI(t, del...); res.code != errors.CodeInvalid {
		t.Fatalf("refusal: code=%d", res.code)
	}
	for _, r := range api.requests() {
		if r.Method == "DELETE" && r.Path == zns+"/healthchecks/hc1" {
			t.Fatalf("DELETE without confirmation")
		}
	}
	if res := runCLI(t, append(append([]string{}, del...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete health check web") {
		t.Fatalf("delete dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, del...), "--yes")...); res.code != 0 {
		t.Fatalf("delete: code=%d stderr=%q", res.code, res.stderr)
	}

	// previews
	res = runCLI(t, base("healthcheck", "preview", "create", "--name", "web", "--address", "example.com", "--type", "HTTPS")...)
	if res.code != 0 {
		t.Fatalf("preview create: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "POST" || req.Path != zns+"/healthchecks/preview" {
		t.Fatalf("preview create request = %+v", req)
	}
	if _, ok := decodeRequestBody(t, req.Body)["query_healthcheck"]; !ok {
		t.Fatalf("preview create is not wrapped: %s", req.Body)
	}
	res = runCLI(t, base("healthcheck", "preview", "get", "hcprev")...)
	if res.code != 0 {
		t.Fatalf("preview get: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != zns+"/healthchecks/preview/hcprev" {
		t.Fatalf("preview get path = %q", api.last().Path)
	}
	pdel := base("healthcheck", "preview", "delete", "hcprev")
	if res := runCLI(t, pdel...); res.code != errors.CodeInvalid {
		t.Fatalf("preview delete refusal: code=%d", res.code)
	}
	if res := runCLI(t, append(append([]string{}, pdel...), "--yes")...); res.code != 0 {
		t.Fatalf("preview delete: code=%d stderr=%q", res.code, res.stderr)
	}

	// header credentials are registered: an API error echoing them is redacted
	apiEcho := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(400, 6003, "invalid header S3CR3T-HC-HEADER")
		return s, b
	})
	res = runCLI(t, "healthcheck", "create", "--name", "web", "--address", "example.com", "--type", "HTTPS",
		"--http-config", `{"path":"/health","header":{"Authorization":"S3CR3T-HC-HEADER"}}`,
		"--zone", zoneID, "--endpoint-url", apiEcho.srv.URL)
	if res.code == 0 {
		t.Fatalf("echo stub should fail the command")
	}
	if strings.Contains(res.stderr, "S3CR3T-HC-HEADER") {
		t.Fatalf("header credential leaked into API error text: %q", res.stderr)
	}

	// zone scope is required
	res = runCLI(t, "healthcheck", "list", "--endpoint-url", ep)
	if res.code != errors.CodeInvalid {
		t.Fatalf("missing zone: code=%d, want 2 (stderr=%q)", res.code, res.stderr)
	}
}

func TestLoadBalancers(t *testing.T) {
	api := v10API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}
	acc := "/accounts/" + accountID
	zns := "/zones/" + zoneID

	res := runCLI(t, base("load-balancer", "list")...)
	if res.code != 0 {
		t.Fatalf("lb list: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != acc+"/load_balancers" || !strings.Contains(res.stdout, "www") || !strings.Contains(res.stdout, "dynamic") {
		t.Fatalf("lb list request = %+v stdout=%s", api.last(), res.stdout)
	}
	res = runCLI(t, base("load-balancer", "get", "lb1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "pool-c") {
		t.Fatalf("lb get: code=%d stdout=%q", res.code, res.stdout)
	}

	res = runCLI(t, base("load-balancer", "create", "--name", "www",
		"--default-pools", "pool-a,pool-b", "--fallback-pool", "pool-c", "--proxied",
		"--steering-policy", "dynamic")...)
	if res.code != 0 {
		t.Fatalf("lb create: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || req.Path != acc+"/load_balancers" {
		t.Fatalf("lb create request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	if got["name"] != "www" || got["fallback_pool"] != "pool-c" || got["proxied"] != true || got["steering_policy"] != "dynamic" {
		t.Fatalf("lb create body = %#v", got)
	}
	if pools, ok := got["default_pools"].([]any); !ok || len(pools) != 2 {
		t.Fatalf("default pools = %#v", got["default_pools"])
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"create", "--default-pools", "a", "--fallback-pool", "c"}, "--name is required"},
		{[]string{"create", "--name", "www", "--fallback-pool", "c"}, "--default-pools is required"},
		{[]string{"create", "--name", "www", "--default-pools", "a"}, "--fallback-pool is required"},
		{[]string{"update", "lb1"}, "nothing to update"},
	} {
		res := runCLI(t, base(append([]string{"load-balancer"}, tc.args...)...)...)
		if res.code != errors.CodeInvalid || !strings.Contains(res.stderr, tc.want) {
			t.Fatalf("%v: code=%d stderr=%q (want %q)", tc.args, res.code, res.stderr, tc.want)
		}
	}

	res = runCLI(t, base("load-balancer", "update", "lb1", "--ttl", "60")...)
	if res.code != 0 {
		t.Fatalf("lb update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PATCH" || req.Path != acc+"/load_balancers/lb1" {
		t.Fatalf("lb update request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, map[string]any{"ttl": float64(60)}) {
		t.Fatalf("lb update body = %#v", got)
	}

	res = runCLI(t, base("load-balancer", "list", "--zone", zoneID)...)
	if res.code != 0 {
		t.Fatalf("lb zone list: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != zns+"/load_balancers" {
		t.Fatalf("lb zone path = %q", api.last().Path)
	}

	lbDel := base("load-balancer", "delete", "lb1")
	if res := runCLI(t, lbDel...); res.code != errors.CodeInvalid {
		t.Fatalf("lb delete refusal: code=%d", res.code)
	}
	if res := runCLI(t, append(append([]string{}, lbDel...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete load balancer www") {
		t.Fatalf("lb delete dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, lbDel...), "--yes")...); res.code != 0 {
		t.Fatalf("lb delete: code=%d stderr=%q", res.code, res.stderr)
	}

	// pools
	res = runCLI(t, base("load-balancer", "pool", "list", "--monitor", "mon1")...)
	if res.code != 0 {
		t.Fatalf("pool list: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Path != acc+"/load_balancers/pools" || !strings.Contains(req.Query, "monitor=mon1") {
		t.Fatalf("pool list request = %+v", req)
	}
	if !strings.Contains(res.stdout, "primary") {
		t.Fatalf("pool list output = %s", res.stdout)
	}
	res = runCLI(t, base("load-balancer", "pool", "get", "pool-a")...)
	if res.code != 0 || !strings.Contains(res.stdout, "mon1") {
		t.Fatalf("pool get: code=%d stdout=%q", res.code, res.stdout)
	}

	res = runCLI(t, base("load-balancer", "pool", "create", "--name", "primary",
		"--origins", `[{"name":"o1","address":"192.0.2.1","header":{"X-Auth":"S3CR3T-ORIGIN-HEADER"}}]`,
		"--monitor", "mon1", "--minimum-origins", "1")...)
	if res.code != 0 {
		t.Fatalf("pool create: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "POST" || req.Path != acc+"/load_balancers/pools" {
		t.Fatalf("pool create request = %+v", req)
	}
	got = decodeRequestBody(t, req.Body)
	if got["name"] != "primary" || got["monitor"] != "mon1" || got["minimum_origins"] != float64(1) {
		t.Fatalf("pool create body = %#v", got)
	}
	if strings.Contains(res.stderr, "S3CR3T-ORIGIN-HEADER") {
		t.Fatalf("origin header credential leaked")
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"pool", "create", "--origins", "[]"}, "--name is required"},
		{[]string{"pool", "create", "--name", "x"}, "--origins is required"},
		{[]string{"pool", "create", "--name", "x", "--origins", "not-json"}, "must be a JSON array"},
		{[]string{"pool", "update", "pool-a"}, "nothing to update"},
	} {
		res := runCLI(t, base(append([]string{"load-balancer"}, tc.args...)...)...)
		if res.code != errors.CodeInvalid || !strings.Contains(res.stderr, tc.want) {
			t.Fatalf("%v: code=%d stderr=%q (want %q)", tc.args, res.code, res.stderr, tc.want)
		}
	}

	res = runCLI(t, base("load-balancer", "pool", "update", "pool-a", "--enabled=false")...)
	if res.code != 0 {
		t.Fatalf("pool update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PATCH" || req.Path != acc+"/load_balancers/pools/pool-a" {
		t.Fatalf("pool update request = %+v", req)
	}
	poolDel := base("load-balancer", "pool", "delete", "pool-a")
	if res := runCLI(t, poolDel...); res.code != errors.CodeInvalid {
		t.Fatalf("pool delete refusal: code=%d", res.code)
	}
	if res := runCLI(t, append(append([]string{}, poolDel...), "--yes")...); res.code != 0 {
		t.Fatalf("pool delete: code=%d stderr=%q", res.code, res.stderr)
	}

	res = runCLI(t, base("load-balancer", "pool", "health", "get", "pool-a")...)
	if res.code != 0 {
		t.Fatalf("pool health: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != acc+"/load_balancers/pools/pool-a/health" {
		t.Fatalf("pool health path = %q", api.last().Path)
	}
	if !strings.Contains(res.stdout, "pool-a") || !strings.Contains(res.stdout, "WEU") {
		t.Fatalf("pool health output = %s", res.stdout)
	}

	// monitors
	res = runCLI(t, base("load-balancer", "monitor", "list")...)
	if res.code != 0 || !strings.Contains(res.stdout, "https") {
		t.Fatalf("monitor list: code=%d stdout=%q", res.code, res.stdout)
	}
	if api.last().Path != acc+"/load_balancers/monitors" {
		t.Fatalf("monitor list path = %q", api.last().Path)
	}
	res = runCLI(t, base("load-balancer", "monitor", "get", "mon1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "/health") {
		t.Fatalf("monitor get: code=%d stdout=%q", res.code, res.stdout)
	}
	res = runCLI(t, base("load-balancer", "monitor", "create", "--type", "https", "--path", "/health",
		"--expected-codes", "2xx", "--interval", "60", "--header", `{"Authorization":"S3CR3T-MONITOR-HEADER"}`)...)
	if res.code != 0 {
		t.Fatalf("monitor create: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "POST" || req.Path != acc+"/load_balancers/monitors" {
		t.Fatalf("monitor create request = %+v", req)
	}
	got = decodeRequestBody(t, req.Body)
	if got["type"] != "https" || got["path"] != "/health" || got["expected_codes"] != "2xx" || got["interval"] != float64(60) {
		t.Fatalf("monitor create body = %#v", got)
	}
	if strings.Contains(res.stderr, "S3CR3T-MONITOR-HEADER") {
		t.Fatalf("monitor header credential leaked")
	}
	if res := runCLI(t, base("load-balancer", "monitor", "create", "--type", "gopher")...); res.code != errors.CodeInvalid || !strings.Contains(res.stderr, "invalid --type") {
		t.Fatalf("invalid monitor type: code=%d stderr=%q", res.code, res.stderr)
	}
	if res := runCLI(t, base("load-balancer", "monitor", "create")...); res.code != errors.CodeInvalid || !strings.Contains(res.stderr, "--type is required") {
		t.Fatalf("missing monitor type: code=%d stderr=%q", res.code, res.stderr)
	}

	res = runCLI(t, base("load-balancer", "monitor", "update", "mon1", "--interval", "120")...)
	if res.code != 0 {
		t.Fatalf("monitor update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PATCH" || req.Path != acc+"/load_balancers/monitors/mon1" {
		t.Fatalf("monitor update request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); got["interval"] != float64(120) {
		t.Fatalf("monitor update body = %#v", got)
	}
	monDel := base("load-balancer", "monitor", "delete", "mon1")
	if res := runCLI(t, monDel...); res.code != errors.CodeInvalid {
		t.Fatalf("monitor delete refusal: code=%d", res.code)
	}
	if res := runCLI(t, append(append([]string{}, monDel...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete monitor https monitor mon1") {
		t.Fatalf("monitor delete dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, monDel...), "--yes")...); res.code != 0 {
		t.Fatalf("monitor delete: code=%d stderr=%q", res.code, res.stderr)
	}

	// regions (untyped)
	res = runCLI(t, base("load-balancer", "region", "list")...)
	if res.code != 0 {
		t.Fatalf("region list: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != acc+"/load_balancers/regions" || !strings.Contains(res.stdout, "WEU") {
		t.Fatalf("region list request = %+v stdout=%s", api.last(), res.stdout)
	}
	res = runCLI(t, base("load-balancer", "region", "get", "WEU", "--json")...)
	if res.code != 0 || !strings.Contains(res.stdout, "Western Europe") {
		t.Fatalf("region get: code=%d stdout=%q", res.code, res.stdout)
	}

	// monitor header credentials are registered: an API error echoing them is redacted
	apiEcho := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(400, 6003, "invalid header S3CR3T-MONITOR-HEADER")
		return s, b
	})
	res = runCLI(t, "load-balancer", "monitor", "create", "--type", "https",
		"--header", `{"Authorization":"S3CR3T-MONITOR-HEADER"}`,
		"--account-id", accountID, "--endpoint-url", apiEcho.srv.URL)
	if res.code == 0 {
		t.Fatalf("echo stub should fail the command")
	}
	if strings.Contains(res.stderr, "S3CR3T-MONITOR-HEADER") {
		t.Fatalf("monitor header leaked into API error text: %q", res.stderr)
	}
}

// ---- v0.6 slice 2: notifications, audit logs, analytics, logs, registrar ---

func alertingPolicyJSON() map[string]any {
	return map[string]any{
		"id": "pol1", "name": "origin errors", "alert_type": "http_alert_origin_error",
		"enabled": true, "alert_interval": "30m", "description": "pages on origin errors",
		"mechanisms": map[string]any{"webhooks": []any{map[string]any{"id": "wh1"}}},
		"filters":    map[string]any{"zones": []any{"example.com"}},
		"created":    "2025-01-01T00:00:00Z", "modified": "2025-01-02T00:00:00Z",
	}
}

func alertingWebhookJSON() map[string]any {
	return map[string]any{
		"id": "wh1", "name": "pager", "type": "generic",
		"url":        "https://hooks.example.com/services/T000/B000?token=S3CR3T-WEBHOOK-TOKEN",
		"created_at": "2025-01-01T00:00:00Z", "last_success": "2025-01-02T00:00:00Z",
	}
}

func registrarDomainJSON() map[string]any {
	return map[string]any{
		"id": "example.com", "available": false, "can_register": false, "locked": true,
		"current_registrar": "Cloudflare, Inc.", "expires_at": "2026-05-01T00:00:00Z",
		"created_at": "2020-05-01T00:00:00Z", "updated_at": "2025-05-01T00:00:00Z",
		"supported_tld": true, "unmodeled_domain_field": "keep-me",
	}
}

func v11API(t *testing.T) *apiStub {
	acc := "/accounts/" + accountID
	zns := "/zones/" + zoneID
	alert := acc + "/alerting/v3"
	return newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		echoBody := func() (int, string) {
			var body map[string]any
			_ = json.Unmarshal([]byte(r.Body), &body)
			return 200, envelope(body)
		}
		switch {
		// policies
		case method == "GET" && path == alert+"/policies":
			return 200, envelope([]any{alertingPolicyJSON()})
		case method == "POST" && path == alert+"/policies":
			return 200, envelope(alertingPolicyJSON())
		case path == alert+"/policies/pol1" && method == "GET":
			return 200, envelope(alertingPolicyJSON())
		case path == alert+"/policies/pol1" && method == "PUT":
			return echoBody()
		case path == alert+"/policies/pol1" && method == "DELETE":
			return 200, envelope(map[string]any{})
		// webhooks
		case method == "GET" && path == alert+"/destinations/webhooks":
			return 200, envelope([]any{alertingWebhookJSON()})
		case method == "POST" && path == alert+"/destinations/webhooks":
			return 200, envelope(alertingWebhookJSON())
		case path == alert+"/destinations/webhooks/wh1" && method == "GET":
			return 200, envelope(alertingWebhookJSON())
		case path == alert+"/destinations/webhooks/wh1" && method == "PUT":
			return echoBody()
		case path == alert+"/destinations/webhooks/wh1" && method == "DELETE":
			return 200, envelope(map[string]any{})
		// pagerduty
		case method == "GET" && path == alert+"/destinations/pagerduty":
			return 200, envelope([]any{map[string]any{"id": "pd1", "name": "oncall"}})
		case method == "DELETE" && path == alert+"/destinations/pagerduty":
			return 200, envelope(map[string]any{})
		// silences
		case method == "GET" && path == alert+"/silences":
			return 200, envelope([]any{map[string]any{"id": "sil1", "policy_id": "pol1", "start_time": "2026-01-01T00:00:00Z", "end_time": "2026-01-02T00:00:00Z"}})
		case method == "POST" && path == alert+"/silences":
			return 200, envelope(map[string]any{"id": "silnew", "policy_id": "pol1", "start_time": "2026-01-01T00:00:00Z", "end_time": "2026-01-02T00:00:00Z"})
		case method == "PUT" && path == alert+"/silences":
			return echoBody()
		case path == alert+"/silences/sil1" && method == "GET":
			return 200, envelope(map[string]any{"id": "sil1", "policy_id": "pol1", "start_time": "2026-01-01T00:00:00Z", "end_time": "2026-01-02T00:00:00Z"})
		case path == alert+"/silences/sil1" && method == "DELETE":
			return 200, envelope(map[string]any{})
		// history and available alerts
		case method == "GET" && path == alert+"/history":
			return 200, envelopeWithInfo([]any{map[string]any{"id": "h1", "name": "origin errors", "alert_type": "http_alert_origin_error", "mechanism_type": "webhooks", "policy_id": "pol1", "sent": "2025-01-02T00:00:00Z"}}, map[string]any{"page": float64(1), "per_page": float64(100), "count": float64(1), "total_count": float64(1), "total_pages": float64(1)})
		case method == "GET" && path == alert+"/available_alerts":
			return 200, envelope(map[string]any{"http_alert_origin_error": []any{map[string]any{"display_name": "Origin Error Rate Alert", "description": "High origin error rate"}}})
		// audit logs
		case method == "GET" && path == acc+"/audit_logs":
			return 200, envelopeWithInfo([]any{map[string]any{
				"id": "log1", "when": "2025-01-02T00:00:00Z",
				"action":    map[string]any{"type": "dns_record_edit", "result": "success"},
				"actor":     map[string]any{"id": "u1", "email": "a@example.com", "ip": "192.0.2.1", "type": "user"},
				"resource":  map[string]any{"id": "rec1", "type": "dns_record"},
				"interface": "API", "metadata": map[string]any{"zone": "example.com"},
			}}, map[string]any{"page": float64(1), "per_page": float64(100), "count": float64(1), "total_count": float64(1), "total_pages": float64(1)})
		// analytics
		case method == "POST" && path == acc+"/analytics/query/httpRequestsOverviewAdaptiveGroups/summary":
			return 200, envelope(map[string]any{"currentTotal": float64(10), "previousTotal": float64(8)})
		case method == "POST" && path == acc+"/analytics/query/httpRequestsOverviewAdaptiveGroups/timeseries":
			return 200, envelope([]any{map[string]any{"sum": map[string]any{"requests": float64(1)}}})
		case method == "POST" && path == acc+"/analytics/query/httpRequestsOverviewAdaptiveGroups/top-n":
			return 200, envelope([]any{map[string]any{"count": float64(5), "dimensions": map[string]any{"clientCountryName": "US"}}})
		// logs explorer
		case method == "POST" && (path == acc+"/logs/explorer/query/sql" || path == zns+"/logs/explorer/query/sql"):
			return 200, envelope([]any{map[string]any{"count": float64(3), "status": float64(200)}})
		// registrar domains
		case method == "GET" && path == acc+"/registrar/domains":
			return 200, envelope([]any{registrarDomainJSON()})
		case path == acc+"/registrar/domains/example.com" && method == "GET":
			return 200, envelope(registrarDomainJSON())
		case path == acc+"/registrar/domains/example.com" && method == "PUT":
			return echoBody()
		// registrar registrations
		case method == "GET" && path == acc+"/registrar/registrations":
			if strings.Contains(r.Query, "cursor=next-page") {
				return 200, envelopeWithInfo([]any{map[string]any{"domain_name": "second.example", "status": "active", "auto_renew": true, "locked": true, "privacy_mode": "redaction"}}, map[string]any{"count": float64(1)})
			}
			return 200, envelopeWithInfo([]any{map[string]any{"domain_name": "example.com", "status": "active", "auto_renew": true, "locked": true, "privacy_mode": "redaction", "expires_at": "2026-05-01T00:00:00Z"}}, map[string]any{"count": float64(1), "cursors": map[string]any{"after": "next-page"}})
		case path == acc+"/registrar/registrations/example.com" && method == "GET":
			return 200, envelope(map[string]any{"domain_name": "example.com", "status": "active", "auto_renew": true, "locked": true, "privacy_mode": "redaction"})
		case path == acc+"/registrar/registrations/example.com" && method == "PATCH":
			return echoBody()
		}
		s, b := apiErr(404, 7000, "not found")
		return s, b
	})
}

func TestNotificationsPoliciesAndWebhooks(t *testing.T) {
	api := v11API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}
	alert := "/accounts/" + accountID + "/alerting/v3"

	res := runCLI(t, base("notifications", "policy", "list")...)
	if res.code != 0 {
		t.Fatalf("policy list: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != alert+"/policies" || !strings.Contains(res.stdout, "origin errors") {
		t.Fatalf("policy list request = %+v stdout=%s", api.last(), res.stdout)
	}
	res = runCLI(t, base("notifications", "policy", "get", "pol1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "http_alert_origin_error") {
		t.Fatalf("policy get: code=%d stdout=%q", res.code, res.stdout)
	}

	res = runCLI(t, base("notifications", "policy", "create", "--name", "origin errors",
		"--alert-type", "http_alert_origin_error", "--enabled",
		"--mechanisms", `{"webhooks":[{"id":"wh1"}]}`, "--alert-interval", "30m")...)
	if res.code != 0 {
		t.Fatalf("policy create: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || req.Path != alert+"/policies" {
		t.Fatalf("policy create request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	if got["name"] != "origin errors" || got["alert_type"] != "http_alert_origin_error" || got["enabled"] != true || got["alert_interval"] != "30m" {
		t.Fatalf("policy create body = %#v", got)
	}
	if _, ok := got["mechanisms"].(map[string]any)["webhooks"]; !ok {
		t.Fatalf("policy mechanisms not sent: %#v", got)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"create", "--alert-type", "x", "--enabled", "--mechanisms", "{}"}, "--name is required"},
		{[]string{"create", "--name", "x", "--enabled", "--mechanisms", "{}"}, "--alert-type is required"},
		{[]string{"create", "--name", "x", "--alert-type", "y", "--mechanisms", "{}"}, "--enabled"},
		{[]string{"create", "--name", "x", "--alert-type", "y", "--enabled"}, "--mechanisms is required"},
		{[]string{"update", "pol1"}, "nothing to update"},
	} {
		res := runCLI(t, base(append([]string{"notifications", "policy"}, tc.args...)...)...)
		if res.code != errors.CodeInvalid || !strings.Contains(res.stderr, tc.want) {
			t.Fatalf("%v: code=%d stderr=%q (want %q)", tc.args, res.code, res.stderr, tc.want)
		}
	}

	res = runCLI(t, base("notifications", "policy", "update", "pol1", "--enabled=false")...)
	if res.code != 0 {
		t.Fatalf("policy update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PUT" || req.Path != alert+"/policies/pol1" {
		t.Fatalf("policy update request = %+v", req)
	}
	got = decodeRequestBody(t, req.Body)
	if got["enabled"] != false || got["name"] != "origin errors" || got["alert_type"] != "http_alert_origin_error" {
		t.Fatalf("policy update did not merge: %#v", got)
	}
	pdel := base("notifications", "policy", "delete", "pol1")
	if res := runCLI(t, pdel...); res.code != errors.CodeInvalid {
		t.Fatalf("policy delete refusal: code=%d", res.code)
	}
	if res := runCLI(t, append(append([]string{}, pdel...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would delete notification policy origin errors") {
		t.Fatalf("policy delete dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, pdel...), "--yes")...); res.code != 0 {
		t.Fatalf("policy delete: code=%d stderr=%q", res.code, res.stderr)
	}

	// webhooks: URL and secret are credentials
	res = runCLI(t, base("notifications", "webhook", "list")...)
	if res.code != 0 || !strings.Contains(res.stdout, "pager") {
		t.Fatalf("webhook list: code=%d stdout=%q", res.code, res.stdout)
	}
	res = runCLI(t, base("notifications", "webhook", "get", "wh1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "wh1") {
		t.Fatalf("webhook get: code=%d stdout=%q", res.code, res.stdout)
	}
	secretFile := filepath.Join(t.TempDir(), "webhook-secret.txt")
	_ = os.WriteFile(secretFile, []byte("S3CR3T-WEBHOOK-SECRET"), 0o600)
	res = runCLI(t, base("notifications", "webhook", "create", "--name", "pager",
		"--url", "https://hooks.example.com/services/T000/B000?token=S3CR3T-WEBHOOK-TOKEN",
		"--secret", "@"+secretFile, "--debug")...)
	if res.code != 0 {
		t.Fatalf("webhook create: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "POST" || req.Path != alert+"/destinations/webhooks" {
		t.Fatalf("webhook create request = %+v", req)
	}
	got = decodeRequestBody(t, req.Body)
	if got["name"] != "pager" || got["secret"] != "S3CR3T-WEBHOOK-SECRET" {
		t.Fatalf("webhook create body = %#v", got)
	}
	if !strings.Contains(res.stderr, "debug:") {
		t.Fatalf("expected debug diagnostics active: %q", res.stderr)
	}
	for _, secret := range []string{"S3CR3T-WEBHOOK-SECRET", "S3CR3T-WEBHOOK-TOKEN"} {
		if strings.Contains(res.stderr, secret) {
			t.Fatalf("credential %q leaked into --debug output: %q", secret, res.stderr)
		}
	}
	if res := runCLI(t, base("notifications", "webhook", "create", "--name", "x", "--url", "https://x", "--secret", "S3CR3T-INLINE")...); res.code != errors.CodeInvalid || !strings.Contains(res.stderr, "@file form") {
		t.Fatalf("inline secret: code=%d stderr=%q", res.code, res.stderr)
	}
	if res := runCLI(t, base("notifications", "webhook", "create", "--url", "https://x")...); res.code != errors.CodeInvalid || !strings.Contains(res.stderr, "--name is required") {
		t.Fatalf("missing name: code=%d stderr=%q", res.code, res.stderr)
	}
	before := api.count()
	res = runCLI(t, base("notifications", "webhook", "create", "--name", "pager", "--url", "https://hooks.example.com/x?token=S3CR3T-WEBHOOK-TOKEN", "--dry-run")...)
	if res.code != 0 || !strings.Contains(res.stdout, "Would create webhook destination pager (url hidden)") || api.count() != before {
		t.Fatalf("webhook dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if strings.Contains(res.stdout, "S3CR3T-WEBHOOK-TOKEN") {
		t.Fatalf("dry-run leaked the webhook token: %q", res.stdout)
	}
	if res := runCLI(t, base("notifications", "webhook", "update", "wh1", "--name", "pager2")...); res.code != 0 {
		t.Fatalf("webhook update: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "PUT" || req.Path != alert+"/destinations/webhooks/wh1" {
		t.Fatalf("webhook update request = %+v", req)
	}
	wdel := base("notifications", "webhook", "delete", "wh1")
	if res := runCLI(t, wdel...); res.code != errors.CodeInvalid {
		t.Fatalf("webhook delete refusal: code=%d", res.code)
	}
	if res := runCLI(t, append(append([]string{}, wdel...), "--yes")...); res.code != 0 {
		t.Fatalf("webhook delete: code=%d stderr=%q", res.code, res.stderr)
	}

	// an API error echoing the request body must not leak URL or secret
	apiEcho := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(400, 6003, "invalid body "+r.Body)
		return s, b
	})
	res = runCLI(t, "notifications", "webhook", "create", "--name", "pager",
		"--url", "https://hooks.example.com/x?token=S3CR3T-WEBHOOK-TOKEN", "--secret", "@"+secretFile,
		"--account-id", accountID, "--endpoint-url", apiEcho.srv.URL)
	if res.code == 0 {
		t.Fatalf("echo stub should fail the command")
	}
	for _, secret := range []string{"S3CR3T-WEBHOOK-TOKEN", "S3CR3T-WEBHOOK-SECRET"} {
		if strings.Contains(res.stderr, secret) {
			t.Fatalf("credential %q leaked into API error text: %q", secret, res.stderr)
		}
	}
}

func TestNotificationsSilencesHistoryAndAuditLog(t *testing.T) {
	api := v11API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}
	alert := "/accounts/" + accountID + "/alerting/v3"

	res := runCLI(t, base("notifications", "silence", "list")...)
	if res.code != 0 || !strings.Contains(res.stdout, "pol1") {
		t.Fatalf("silence list: code=%d stdout=%q", res.code, res.stdout)
	}
	res = runCLI(t, base("notifications", "silence", "get", "sil1")...)
	if res.code != 0 || !strings.Contains(res.stdout, "2026-01-01") {
		t.Fatalf("silence get: code=%d stdout=%q", res.code, res.stdout)
	}
	res = runCLI(t, base("notifications", "silence", "create", "--policy-id", "pol1",
		"--start-time", "2026-01-01T00:00:00Z", "--end-time", "2026-01-02T00:00:00Z")...)
	if res.code != 0 {
		t.Fatalf("silence create: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || req.Path != alert+"/silences" {
		t.Fatalf("silence create request = %+v", req)
	}
	want := map[string]any{"policy_id": "pol1", "start_time": "2026-01-01T00:00:00Z", "end_time": "2026-01-02T00:00:00Z"}
	if got := decodeRequestBody(t, req.Body); !reflect.DeepEqual(got, want) {
		t.Fatalf("silence create body = %#v (want %#v)", got, want)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"create", "--start-time", "x", "--end-time", "y"}, "--policy-id is required"},
		{[]string{"create", "--policy-id", "p", "--end-time", "y"}, "--start-time is required"},
		{[]string{"create", "--policy-id", "p", "--start-time", "x"}, "--end-time is required"},
		{[]string{"update", "sil1"}, "nothing to update"},
	} {
		res := runCLI(t, base(append([]string{"notifications", "silence"}, tc.args...)...)...)
		if res.code != errors.CodeInvalid || !strings.Contains(res.stderr, tc.want) {
			t.Fatalf("%v: code=%d stderr=%q (want %q)", tc.args, res.code, res.stderr, tc.want)
		}
	}

	res = runCLI(t, base("notifications", "silence", "update", "sil1", "--end-time", "2026-01-03T00:00:00Z")...)
	if res.code != 0 {
		t.Fatalf("silence update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PUT" || req.Path != alert+"/silences" {
		t.Fatalf("silence update request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	if got["id"] != "sil1" || got["end_time"] != "2026-01-03T00:00:00Z" || got["start_time"] != "2026-01-01T00:00:00Z" {
		t.Fatalf("silence update body = %#v", got)
	}
	sdel := base("notifications", "silence", "delete", "sil1")
	if res := runCLI(t, sdel...); res.code != errors.CodeInvalid {
		t.Fatalf("silence delete refusal: code=%d", res.code)
	}
	if res := runCLI(t, append(append([]string{}, sdel...), "--yes")...); res.code != 0 {
		t.Fatalf("silence delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != alert+"/silences/sil1" {
		t.Fatalf("silence delete request = %+v", req)
	}

	res = runCLI(t, base("notifications", "pagerduty", "list")...)
	if res.code != 0 || !strings.Contains(res.stdout, "oncall") {
		t.Fatalf("pagerduty list: code=%d stdout=%q", res.code, res.stdout)
	}
	pdel := base("notifications", "pagerduty", "delete")
	if res := runCLI(t, pdel...); res.code != errors.CodeInvalid {
		t.Fatalf("pagerduty delete refusal: code=%d", res.code)
	}
	if res := runCLI(t, append(append([]string{}, pdel...), "--dry-run")...); res.code != 0 || !strings.Contains(res.stdout, "Would disconnect the PagerDuty integration") {
		t.Fatalf("pagerduty dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, append(append([]string{}, pdel...), "--yes")...); res.code != 0 {
		t.Fatalf("pagerduty delete: code=%d stderr=%q", res.code, res.stderr)
	}
	if req := api.last(); req.Method != "DELETE" || req.Path != alert+"/destinations/pagerduty" {
		t.Fatalf("pagerduty delete request = %+v", req)
	}

	res = runCLI(t, base("notifications", "history", "list", "--since", "2026-01-01T00:00:00Z", "--before", "2026-02-01T00:00:00Z")...)
	if res.code != 0 {
		t.Fatalf("history list: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Path != alert+"/history" || !strings.Contains(req.Query, "since=2026-01-01") || !strings.Contains(req.Query, "before=2026-02-01") || !strings.Contains(req.Query, "page=1") {
		t.Fatalf("history list request = %+v", req)
	}
	if !strings.Contains(res.stdout, "http_alert_origin_error") {
		t.Fatalf("history output = %s", res.stdout)
	}

	res = runCLI(t, base("notifications", "alert-type", "list")...)
	if res.code != 0 || !strings.Contains(res.stdout, "http_alert_origin_error") || !strings.Contains(res.stdout, "Origin Error Rate Alert") {
		t.Fatalf("alert-type list: code=%d stdout=%q", res.code, res.stdout)
	}
	if api.last().Path != alert+"/available_alerts" {
		t.Fatalf("alert-type path = %q", api.last().Path)
	}

	// audit logs
	res = runCLI(t, base("audit-log", "list", "--since", "2026-01-01T00:00:00Z",
		"--action", "dns_record_edit", "--actor", "a@example.com", "--zone", "example.com",
		"--direction", "desc", "--hide-user-logs")...)
	if res.code != 0 {
		t.Fatalf("audit-log list: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Path != "/accounts/"+accountID+"/audit_logs" {
		t.Fatalf("audit-log path = %q", req.Path)
	}
	for _, want := range []string{"since=2026-01-01", "action=dns_record_edit", "actor=a%40example.com", "zone=example.com", "direction=desc", "hide_user_logs=true", "page=1"} {
		if !strings.Contains(req.Query, want) {
			t.Fatalf("audit-log query %q missing %q", req.Query, want)
		}
	}
	if !strings.Contains(res.stdout, "dns_record_edit") || !strings.Contains(res.stdout, "a@example.com") {
		t.Fatalf("audit-log output = %s", res.stdout)
	}
	if res := runCLI(t, base("audit-log", "list", "--direction", "sideways")...); res.code != errors.CodeInvalid {
		t.Fatalf("invalid direction: code=%d", res.code)
	}

	api404 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(404, 7000, "not found")
		return s, b
	})
	if res := runCLI(t, "audit-log", "list", "--account-id", accountID, "--endpoint-url", api404.srv.URL); res.code != errors.CodeNotFound {
		t.Fatalf("404: code=%d, want 5", res.code)
	}
	api403 := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(403, 9109, "forbidden")
		return s, b
	})
	if res := runCLI(t, "notifications", "policy", "list", "--account-id", accountID, "--endpoint-url", api403.srv.URL); res.code != errors.CodePermission {
		t.Fatalf("403: code=%d, want 4", res.code)
	}
}

func TestAnalyticsAndLogsQuery(t *testing.T) {
	api := v11API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}
	acc := "/accounts/" + accountID

	queryFile := filepath.Join(t.TempDir(), "query.json")
	query := `{"filters":[{"name":"date","op":"gte","value":"2026-01-01"}],"from":"2026-01-01T00:00:00Z","to":"2026-01-02T00:00:00Z","groupBy":[{"name":"date"}],"stats":[{"name":"requests","op":"sum"}]}`
	_ = os.WriteFile(queryFile, []byte(query), 0o600)

	res := runCLI(t, base("analytics", "summary", "get", "httpRequestsOverviewAdaptiveGroups", "--query", "@"+queryFile)...)
	if res.code != 0 {
		t.Fatalf("summary: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "POST" || req.Path != acc+"/analytics/query/httpRequestsOverviewAdaptiveGroups/summary" {
		t.Fatalf("summary request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	if len(got) != 5 || got["from"] != "2026-01-01T00:00:00Z" {
		t.Fatalf("summary body = %#v", got)
	}
	if stats, ok := got["stats"].([]any); !ok || len(stats) != 1 {
		t.Fatalf("summary stats = %#v", got["stats"])
	}
	if !strings.Contains(res.stdout, "10") {
		t.Fatalf("summary output = %s", res.stdout)
	}

	res = runCLI(t, base("analytics", "timeseries", "get", "httpRequestsOverviewAdaptiveGroups", "--query", "@"+queryFile, "--resolution", "1h")...)
	if res.code != 0 {
		t.Fatalf("timeseries: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Path != acc+"/analytics/query/httpRequestsOverviewAdaptiveGroups/timeseries" {
		t.Fatalf("timeseries path = %q", req.Path)
	}
	if got := decodeRequestBody(t, req.Body); got["resolution"] != "1h" {
		t.Fatalf("timeseries body = %#v", got)
	}

	res = runCLI(t, base("analytics", "top-n", "get", "httpRequestsOverviewAdaptiveGroups", "--query", "@"+queryFile)...)
	if res.code != 0 {
		t.Fatalf("top-n: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != acc+"/analytics/query/httpRequestsOverviewAdaptiveGroups/top-n" || !strings.Contains(res.stdout, "clientCountryName") {
		t.Fatalf("top-n request = %+v stdout=%s", api.last(), res.stdout)
	}
	if res := runCLI(t, base("analytics", "summary", "get", "dataset")...); res.code != errors.CodeInvalid || !strings.Contains(res.stderr, "--query is required") {
		t.Fatalf("missing query: code=%d stderr=%q", res.code, res.stderr)
	}
	if res := runCLI(t, base("analytics", "summary", "get", "dataset", "--query", "[]")...); res.code != errors.CodeInvalid || !strings.Contains(res.stderr, "must be a JSON object") {
		t.Fatalf("non-object query: code=%d stderr=%q", res.code, res.stderr)
	}
	for _, args := range [][]string{
		{"analytics", "summary", "get", "d", "--query", "@" + queryFile, "--dry-run"},
	} {
		if res := runCLI(t, base(args...)...); res.code != 0 || !strings.Contains(res.stdout, "Would run a summary analytics query on dataset d") {
			t.Fatalf("analytics dry-run: code=%d stdout=%q", res.code, res.stdout)
		}
	}

	// logs explorer SQL: raw text body, account and zone scope
	res = runCLI(t, base("logs", "query", "--sql", "SELECT count(*) FROM http_requests")...)
	if res.code != 0 {
		t.Fatalf("logs query: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "POST" || req.Path != acc+"/logs/explorer/query/sql" {
		t.Fatalf("logs query request = %+v", req)
	}
	if req.Body != "SELECT count(*) FROM http_requests" {
		t.Fatalf("logs query body = %q", req.Body)
	}
	if !strings.Contains(req.ContentType, "text/plain") {
		t.Fatalf("logs content type = %q", req.ContentType)
	}
	if !strings.Contains(res.stdout, "status") {
		t.Fatalf("logs output = %s", res.stdout)
	}
	res = runCLI(t, base("logs", "query", "--sql", "SELECT 1", "--zone", zoneID)...)
	if res.code != 0 {
		t.Fatalf("logs zone query: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != "/zones/"+zoneID+"/logs/explorer/query/sql" {
		t.Fatalf("logs zone path = %q", api.last().Path)
	}
	if res := runCLI(t, base("logs", "query")...); res.code != errors.CodeInvalid || !strings.Contains(res.stderr, "--sql is required") {
		t.Fatalf("missing sql: code=%d stderr=%q", res.code, res.stderr)
	}
	sqlFile := filepath.Join(t.TempDir(), "query.sql")
	_ = os.WriteFile(sqlFile, []byte("SELECT 2"), 0o600)
	res = runCLI(t, base("logs", "query", "--sql", "@"+sqlFile)...)
	if res.code != 0 || api.last().Body != "SELECT 2" {
		t.Fatalf("logs @file sql: code=%d body=%q", res.code, api.last().Body)
	}
}

func TestRegistrar(t *testing.T) {
	api := v11API(t)
	setToken(t, "tok")
	newHome(t)
	ep := api.srv.URL
	base := func(args ...string) []string {
		return append(args, "--account-id", accountID, "--endpoint-url", ep)
	}
	acc := "/accounts/" + accountID

	res := runCLI(t, base("registrar", "domain", "list")...)
	if res.code != 0 {
		t.Fatalf("domain list: code=%d stderr=%q", res.code, res.stderr)
	}
	if api.last().Path != acc+"/registrar/domains" || !strings.Contains(res.stdout, "example.com") {
		t.Fatalf("domain list request = %+v stdout=%s", api.last(), res.stdout)
	}
	res = runCLI(t, base("registrar", "domain", "get", "example.com")...)
	if res.code != 0 || !strings.Contains(res.stdout, "Cloudflare, Inc.") {
		t.Fatalf("domain get: code=%d stdout=%q", res.code, res.stdout)
	}
	if api.last().Path != acc+"/registrar/domains/example.com" {
		t.Fatalf("domain get path = %q", api.last().Path)
	}

	res = runCLI(t, base("registrar", "domain", "update", "example.com", "--locked=false")...)
	if res.code != 0 {
		t.Fatalf("domain update: code=%d stderr=%q", res.code, res.stderr)
	}
	req := api.last()
	if req.Method != "PUT" || req.Path != acc+"/registrar/domains/example.com" {
		t.Fatalf("domain update request = %+v", req)
	}
	got := decodeRequestBody(t, req.Body)
	if got["locked"] != false || got["unmodeled_domain_field"] != "keep-me" {
		t.Fatalf("domain update did not merge: %#v", got)
	}
	if res := runCLI(t, base("registrar", "domain", "update", "example.com")...); res.code != errors.CodeInvalid || !strings.Contains(res.stderr, "nothing to update") {
		t.Fatalf("empty domain update: code=%d stderr=%q", res.code, res.stderr)
	}

	// registrations follow the cursor
	res = runCLI(t, base("registrar", "registration", "list", "--direction", "asc", "--sort-by", "domain_name")...)
	if res.code != 0 {
		t.Fatalf("registration list: code=%d stderr=%q", res.code, res.stderr)
	}
	var reqs []recordedRequest
	for _, r := range api.requests() {
		if r.Path == acc+"/registrar/registrations" {
			reqs = append(reqs, r)
		}
	}
	if len(reqs) != 2 {
		t.Fatalf("expected 2 cursor pages, got %d", len(reqs))
	}
	if !strings.Contains(reqs[0].Query, "per_page=") || !strings.Contains(reqs[0].Query, "direction=asc") || !strings.Contains(reqs[0].Query, "sort_by=domain_name") {
		t.Fatalf("registration query = %q", reqs[0].Query)
	}
	if !strings.Contains(reqs[1].Query, "cursor=next-page") {
		t.Fatalf("second page cursor = %q", reqs[1].Query)
	}
	if !strings.Contains(res.stdout, "example.com") || !strings.Contains(res.stdout, "second.example") {
		t.Fatalf("registration list output = %s", res.stdout)
	}
	if res := runCLI(t, base("registrar", "registration", "list", "--direction", "sideways")...); res.code != errors.CodeInvalid {
		t.Fatalf("invalid direction: code=%d", res.code)
	}

	res = runCLI(t, base("registrar", "registration", "get", "example.com")...)
	if res.code != 0 || !strings.Contains(res.stdout, "active") {
		t.Fatalf("registration get: code=%d stdout=%q", res.code, res.stdout)
	}
	res = runCLI(t, base("registrar", "registration", "update", "example.com", "--auto-renew=false")...)
	if res.code != 0 {
		t.Fatalf("registration update: code=%d stderr=%q", res.code, res.stderr)
	}
	req = api.last()
	if req.Method != "PATCH" || req.Path != acc+"/registrar/registrations/example.com" {
		t.Fatalf("registration update request = %+v", req)
	}
	if got := decodeRequestBody(t, req.Body); got["auto_renew"] != false {
		t.Fatalf("registration update body = %#v", got)
	}
	if res := runCLI(t, base("registrar", "registration", "update", "example.com")...); res.code != errors.CodeInvalid || !strings.Contains(res.stderr, "nothing to update") {
		t.Fatalf("empty registration update: code=%d stderr=%q", res.code, res.stderr)
	}
}

// ---- v1.0 readiness: conformance regressions ------------------------------

// TestDryRunPreviewsNeverMutate covers the commands whose --dry-run handling was
// added during the v1.0 conformance audit: the preview must be complete and no
// request may reach the API.
func TestDryRunPreviewsNeverMutate(t *testing.T) {
	api := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(500, 1000, "the API must not be called during --dry-run")
		return s, b
	})
	setToken(t, "tok")
	newHome(t)
	sqlFile := filepath.Join(t.TempDir(), "seed.sql")
	_ = os.WriteFile(sqlFile, []byte("CREATE TABLE t(id INT);"), 0o600)
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"d1", "database", "update", "db1", "--read-replication-mode", "auto"}, "Would set the read replication mode of D1 database db1 to auto"},
		{[]string{"d1", "database", "import", "db1", "--file", "@" + sqlFile}, "Would import @" + sqlFile + " into D1 database db1"},
		{[]string{"hyperdrive", "config", "update", "h1", "--name", "renamed"}, "Would update Hyperdrive configuration h1"},
		{[]string{"queue", "update", "q1", "--delivery-delay", "5"}, "Would update queue q1"},
		{[]string{"queue", "consumer", "update", "q1", "c1", "--dead-letter-queue", "dlq"}, "Would update consumer c1 of queue q1"},
		{[]string{"vectorize", "index", "metadata", "create", "idx", "--property", "lang", "--type", "string"}, "Would create metadata index lang on Vectorize index idx"},
	}
	for _, tc := range cases {
		before := api.count()
		res := runCLI(t, append(append([]string{}, tc.args...), "--dry-run", "--account-id", accountID, "--endpoint-url", api.srv.URL)...)
		if res.code != errors.CodeSuccess {
			t.Fatalf("%v: code=%d stderr=%q", tc.args, res.code, res.stderr)
		}
		if !strings.Contains(res.stdout, tc.want) {
			t.Fatalf("%v: stdout=%q (want %q)", tc.args, res.stdout, tc.want)
		}
		if api.count() != before {
			t.Fatalf("%v issued a request during --dry-run", tc.args)
		}
	}
}

// TestExitCodeSuccessAndNetwork pins the two exit codes that had no direct
// test coverage: success (0) and network/timeout failure (8).
func TestExitCodeSuccessAndNetwork(t *testing.T) {
	api := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		if method == "GET" && path == "/zones" {
			return 200, envelopeWithInfo([]any{map[string]any{"id": zoneID, "name": "example.com", "status": "active"}}, map[string]any{"page": float64(1), "per_page": float64(100), "count": float64(1), "total_count": float64(1), "total_pages": float64(1)})
		}
		s, b := apiErr(404, 7000, "not found")
		return s, b
	})
	setToken(t, "tok")
	newHome(t)

	res := runCLI(t, "zone", "list", "--endpoint-url", api.srv.URL)
	if res.code != errors.CodeSuccess {
		t.Fatalf("success: code=%d stderr=%q", res.code, res.stderr)
	}

	// a closed port is a network failure
	closed := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		return 200, envelope(nil)
	})
	url := closed.srv.URL
	closed.srv.Close()
	res = runCLI(t, "zone", "list", "--endpoint-url", url)
	if res.code != errors.CodeNetwork {
		t.Fatalf("network: code=%d, want %d (stderr=%q)", res.code, errors.CodeNetwork, res.stderr)
	}

	// a request that outlives --timeout is also a network failure
	slow := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		time.Sleep(300 * time.Millisecond)
		return 200, envelope(nil)
	})
	res = runCLI(t, "zone", "list", "--timeout", "50ms", "--endpoint-url", slow.srv.URL)
	if res.code != errors.CodeNetwork {
		t.Fatalf("timeout: code=%d, want %d (stderr=%q)", res.code, errors.CodeNetwork, res.stderr)
	}
}

// ---- OAuth phases 1-2: store, resolution chain, login/logout (docs/oauth.md §11) ----

// lockedBuffer is a concurrency-safe writer for commands that run in a
// goroutine while the test drives the fake browser.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// oauthStub is an offline OAuth provider: an authorize page that redirects to
// the loopback callback plus token and revocation endpoints. No live network is
// involved.
type oauthStub struct {
	server               *httptest.Server
	mu                   sync.Mutex
	forms                []url.Values
	deny                 bool
	rejectRev            bool
	rejectRefresh        bool
	authorizeError       string
	authorizeDescription string
	tokenError           string
	tokenDescription     string
	echoCodeInError      bool
}

func newOAuthStub(t *testing.T) *oauthStub {
	t.Helper()
	s := &oauthStub{}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/auth", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		redirect, err := url.Parse(q.Get("redirect_uri"))
		if err != nil || redirect.Scheme == "" {
			http.Error(w, "bad redirect_uri", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		authErr, authErrDesc := s.authorizeError, s.authorizeDescription
		deny := s.deny
		s.mu.Unlock()
		next := redirect.Query()
		switch {
		case authErr != "":
			next.Set("error", authErr)
			if authErrDesc != "" {
				next.Set("error_description", authErrDesc)
			}
		case deny:
			next.Set("error", "access_denied")
		default:
			next.Set("code", "cli-auth-code")
		}
		next.Set("state", q.Get("state"))
		redirect.RawQuery = next.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	})
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		s.mu.Lock()
		s.forms = append(s.forms, r.PostForm)
		reject := s.rejectRefresh && r.PostForm.Get("grant_type") == "refresh_token"
		tokErr, tokErrDesc, echoCode := s.tokenError, s.tokenDescription, s.echoCodeInError
		s.mu.Unlock()
		if echoCode {
			tokErrDesc += " (code " + r.PostForm.Get("code") + ")"
		}
		if tokErr != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			payload := map[string]string{"error": tokErr}
			if tokErrDesc != "" {
				payload["error_description"] = tokErrDesc
			}
			_ = json.NewEncoder(w).Encode(payload)
			return
		}
		if reject {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"refresh token is not valid"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "cli-access-token",
			"refresh_token": "cli-refresh-token",
			"expires_in":    3600,
			"scope":         "openid offline_access account:read",
			"token_type":    "Bearer",
		})
	})
	mux.HandleFunc("/oauth2/revoke", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		s.mu.Lock()
		s.forms = append(s.forms, r.PostForm)
		reject := s.rejectRev
		s.mu.Unlock()
		if reject {
			http.Error(w, "invalid_token", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	s.server = httptest.NewServer(mux)
	t.Cleanup(s.server.Close)
	return s
}

func (s *oauthStub) apply(t *testing.T) {
	t.Helper()
	t.Setenv("FLAREADM_OAUTH_AUTH_URL", s.server.URL+"/oauth2/auth")
	t.Setenv("FLAREADM_OAUTH_TOKEN_URL", s.server.URL+"/oauth2/token")
	t.Setenv("FLAREADM_OAUTH_REVOKE_URL", s.server.URL+"/oauth2/revoke")
}

func (s *oauthStub) lastForm(t *testing.T) url.Values {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.forms) == 0 {
		t.Fatal("no oauth request recorded")
	}
	return s.forms[len(s.forms)-1]
}

// freePort returns a currently free loopback port.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

// writeStoredCredential seeds the OAuth store for a profile.
func writeStoredCredential(t *testing.T, profile string, cred map[string]any) string {
	t.Helper()
	dir := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "flareadm", "oauth")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, profile+".json")
	data, err := json.Marshal(cred)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func storedCredentialMap(expiry time.Time) map[string]any {
	return map[string]any{
		"version":       1,
		"client_id":     "cli-client",
		"access_token":  "stored-access-token",
		"refresh_token": "stored-refresh-token",
		"token_type":    "Bearer",
		"expires_at":    expiry.UTC().Format(time.RFC3339),
		"scopes":        []string{"openid", "account:read"},
	}
}

// TestOAuthResolutionPrecedence covers the four chain combinations
// (docs/oauth.md §8): env only, store only, both, neither.
func TestOAuthResolutionPrecedence(t *testing.T) {
	setToken(t, "env-token")
	newHome(t)

	// env only
	res := runCLI(t, "auth", "status")
	if res.code != 0 || !strings.Contains(res.stdout, "FLAREADM_API_TOKEN") {
		t.Fatalf("env only: code=%d stdout=%q", res.code, res.stdout)
	}
	if !strings.Contains(res.stdout, "api token (environment)") {
		t.Fatalf("env only kind missing: %s", res.stdout)
	}

	// both: the environment wins and the store is not consulted
	writeStoredCredential(t, "default", storedCredentialMap(time.Now().Add(time.Hour)))
	res = runCLI(t, "auth", "status")
	if res.code != 0 || !strings.Contains(res.stdout, "FLAREADM_API_TOKEN") {
		t.Fatalf("both: code=%d stdout=%q", res.code, res.stdout)
	}
	if strings.Contains(res.stdout, "oauth:") {
		t.Fatalf("environment must win over the store: %s", res.stdout)
	}

	// store only
	t.Setenv("FLAREADM_API_TOKEN", "")
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	t.Setenv("CF_API_TOKEN", "")
	res = runCLI(t, "auth", "status")
	if res.code != 0 {
		t.Fatalf("store only: code=%d stderr=%q", res.code, res.stderr)
	}
	for _, want := range []string{"oauth:default", "cli-client", "REFRESH TOKEN", "account:read", "STORE"} {
		if !strings.Contains(res.stdout, want) {
			t.Fatalf("store only output missing %q: %s", want, res.stdout)
		}
	}
	if strings.Contains(res.stdout, "stored-access-token") || strings.Contains(res.stdout, "stored-refresh-token") {
		t.Fatalf("status must never print token material: %s", res.stdout)
	}
	// --json is the normalized envelope
	res = runCLI(t, "auth", "status", "--json")
	if res.code != 0 || !strings.Contains(res.stdout, `"SOURCE": "oauth:default"`) {
		t.Fatalf("status --json: code=%d stdout=%q", res.code, res.stdout)
	}

	// neither: unchanged message and exit 3
	if err := os.Remove(filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "flareadm", "oauth", "default.json")); err != nil {
		t.Fatal(err)
	}
	res = runCLI(t, "auth", "status")
	if res.code != errors.CodeAuth {
		t.Fatalf("neither: code=%d, want 3", res.code)
	}
	if !strings.Contains(res.stderr, "no credential found") {
		t.Fatalf("neither: stderr=%q", res.stderr)
	}
	res = runCLI(t, "zone", "list", "--endpoint-url", "http://127.0.0.1:1/")
	if res.code != errors.CodeAuth || !strings.Contains(res.stderr, "no API token found; set FLAREADM_API_TOKEN") {
		t.Fatalf("unchanged missing-credential error: code=%d stderr=%q", res.code, res.stderr)
	}
}

// TestOAuthStoreBackedAPICall proves the store is used as the client bearer
// credential without any environment token.
func TestOAuthStoreBackedAPICall(t *testing.T) {
	api := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		if method == "GET" && path == "/zones" {
			if r.Auth != "Bearer stored-access-token" {
				t.Errorf("authorization = %q, want the stored OAuth access token", r.Auth)
			}
			return 200, envelopeWithInfo([]any{map[string]any{"id": zoneID, "name": "example.com", "status": "active"}},
				map[string]any{"page": float64(1), "per_page": float64(100), "count": float64(1), "total_count": float64(1), "total_pages": float64(1)})
		}
		s, b := apiErr(404, 7000, "not found")
		return s, b
	})
	newHome(t)
	t.Setenv("FLAREADM_API_TOKEN", "")
	writeStoredCredential(t, "default", storedCredentialMap(time.Now().Add(time.Hour)))
	res := runCLI(t, "zone", "list", "--endpoint-url", api.srv.URL)
	if res.code != 0 {
		t.Fatalf("store-backed call: code=%d stderr=%q", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "example.com") {
		t.Fatalf("store-backed output = %s", res.stdout)
	}
}

func TestOAuthLoginNonInteractiveExitsTwoWithoutListener(t *testing.T) {
	stub := newOAuthStub(t)
	stub.apply(t)
	newHome(t)
	t.Setenv("FLAREADM_API_TOKEN", "")

	res := runCLI(t, "auth", "login", "--client-id", "cli-client")
	if res.code != errors.CodeInvalid {
		t.Fatalf("non-interactive login: code=%d, want 2 (stderr=%q)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "FLAREADM_API_TOKEN") || !strings.Contains(res.stderr, "--no-browser") {
		t.Fatalf("message should name the headless alternatives: %q", res.stderr)
	}
	// No listener, no token request, no credential written.
	if _, err := os.Stat(filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "flareadm", "oauth")); !os.IsNotExist(err) {
		t.Fatalf("login must not create the store: %v", err)
	}
	stub.mu.Lock()
	requests := len(stub.forms)
	stub.mu.Unlock()
	if requests != 0 {
		t.Fatalf("login must not call the token endpoint, got %d requests", requests)
	}
}

func TestOAuthLoginNoBrowserTimeoutExitsEight(t *testing.T) {
	stub := newOAuthStub(t)
	stub.apply(t)
	newHome(t)
	t.Setenv("FLAREADM_API_TOKEN", "")

	port := freePort(t)
	res := runCLI(t, "auth", "login", "--client-id", "cli-client", "--no-browser",
		"--callback-port", strconv.Itoa(port), "--timeout", "300ms")
	if res.code != errors.CodeNetwork {
		t.Fatalf("timeout: code=%d, want 8 (stdout=%q stderr=%q)", res.code, res.stdout, res.stderr)
	}
	if n := countURLLines(res.stdout); n != 1 {
		t.Fatalf("the authorize URL must be printed once, got %d URL lines: %q", n, res.stdout)
	}
	if !strings.Contains(res.stderr, "timed out") {
		t.Fatalf("timeout message missing: %q", res.stderr)
	}
}

func TestOAuthLoginFullFlowThroughCLI(t *testing.T) {
	stub := newOAuthStub(t)
	stub.apply(t)
	newHome(t)
	t.Setenv("FLAREADM_API_TOKEN", "")

	port := freePort(t)
	out, errOut := &lockedBuffer{}, &lockedBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- Run(context.Background(),
			[]string{"auth", "login", "--client-id", "cli-client", "--no-browser",
				"--callback-port", strconv.Itoa(port), "--timeout", "10s", "--debug"},
			strings.NewReader(""), out, errOut)
	}()

	authorize := waitForLine(t, out)
	resp, err := http.Get(authorize) //nolint:gosec // loopback test URL
	if err != nil {
		t.Fatalf("browser: %v", err)
	}
	_ = resp.Body.Close()
	if code := <-done; code != 0 {
		t.Fatalf("login: code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}

	// The authorize URL carried PKCE S256 and the offline scopes.
	parsed, err := url.Parse(authorize)
	if err != nil {
		t.Fatal(err)
	}
	q := parsed.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("state") == "" {
		t.Fatalf("authorize query = %v", q)
	}
	if !strings.Contains(q.Get("scope"), "offline_access") {
		t.Fatalf("scope = %q", q.Get("scope"))
	}

	// The token request is a public-client code exchange.
	form := stub.lastForm(t)
	if form.Get("grant_type") != "authorization_code" || form.Get("code") != "cli-auth-code" ||
		form.Get("code_verifier") == "" || form.Get("client_secret") != "" {
		t.Fatalf("token request = %v", form)
	}

	// The credential (including the refresh token) is stored.
	path := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "flareadm", "oauth", "default.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("credential not stored: %v", err)
	}
	var stored map[string]any
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	if stored["refresh_token"] != "cli-refresh-token" || stored["access_token"] != "cli-access-token" {
		t.Fatalf("stored credential = %#v", stored)
	}
	if stored["version"] != float64(1) {
		t.Fatalf("credential version = %v", stored["version"])
	}

	// Redaction: no credential material on stdout/stderr, even with --debug.
	combined := out.String() + errOut.String()
	for _, secret := range []string{"cli-access-token", "cli-refresh-token", "cli-auth-code"} {
		if strings.Contains(combined, secret) {
			t.Fatalf("secret %q leaked into CLI output:\n%s", secret, combined)
		}
	}
	// Tokens are owner-only (POSIX modes are not meaningful on Windows).
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("credential mode = %o, want 600", perm)
		}
	}

	// auth status now reports the stored credential.
	res := runCLI(t, "auth", "status")
	if res.code != 0 || !strings.Contains(res.stdout, "oauth:default") {
		t.Fatalf("status after login: code=%d stdout=%q", res.code, res.stdout)
	}
}

// countURLLines counts printed lines that are themselves URLs.
func countURLLines(output string) int {
	n := 0
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "http") {
			n++
		}
	}
	return n
}

// waitForLine polls a buffer until a line starting with http appears.
func waitForLine(t *testing.T, b *lockedBuffer) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(b.String(), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "http") {
				return strings.TrimSpace(line)
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no URL line appeared; output so far: %q", b.String())
	return ""
}

func TestOAuthLoginDeniedAndStateMismatch(t *testing.T) {
	stub := newOAuthStub(t)
	stub.apply(t)
	newHome(t)
	t.Setenv("FLAREADM_API_TOKEN", "")

	// A denied consent exits 3 and stores nothing.
	stub.mu.Lock()
	stub.deny = true
	stub.mu.Unlock()
	port := freePort(t)
	out, errOut := &lockedBuffer{}, &lockedBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- Run(context.Background(),
			[]string{"auth", "login", "--client-id", "cli-client", "--no-browser",
				"--callback-port", strconv.Itoa(port), "--timeout", "10s"},
			strings.NewReader(""), out, errOut)
	}()
	authorize := waitForLine(t, out)
	resp, err := http.Get(authorize) //nolint:gosec // loopback test URL
	if err != nil {
		t.Fatalf("browser: %v", err)
	}
	_ = resp.Body.Close()
	if code := <-done; code != errors.CodeAuth {
		t.Fatalf("denied consent: code=%d, want 3 (stderr=%q)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "access_denied") {
		t.Fatalf("denial not reported: %q", errOut.String())
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "flareadm", "oauth", "default.json")); !os.IsNotExist(err) {
		t.Fatalf("a denied login must not store a credential: %v", err)
	}

	// A callback with the wrong state is rejected.
	stub.mu.Lock()
	stub.deny = false
	stub.mu.Unlock()
	port = freePort(t)
	out, errOut = &lockedBuffer{}, &lockedBuffer{}
	done = make(chan int, 1)
	go func() {
		done <- Run(context.Background(),
			[]string{"auth", "login", "--client-id", "cli-client", "--no-browser",
				"--callback-port", strconv.Itoa(port), "--timeout", "10s"},
			strings.NewReader(""), out, errOut)
	}()
	authorize = waitForLine(t, out)
	parsed, err := url.Parse(authorize)
	if err != nil {
		t.Fatal(err)
	}
	callback := parsed.Query().Get("redirect_uri")
	resp, err = http.Get(callback + "?code=stolen&state=wrong") //nolint:gosec // loopback test URL
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	_ = resp.Body.Close()
	if code := <-done; code != errors.CodeAuth {
		t.Fatalf("state mismatch: code=%d, want 3 (stderr=%q)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "state mismatch") {
		t.Fatalf("state mismatch not reported: %q", errOut.String())
	}
}

func TestOAuthLoginValidationAndDryRun(t *testing.T) {
	stub := newOAuthStub(t)
	stub.apply(t)
	newHome(t)
	t.Setenv("FLAREADM_API_TOKEN", "")

	// Missing client id.
	if res := runCLI(t, "auth", "login", "--no-browser"); res.code != errors.CodeInvalid ||
		!strings.Contains(res.stderr, "--client-id is required") {
		t.Fatalf("missing client id: code=%d stderr=%q", res.code, res.stderr)
	}
	// Unknown scope, conflicting scope flags, bad port.
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--client-id", "c", "--scopes", "not:a-scope"}, "unknown scope"},
		{[]string{"--client-id", "c", "--scopes", "account:read", "--all-scopes"}, "cannot be combined"},
		{[]string{"--client-id", "c", "--all-scopes", "--read-only"}, "mutually exclusive"},
		{[]string{"--client-id", "c", "--callback-port", "70000"}, "between 0 and 65535"},
	} {
		res := runCLI(t, append([]string{"auth", "login"}, tc.args...)...)
		if res.code != errors.CodeInvalid || !strings.Contains(res.stderr, tc.want) {
			t.Fatalf("%v: code=%d stderr=%q (want %q)", tc.args, res.code, res.stderr, tc.want)
		}
	}
	// --dry-run previews and never starts a listener.
	res := runCLI(t, "auth", "login", "--client-id", "cli-client", "--dry-run", "--all-scopes")
	if res.code != 0 || !strings.Contains(res.stdout, "Would start an OAuth login") {
		t.Fatalf("dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if strings.Contains(res.stdout, "cli-access-token") {
		t.Fatalf("dry-run must not print tokens: %q", res.stdout)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "flareadm", "oauth")); !os.IsNotExist(err) {
		t.Fatalf("dry-run must not write the store: %v", err)
	}

	// The profile key oauth_client_id is honoured.
	if err := os.MkdirAll(filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "flareadm"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "flareadm", "config.toml")
	if err := os.WriteFile(cfg, []byte("[profile.default]\noauth_client_id = \"from-profile\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res = runCLI(t, "auth", "login", "--dry-run", "--no-browser")
	if res.code != 0 || !strings.Contains(res.stdout, "Would start an OAuth login") {
		t.Fatalf("profile client id: code=%d stderr=%q", res.code, res.stderr)
	}
}

func TestOAuthLoginRefusesWhileEnvCredentialsExist(t *testing.T) {
	newHome(t)
	setToken(t, "existing-token")
	stub := newOAuthStub(t)
	stub.apply(t)

	res := runCLI(t, "auth", "login", "--client-id", "cli-client", "--no-browser")
	if res.code != errors.CodeInvalid {
		t.Fatalf("code=%d, want 2 (stderr=%q)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "already authenticated") || !strings.Contains(res.stderr, "FLAREADM_API_TOKEN") {
		t.Fatalf("message should name the variable to unset: %q", res.stderr)
	}
}

func TestOAuthUnwritableStoreExitsOne(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory permissions are not enforced on Windows; the uncreatable-directory case is covered by internal/oauth")
	}
	stub := newOAuthStub(t)
	stub.apply(t)
	newHome(t)
	t.Setenv("FLAREADM_API_TOKEN", "")
	// The credential directory exists but cannot be written to (the parent
	// chain stays writable so only the store write fails).
	base := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "flareadm")
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "oauth")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}

	port := freePort(t)
	out, errOut := &lockedBuffer{}, &lockedBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- Run(context.Background(),
			[]string{"auth", "login", "--client-id", "cli-client", "--no-browser",
				"--callback-port", strconv.Itoa(port), "--timeout", "10s"},
			strings.NewReader(""), out, errOut)
	}()
	authorize := waitForLine(t, out)
	resp, err := http.Get(authorize) //nolint:gosec // loopback test URL
	if err != nil {
		t.Fatalf("browser: %v", err)
	}
	_ = resp.Body.Close()
	if code := <-done; code != errors.CodeUnclassified {
		t.Fatalf("unwritable store: code=%d, want 1 (stderr=%q)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "oauth") {
		t.Fatalf("error should name the credential directory: %q", errOut.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "default.json")); !os.IsNotExist(err) {
		t.Fatalf("a failed login must not leave a credential behind: %v", err)
	}
}

func TestOAuthLogout(t *testing.T) {
	stub := newOAuthStub(t)
	stub.apply(t)
	newHome(t)
	t.Setenv("FLAREADM_API_TOKEN", "")
	path := writeStoredCredential(t, "default", storedCredentialMap(time.Now().Add(time.Hour)))

	// Refusal without --yes in a non-interactive session.
	if res := runCLI(t, "auth", "logout"); res.code != errors.CodeInvalid {
		t.Fatalf("logout refusal: code=%d, want 2", res.code)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("refused logout must keep the credential: %v", err)
	}

	// Dry-run previews and keeps everything.
	res := runCLI(t, "auth", "logout", "--dry-run")
	if res.code != 0 || !strings.Contains(res.stdout, "Would revoke the OAuth credential") {
		t.Fatalf("logout dry-run: code=%d stdout=%q", res.code, res.stdout)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("dry-run must keep the credential: %v", err)
	}
	stub.mu.Lock()
	before := len(stub.forms)
	stub.mu.Unlock()

	// --yes revokes the refresh token and deletes the file.
	res = runCLI(t, "auth", "logout", "--yes")
	if res.code != 0 {
		t.Fatalf("logout: code=%d stderr=%q", res.code, res.stderr)
	}
	if form := stub.lastForm(t); form.Get("token") != "stored-refresh-token" || form.Get("token_type_hint") != "refresh_token" {
		t.Fatalf("revoke request = %v", form)
	}
	stub.mu.Lock()
	after := len(stub.forms)
	stub.mu.Unlock()
	if after != before+1 {
		t.Fatalf("expected exactly one revoke request, got %d", after-before)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("credential should be deleted: %v", err)
	}

	// Nothing stored: exit 3 with a clear message.
	if res := runCLI(t, "auth", "logout", "--yes"); res.code != errors.CodeAuth {
		t.Fatalf("logout without a credential: code=%d, want 3", res.code)
	}

	// --local deletes without calling the revoke endpoint.
	writeStoredCredential(t, "default", storedCredentialMap(time.Now().Add(time.Hour)))
	stub.mu.Lock()
	before = len(stub.forms)
	stub.mu.Unlock()
	res = runCLI(t, "auth", "logout", "--yes", "--local")
	if res.code != 0 {
		t.Fatalf("local logout: code=%d stderr=%q", res.code, res.stderr)
	}
	stub.mu.Lock()
	after = len(stub.forms)
	stub.mu.Unlock()
	if after != before {
		t.Fatalf("--local must not call the revoke endpoint")
	}

	// A rejected revocation exits 3 but still deletes the local credential.
	writeStoredCredential(t, "default", storedCredentialMap(time.Now().Add(time.Hour)))
	stub.mu.Lock()
	stub.rejectRev = true
	stub.mu.Unlock()
	res = runCLI(t, "auth", "logout", "--yes")
	if res.code != errors.CodeAuth {
		t.Fatalf("rejected revocation: code=%d, want 3", res.code)
	}
	if !strings.Contains(res.stderr, "deleted anyway") {
		t.Fatalf("message should say the credential was deleted: %q", res.stderr)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("rejected revocation still deletes locally: %v", err)
	}

	// A network failure keeps the credential so logout can be retried.
	writeStoredCredential(t, "default", storedCredentialMap(time.Now().Add(time.Hour)))
	t.Setenv("FLAREADM_OAUTH_REVOKE_URL", "http://127.0.0.1:1/oauth2/revoke")
	res = runCLI(t, "auth", "logout", "--yes")
	if res.code != errors.CodeNetwork {
		t.Fatalf("network failure: code=%d, want 8", res.code)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("network failure must keep the credential: %v", err)
	}
}

// TestOAuthExpiredCredentialRefreshes covers the Phase 1 half of the refresh
// contract: an expired stored credential is refreshed before the API call and
// the rotated credential is persisted.
func TestOAuthExpiredCredentialRefreshes(t *testing.T) {
	stub := newOAuthStub(t)
	stub.apply(t)
	api := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		if r.Auth != "Bearer cli-access-token" {
			t.Errorf("authorization = %q, want the refreshed token", r.Auth)
		}
		return 200, envelopeWithInfo([]any{}, map[string]any{"page": float64(1), "per_page": float64(100), "count": float64(0), "total_count": float64(0), "total_pages": float64(1)})
	})
	newHome(t)
	t.Setenv("FLAREADM_API_TOKEN", "")
	writeStoredCredential(t, "default", storedCredentialMap(time.Now().Add(time.Minute)))

	res := runCLI(t, "zone", "list", "--endpoint-url", api.srv.URL)
	if res.code != 0 {
		t.Fatalf("refresh-backed call: code=%d stderr=%q", res.code, res.stderr)
	}
	form := stub.lastForm(t)
	if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "stored-refresh-token" {
		t.Fatalf("refresh request = %v", form)
	}
	data, err := os.ReadFile(filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "flareadm", "oauth", "default.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "cli-refresh-token") {
		t.Fatalf("rotated credential not persisted: %s", data)
	}
}

// TestConfigureOAuthClientIDKey covers the oauth_client_id profile key end to
// end: configure set/get/list, profile get/update and the config file.
func TestConfigureOAuthClientIDKey(t *testing.T) {
	newHome(t)
	setToken(t, "tok")

	if res := runCLI(t, "configure", "init"); res.code != 0 {
		t.Fatalf("init: %d %s", res.code, res.stderr)
	}
	if res := runCLI(t, "configure", "set", "oauth_client_id", "client-abc"); res.code != 0 {
		t.Fatalf("set oauth_client_id: code=%d stderr=%q", res.code, res.stderr)
	}
	if res := runCLI(t, "configure", "get", "oauth_client_id"); res.code != 0 || res.stdout != "client-abc\n" {
		t.Fatalf("get oauth_client_id: code=%d stdout=%q", res.code, res.stdout)
	}
	data, err := os.ReadFile(cfgPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `oauth_client_id = "client-abc"`) {
		t.Fatalf("config file = %s", data)
	}
	res := runCLI(t, "configure", "list", "--json")
	if res.code != 0 || !strings.Contains(res.stdout, "oauth_client_id") {
		t.Fatalf("list: code=%d stdout=%q", res.code, res.stdout)
	}

	// The documented key list names it, both for unknown-key errors and help.
	res = runCLI(t, "configure", "set", "nope", "x")
	if res.code != errors.CodeInvalid || !strings.Contains(res.stderr, "oauth_client_id") {
		t.Fatalf("unknown key message should list oauth_client_id: code=%d stderr=%q", res.code, res.stderr)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"configure", "set", "--help"}, "oauth_client_id"},
		{[]string{"configure", "get", "--help"}, "oauth_client_id"},
		{[]string{"profile", "update", "--help"}, "--oauth-client-id"},
	} {
		res := runCLI(t, tc.args...)
		if res.code != 0 || !strings.Contains(res.stdout, tc.want) {
			t.Fatalf("%v help should mention %s: code=%d stdout=%q", tc.args, tc.want, res.code, res.stdout)
		}
	}

	// profile get/update handle the key too.
	if res := runCLI(t, "profile", "create", "work", "--oauth-client-id", "client-work"); res.code != 0 {
		t.Fatalf("profile create: code=%d stderr=%q", res.code, res.stderr)
	}
	res = runCLI(t, "profile", "get", "work")
	if res.code != 0 || !strings.Contains(res.stdout, "client-work") {
		t.Fatalf("profile get: code=%d stdout=%q", res.code, res.stdout)
	}
	if res := runCLI(t, "profile", "update", "work", "--oauth-client-id", "client-work-2"); res.code != 0 {
		t.Fatalf("profile update: code=%d stderr=%q", res.code, res.stderr)
	}
	res = runCLI(t, "profile", "get", "work", "--json")
	if res.code != 0 || !strings.Contains(res.stdout, "client-work-2") {
		t.Fatalf("profile get --json: code=%d stdout=%q", res.code, res.stdout)
	}
	// The key drives auth login's client-id fallback (no environment token).
	t.Setenv("FLAREADM_API_TOKEN", "")
	res = runCLI(t, "auth", "login", "--dry-run", "--profile", "work", "--no-browser")
	if res.code != 0 || !strings.Contains(res.stdout, "Would start an OAuth login for profile work") {
		t.Fatalf("login with the profile key: code=%d stdout=%q stderr=%q", res.code, res.stdout, res.stderr)
	}
}

// ---- OAuth phases 3-4: refresh/expiry semantics, identity, 403 guidance ----

// TestOAuthRefreshesOnceOnUnauthorized covers the 401 path and clock skew: the
// stored credential is not expired locally, the API rejects the access token
// anyway, the client refreshes once and retries exactly once.
func TestOAuthRefreshesOnceOnUnauthorized(t *testing.T) {
	stub := newOAuthStub(t)
	stub.apply(t)
	var apiCalls int
	api := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		apiCalls++
		if r.Auth == "Bearer cli-access-token" {
			return 200, envelopeWithInfo([]any{map[string]any{"id": zoneID, "name": "example.com", "status": "active"}},
				map[string]any{"page": float64(1), "per_page": float64(100), "count": float64(1), "total_count": float64(1), "total_pages": float64(1)})
		}
		s, b := apiErr(401, 1000, "Invalid access token")
		return s, b
	})
	newHome(t)
	t.Setenv("FLAREADM_API_TOKEN", "")
	// Not inside the expiry window: no proactive refresh, so the first request
	// carries the stored token and the 401 drives the refresh.
	writeStoredCredential(t, "default", storedCredentialMap(time.Now().Add(30*time.Minute)))

	res := runCLI(t, "zone", "list", "--endpoint-url", api.srv.URL)
	if res.code != 0 {
		t.Fatalf("401 retry: code=%d stderr=%q", res.code, res.stderr)
	}
	if apiCalls != 2 {
		t.Fatalf("API calls = %d, want exactly 2 (original + one retry)", apiCalls)
	}
	if form := stub.lastForm(t); form.Get("grant_type") != "refresh_token" {
		t.Fatalf("expected a refresh, got %v", form)
	}
	if !strings.Contains(res.stdout, "example.com") {
		t.Fatalf("output = %s", res.stdout)
	}
	// The response is not retried again: the second call used the new token.
	if errors.CodeOf(errors.New(errors.CodeSuccess, "")) != errors.CodeSuccess {
		t.Fatal("sanity")
	}
}

// TestOAuthUnauthorizedWithoutRefreshExitsThree covers a rejected refresh after
// a 401: exit 3 with a pointer at auth login.
func TestOAuthUnauthorizedWithoutRefreshExitsThree(t *testing.T) {
	stub := newOAuthStub(t)
	stub.apply(t)
	stub.mu.Lock()
	stub.rejectRefresh = true
	stub.mu.Unlock()
	api := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(401, 1000, "Invalid access token")
		return s, b
	})
	newHome(t)
	t.Setenv("FLAREADM_API_TOKEN", "")
	writeStoredCredential(t, "default", storedCredentialMap(time.Now().Add(30*time.Minute)))

	res := runCLI(t, "zone", "list", "--endpoint-url", api.srv.URL)
	if res.code != errors.CodeAuth {
		t.Fatalf("code=%d, want 3 (stderr=%q)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "auth login") {
		t.Fatalf("stderr should point at auth login: %q", res.stderr)
	}
}

// TestOAuthForbiddenIsNotRetried covers the 403 rule: no refresh, no retry, and
// a message that states both possible causes without claiming which.
func TestOAuthForbiddenIsNotRetried(t *testing.T) {
	stub := newOAuthStub(t)
	stub.apply(t)
	apiCalls := 0
	api := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		apiCalls++
		s, b := apiErr(403, 9109, "Unauthorized to access requested resource")
		return s, b
	})
	newHome(t)
	t.Setenv("FLAREADM_API_TOKEN", "")
	writeStoredCredential(t, "default", storedCredentialMap(time.Now().Add(30*time.Minute)))

	res := runCLI(t, "zone", "list", "--endpoint-url", api.srv.URL)
	if res.code != errors.CodePermission {
		t.Fatalf("code=%d, want 4 (stderr=%q)", res.code, res.stderr)
	}
	if apiCalls != 1 {
		t.Fatalf("403 must not be retried: %d API calls", apiCalls)
	}
	stub.mu.Lock()
	requests := len(stub.forms)
	stub.mu.Unlock()
	if requests != 0 {
		t.Fatalf("403 must not trigger a refresh: %d oauth requests", requests)
	}
	for _, want := range []string{"granted scopes", "account role", "auth login --all-scopes", "auth status"} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("403 hint missing %q: %q", want, res.stderr)
		}
	}
}

// TestForbiddenHintAbsentForAPITokens: the hint is OAuth-only.
func TestForbiddenHintAbsentForAPITokens(t *testing.T) {
	setToken(t, "tok")
	newHome(t)
	api := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		s, b := apiErr(403, 9109, "forbidden")
		return s, b
	})
	res := runCLI(t, "zone", "list", "--endpoint-url", api.srv.URL)
	if res.code != errors.CodePermission {
		t.Fatalf("code=%d, want 4", res.code)
	}
	if strings.Contains(res.stderr, "auth login --all-scopes") || strings.Contains(res.stderr, "granted scopes") {
		t.Fatalf("API-token 403 must not get the OAuth hint: %q", res.stderr)
	}
}

// TestOAuthVerifyAndStatusIdentity: OAuth credentials verify with GET /user,
// API tokens keep using GET /user/tokens/verify.
func TestOAuthVerifyAndStatusIdentity(t *testing.T) {
	stub := newOAuthStub(t)
	stub.apply(t)
	paths := []string{}
	api := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		paths = append(paths, path)
		switch path {
		case "/user":
			return 200, envelope(map[string]any{"id": "user-1", "email": "dev@example.com", "first_name": "Dev", "last_name": "Eloper"})
		case "/user/tokens/verify":
			return 200, envelope(map[string]any{"id": "token-1", "status": "active"})
		}
		s, b := apiErr(404, 7000, "not found")
		return s, b
	})
	newHome(t)
	t.Setenv("FLAREADM_API_TOKEN", "")
	writeStoredCredential(t, "default", storedCredentialMap(time.Now().Add(time.Hour)))

	res := runCLI(t, "auth", "verify", "--endpoint-url", api.srv.URL)
	if res.code != 0 {
		t.Fatalf("oauth verify: code=%d stderr=%q", res.code, res.stderr)
	}
	if len(paths) != 1 || paths[0] != "/user" {
		t.Fatalf("oauth verify paths = %v, want [/user]", paths)
	}
	if !strings.Contains(res.stdout, "dev@example.com") || !strings.Contains(res.stdout, "Dev Eloper") {
		t.Fatalf("oauth verify output = %s", res.stdout)
	}

	// Status adds the identity row for OAuth credentials.
	res = runCLI(t, "auth", "status", "--endpoint-url", api.srv.URL)
	if res.code != 0 || !strings.Contains(res.stdout, "dev@example.com") {
		t.Fatalf("status identity: code=%d stdout=%q", res.code, res.stdout)
	}
	for _, want := range []string{"SOURCE", "oauth:default", "SCOPES", "EXPIRES", "REFRESH TOKEN", "STORE", "USER"} {
		if !strings.Contains(res.stdout, want) {
			t.Fatalf("status output missing %q: %s", want, res.stdout)
		}
	}
	if strings.Contains(res.stdout, "stored-access-token") || strings.Contains(res.stdout, "stored-refresh-token") {
		t.Fatalf("status leaked token material: %s", res.stdout)
	}

	// An API token keeps the old verification call.
	setToken(t, "tok")
	paths = nil
	res = runCLI(t, "auth", "verify", "--endpoint-url", api.srv.URL)
	if res.code != 0 || len(paths) != 1 || paths[0] != "/user/tokens/verify" {
		t.Fatalf("api-token verify: code=%d paths=%v stdout=%q", res.code, paths, res.stdout)
	}
	if !strings.Contains(res.stdout, "active") {
		t.Fatalf("api-token verify output = %s", res.stdout)
	}
}

// TestStoreBackedRefreshFailureDoesNotHang: an unreachable token endpoint during
// a proactive refresh exits 8 quickly instead of hanging.
func TestStoreBackedRefreshFailureDoesNotHang(t *testing.T) {
	newHome(t)
	t.Setenv("FLAREADM_API_TOKEN", "")
	t.Setenv("FLAREADM_OAUTH_TOKEN_URL", "http://127.0.0.1:1/oauth2/token")
	api := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		t.Error("the API must not be called when the refresh fails")
		return 200, envelope(nil)
	})
	writeStoredCredential(t, "default", storedCredentialMap(time.Now().Add(time.Minute)))

	start := time.Now()
	res := runCLI(t, "zone", "list", "--endpoint-url", api.srv.URL, "--timeout", "2s")
	elapsed := time.Since(start)
	if res.code != errors.CodeNetwork {
		t.Fatalf("code=%d, want 8 (stderr=%q)", res.code, res.stderr)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("refresh failure took %s; it must not hang", elapsed)
	}
}

// runLoginWithBrowser drives one CLI login end to end against the stub: it
// starts the command, plays the browser against the printed authorize URL and
// returns stdout, stderr and the exit code.
func runLoginWithBrowser(t *testing.T, extra ...string) (string, string, int) {
	t.Helper()
	port := freePort(t)
	out, errOut := &lockedBuffer{}, &lockedBuffer{}
	args := append([]string{"auth", "login", "--client-id", "cli-client", "--no-browser",
		"--callback-port", strconv.Itoa(port), "--timeout", "10s"}, extra...)
	done := make(chan int, 1)
	go func() {
		done <- Run(context.Background(), args, strings.NewReader(""), out, errOut)
	}()
	authorize := waitForLine(t, out)
	resp, err := http.Get(authorize) //nolint:gosec // loopback test URL
	if err == nil {
		_ = resp.Body.Close()
	}
	code := <-done
	return out.String(), errOut.String(), code
}

// TestOAuthLoginFailureMessages checks that every OAuth failure surfaces the
// error code and Cloudflare's description, with remediation that matches the
// actual problem: scope rejections talk about scopes, client/redirect problems
// name the redirect URI and never mention --scopes.
func TestOAuthLoginFailureMessages(t *testing.T) {
	cases := []struct {
		name          string
		authorize     [2]string // code, description
		token         [2]string // code, description
		wantCode      string
		wantSnippets  []string
		deniedSnippet string
	}{
		{
			name:          "authorize invalid_scope",
			authorize:     [2]string{"invalid_scope", "scope not allowed for this client"},
			wantCode:      "invalid_scope",
			wantSnippets:  []string{"invalid_scope", "scope not allowed for this client", "--scopes", "requested: ", "Manage Account > OAuth clients"},
			deniedSnippet: "compare the redirect URI",
		},
		{
			name:          "authorize unauthorized_client",
			authorize:     [2]string{"unauthorized_client", "client not found"},
			wantCode:      "unauthorized_client",
			wantSnippets:  []string{"unauthorized_client", "client not found", "redirect URI http://127.0.0.1:", "/oauth/callback", "registered redirect URL"},
			deniedSnippet: "--scopes",
		},
		{
			name:          "token invalid_grant",
			token:         [2]string{"invalid_grant", "authorization code expired"},
			wantCode:      "invalid_grant",
			wantSnippets:  []string{"invalid_grant", "authorization code expired", "auth login", "single use"},
			deniedSnippet: "--scopes",
		},
		{
			name:          "unknown error code",
			authorize:     [2]string{"teapot_error", "unexpected server failure"},
			wantCode:      "teapot_error",
			wantSnippets:  []string{"teapot_error", "unexpected server failure", "Manage Account > OAuth clients"},
			deniedSnippet: "--scopes",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := newOAuthStub(t)
			stub.apply(t)
			newHome(t)
			t.Setenv("FLAREADM_API_TOKEN", "")
			stub.mu.Lock()
			stub.authorizeError, stub.authorizeDescription = tc.authorize[0], tc.authorize[1]
			stub.tokenError, stub.tokenDescription = tc.token[0], tc.token[1]
			stub.mu.Unlock()

			stdout, stderr, code := runLoginWithBrowser(t)
			if code != errors.CodeAuth {
				t.Fatalf("exit code = %d, want 3 (stderr=%q)", code, stderr)
			}
			for _, want := range tc.wantSnippets {
				if !strings.Contains(stderr, want) {
					t.Fatalf("stderr missing %q:\n%s", want, stderr)
				}
			}
			if tc.deniedSnippet != "" && strings.Contains(stderr, tc.deniedSnippet) {
				t.Fatalf("stderr must not contain %q for this failure:\n%s", tc.deniedSnippet, stderr)
			}
			for _, secret := range []string{"cli-access-token", "cli-refresh-token", "cli-auth-code"} {
				if strings.Contains(stderr, secret) || strings.Contains(stdout, secret) {
					t.Fatalf("credential material %q leaked:\nstdout=%s\nstderr=%s", secret, stdout, stderr)
				}
			}
		})
	}
}

// TestOAuthLoginTokenErrorRedactsEchoedCode: even a server error description
// that echoes the authorization code must not reach the terminal.
func TestOAuthLoginTokenErrorRedactsEchoedCode(t *testing.T) {
	stub := newOAuthStub(t)
	stub.apply(t)
	newHome(t)
	t.Setenv("FLAREADM_API_TOKEN", "")
	stub.mu.Lock()
	stub.tokenError = "invalid_grant"
	stub.tokenDescription = "code rejected"
	stub.echoCodeInError = true
	stub.mu.Unlock()

	stdout, stderr, code := runLoginWithBrowser(t)
	if code != errors.CodeAuth {
		t.Fatalf("exit code = %d, want 3 (stderr=%q)", code, stderr)
	}
	if !strings.Contains(stderr, "invalid_grant") || !strings.Contains(stderr, "code rejected") {
		t.Fatalf("stderr lost the error detail: %q", stderr)
	}
	if strings.Contains(stderr, "cli-auth-code") || strings.Contains(stdout, "cli-auth-code") {
		t.Fatalf("the authorization code leaked back through the error description:\n%s", stderr)
	}
	if !strings.Contains(stderr, "[REDACTED]") {
		t.Fatalf("expected the echoed code to be redacted: %q", stderr)
	}
}

// TestOAuthLoginBrowserPathRequiresTerminalAtCLILevel pins the CLI-level rule:
// the browser path is interactive-only, so a piped stdin exits 2 before any
// opener runs and prints nothing. The fallback behaviour itself (URL printed
// once, waiting continues, timeout exit 8) is covered by the flow tests, which
// can drive the browser path without a TTY.
func TestOAuthLoginBrowserPathRequiresTerminalAtCLILevel(t *testing.T) {
	stub := newOAuthStub(t)
	stub.apply(t)
	newHome(t)
	t.Setenv("FLAREADM_API_TOKEN", "")
	t.Setenv("BROWSER", "definitely-not-a-real-browser-xyz")

	res := runCLI(t, "auth", "login", "--client-id", "cli-client")
	if res.code != errors.CodeInvalid {
		t.Fatalf("code=%d, want 2 (stderr=%q)", res.code, res.stderr)
	}
	if strings.Contains(res.stdout, "http") {
		t.Fatalf("the authorize URL must not be printed when the login cannot proceed: %q", res.stdout)
	}
	stub.mu.Lock()
	requests := len(stub.forms)
	stub.mu.Unlock()
	if requests != 0 {
		t.Fatalf("no token request may happen: %d", requests)
	}
}
