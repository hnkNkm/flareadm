package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hnkNkm/flareadm/internal/errors"
)

// exitCode exposes the package's exit-code mapping to the tests.
func exitCode(err error) int { return errors.CodeOf(err) }

// syncBuffer is a concurrency-safe writer: the flow writes the authorize URL
// from its own goroutine while the test polls it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// fakeOAuth is an offline OAuth provider: an authorize page that redirects to
// the loopback callback, plus a token endpoint that returns fixed tokens. The
// only socket a test opens besides these is the callback listener.
type fakeOAuth struct {
	server        *httptest.Server
	mu            sync.Mutex
	requests      []url.Values
	denyConsent   bool
	failToken     bool
	tokenResponse map[string]any
	rotateRefresh string
}

func newFakeOAuth(t *testing.T) *fakeOAuth {
	t.Helper()
	f := &fakeOAuth{
		tokenResponse: map[string]any{
			"access_token":  "access-from-server",
			"expires_in":    3600,
			"refresh_token": "refresh-from-server",
			"scope":         "openid offline_access account:read",
			"token_type":    "Bearer",
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/auth", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		redirect, err := url.Parse(q.Get("redirect_uri"))
		if err != nil || redirect.Scheme == "" {
			http.Error(w, "bad redirect_uri", http.StatusBadRequest)
			return
		}
		next := redirect.Query()
		if f.denyConsent {
			next.Set("error", "access_denied")
			next.Set("error_description", "user declined")
		} else {
			next.Set("code", "auth-code-abc")
		}
		next.Set("state", q.Get("state"))
		redirect.RawQuery = next.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	})
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.requests = append(f.requests, r.PostForm)
		rotate := f.rotateRefresh
		fail := f.failToken
		resp := f.tokenResponse
		f.mu.Unlock()
		if fail {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"refresh token is not valid"}`))
			return
		}
		out := map[string]any{}
		for k, v := range resp {
			out[k] = v
		}
		if rotate != "" && r.PostForm.Get("grant_type") == "refresh_token" {
			out["refresh_token"] = rotate
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/oauth2/revoke", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.requests = append(f.requests, r.PostForm)
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeOAuth) endpoints() Endpoints {
	return Endpoints{
		Auth:   f.server.URL + "/oauth2/auth",
		Token:  f.server.URL + "/oauth2/token",
		Revoke: f.server.URL + "/oauth2/revoke",
	}
}

func (f *fakeOAuth) lastRequest(t *testing.T) url.Values {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) == 0 {
		t.Fatal("no token/revoke request recorded")
	}
	return f.requests[len(f.requests)-1]
}

// browser mimics the user's browser: it follows the authorize redirect to the
// loopback callback. The callback server is started by Login, so this runs in
// a goroutine while Login waits.
func browser(t *testing.T, authorizeURL string) {
	t.Helper()
	resp, err := http.Get(authorizeURL) //nolint:gosec // test-only loopback URL
	if err != nil {
		t.Errorf("browser: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
}

func TestLoginFullFlowPKCE(t *testing.T) {
	fake := newFakeOAuth(t)
	var printed syncBuffer
	var protected []string
	type result struct {
		cred Credential
		err  error
	}
	done := make(chan result, 1)
	go func() {
		cred, err := Login(context.Background(), LoginOptions{
			ClientID:     "client-123",
			Scopes:       []string{"account:read"},
			CallbackHost: "127.0.0.1",
			CallbackPort: 0, // ephemeral: the test learns the URL from Out
			OpenBrowser:  false,
			Timeout:      10 * time.Second,
			Endpoints:    fake.endpoints(),
			Out:          &printed,
			Protect:      func(s string) { protected = append(protected, s) },
		})
		done <- result{cred, err}
	}()

	authorize := waitForAuthorizeURL(t, &printed)
	parsed, err := url.Parse(strings.TrimSpace(authorize))
	if err != nil {
		t.Fatalf("authorize URL: %v", err)
	}
	q := parsed.Query()
	for key, want := range map[string]string{
		"response_type":         "code",
		"client_id":             "client-123",
		"code_challenge_method": "S256",
	} {
		if got := q.Get(key); got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
	if !strings.Contains(q.Get("scope"), "offline_access") || !strings.Contains(q.Get("scope"), "offline") {
		t.Fatalf("scope = %q, want offline_access and offline", q.Get("scope"))
	}
	if q.Get("code_challenge") == "" || q.Get("state") == "" {
		t.Fatal("authorize URL lacks PKCE challenge or state")
	}
	browser(t, strings.TrimSpace(authorize))
	got := <-done
	if got.err != nil {
		t.Fatalf("login: %v", got.err)
	}
	if got.cred.AccessToken != "access-from-server" || got.cred.RefreshToken != "refresh-from-server" {
		t.Fatalf("credential = %+v", got.cred)
	}
	if got.cred.ExpiresAt.IsZero() || len(got.cred.Scopes) != 3 {
		t.Fatalf("expiry/scopes not derived: %+v", got.cred)
	}

	// The token request must be a public-client code exchange with the verifier
	// and without any client secret.
	form := fake.lastRequest(t)
	if form.Get("grant_type") != "authorization_code" || form.Get("code") != "auth-code-abc" {
		t.Fatalf("token request = %v", form)
	}
	if form.Get("code_verifier") == "" {
		t.Fatal("token request lacks the PKCE code verifier")
	}
	if form.Get("client_secret") != "" {
		t.Fatal("token request must not include a client secret")
	}
	if !strings.Contains(form.Get("redirect_uri"), CallbackPath) {
		t.Fatalf("redirect_uri = %q", form.Get("redirect_uri"))
	}

	// Redaction hook saw the code and both tokens.
	joined := strings.Join(protected, ",")
	for _, secret := range []string{"auth-code-abc", "access-from-server", "refresh-from-server"} {
		if !strings.Contains(joined, secret) {
			t.Fatalf("secret %q was not registered for redaction (got %v)", secret, protected)
		}
	}
}

// waitForAuthorizeURL polls the writer until the URL line appears.
func waitForAuthorizeURL(t *testing.T, w *syncBuffer) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s := w.String(); strings.Contains(s, "http") {
			for _, line := range strings.Split(s, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "http") {
					return line
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the authorize URL was never printed")
	return ""
}

func TestLoginStateMismatchIsRejected(t *testing.T) {
	fake := newFakeOAuth(t)
	var printed syncBuffer
	done := make(chan error, 1)
	go func() {
		_, err := Login(context.Background(), LoginOptions{
			ClientID: "client-123", CallbackHost: "127.0.0.1",
			OpenBrowser: false, Timeout: 5 * time.Second,
			Endpoints: fake.endpoints(), Out: &printed,
		})
		done <- err
	}()
	authorize := strings.TrimSpace(waitForAuthorizeURL(t, &printed))
	redirect, err := url.Parse(authorize)
	if err != nil {
		t.Fatal(err)
	}
	target := redirect.Query().Get("redirect_uri")
	resp, err := http.Get(target + "?code=stolen&state=wrong-state") //nolint:gosec // loopback test URL
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	_ = resp.Body.Close()
	if err := <-done; err == nil || !strings.Contains(err.Error(), "state mismatch") {
		t.Fatalf("want a state-mismatch error, got %v", err)
	}
}

func TestLoginAccessDeniedMapsToAuthError(t *testing.T) {
	fake := newFakeOAuth(t)
	fake.denyConsent = true
	var printed syncBuffer
	done := make(chan error, 1)
	go func() {
		_, err := Login(context.Background(), LoginOptions{
			ClientID: "client-123", CallbackHost: "127.0.0.1",
			OpenBrowser: false, Timeout: 5 * time.Second,
			Endpoints: fake.endpoints(), Out: &printed,
		})
		done <- err
	}()
	browser(t, strings.TrimSpace(waitForAuthorizeURL(t, &printed)))
	err := <-done
	if err == nil || !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("want an access_denied error, got %v", err)
	}
	if code := exitCode(err); code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
}

func TestRefreshRotatesOnlyWhenReturned(t *testing.T) {
	fake := newFakeOAuth(t)
	now := time.Now()
	store := newStoreDir(t)
	stored := sampleCredential()
	if err := store.Save("work", stored); err != nil {
		t.Fatal(err)
	}

	rotated, err := Refresh(context.Background(), RefreshOptions{
		ClientID:   stored.ClientID,
		Credential: stored,
		Endpoints:  fake.endpoints(),
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if rotated.AccessToken != "access-from-server" || rotated.RefreshToken != "refresh-from-server" {
		t.Fatalf("rotated credential = %+v", rotated)
	}
	if form := fake.lastRequest(t); form.Get("grant_type") != "refresh_token" || form.Get("client_id") != "client-123" {
		t.Fatalf("refresh request = %v", form)
	}
	if form := fake.lastRequest(t); form.Get("client_secret") != "" {
		t.Fatal("refresh must not send a client secret")
	}

	// A response without a refresh_token keeps the stored one (RFC 6749 §6).
	fake.mu.Lock()
	fake.tokenResponse = map[string]any{"access_token": "second-access", "expires_in": 900}
	fake.mu.Unlock()
	kept, err := Refresh(context.Background(), RefreshOptions{
		ClientID: stored.ClientID, Credential: stored, Endpoints: fake.endpoints(),
	})
	if err != nil {
		t.Fatalf("refresh without rotation: %v", err)
	}
	if kept.RefreshToken != stored.RefreshToken {
		t.Fatalf("refresh token = %q, want the stored one", kept.RefreshToken)
	}

	// A rejection maps to exit code 3.
	fake.mu.Lock()
	fake.failToken = true
	fake.mu.Unlock()
	if _, err := Refresh(context.Background(), RefreshOptions{
		ClientID: stored.ClientID, Credential: stored, Endpoints: fake.endpoints(),
	}); err == nil || exitCode(err) != 3 {
		t.Fatalf("rejected refresh should exit 3, got %v", err)
	}
}

func TestRefreshWithoutStoredTokenFailsClearly(t *testing.T) {
	fake := newFakeOAuth(t)
	_, err := Refresh(context.Background(), RefreshOptions{Endpoints: fake.endpoints(), Credential: Credential{AccessToken: "x"}})
	if err == nil || exitCode(err) != 3 || !strings.Contains(err.Error(), "auth login") {
		t.Fatalf("want an actionable auth error, got %v", err)
	}
}

func TestRevokeSendsRefreshToken(t *testing.T) {
	fake := newFakeOAuth(t)
	cred := sampleCredential()
	if err := Revoke(context.Background(), RevokeOptions{
		Credential: cred, ClientID: cred.ClientID, Endpoints: fake.endpoints(),
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	form := fake.lastRequest(t)
	if form.Get("token") != cred.RefreshToken || form.Get("token_type_hint") != "refresh_token" {
		t.Fatalf("revoke request = %v", form)
	}
}

func TestTokenEndpointErrorsAreAuthFailures(t *testing.T) {
	fake := newFakeOAuth(t)
	fake.mu.Lock()
	fake.failToken = true
	fake.mu.Unlock()
	_, err := Login(context.Background(), LoginOptions{
		ClientID: "client", CallbackHost: "127.0.0.1", OpenBrowser: false,
		Timeout: 300 * time.Millisecond, Endpoints: fake.endpoints(), Out: &syncBuffer{},
	})
	// Login cannot reach the token endpoint without a callback, so this checks
	// the state/consent path only indirectly; the direct token-error mapping is
	// covered by TestRefreshRotatesOnlyWhenReturned.
	if err == nil {
		t.Fatal("login without a browser callback must fail")
	}
}

func TestEndpointsFromEnvOverrides(t *testing.T) {
	env := map[string]string{
		EnvAuthURL:   "http://auth.test/authorize",
		EnvTokenURL:  "http://auth.test/token",
		EnvRevokeURL: "http://auth.test/revoke",
	}
	got := EndpointsFromEnv(func(k string) string { return env[k] })
	if got.Auth != env[EnvAuthURL] || got.Token != env[EnvTokenURL] || got.Revoke != env[EnvRevokeURL] {
		t.Fatalf("endpoints = %+v", got)
	}
	defaults := EndpointsFromEnv(func(string) string { return "" })
	if defaults.Auth != DefaultAuthURL || defaults.Token != DefaultTokenURL || defaults.Revoke != DefaultRevokeURL {
		t.Fatalf("defaults = %+v", defaults)
	}
}

func TestWithOfflineScopesAppendsRequired(t *testing.T) {
	got := WithOfflineScopes([]string{"account:read", "offline"})
	joined := fmt.Sprint(got)
	for _, want := range []string{"account:read", "offline", "offline_access", "openid"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("scope %q missing from %v", want, got)
		}
	}
	if strings.Count(joined, "offline ") > 1 || strings.Contains(joined, "offline offline") {
		t.Fatalf("duplicate scopes: %v", got)
	}
}

// TestRefreshRotationRaceKeepsValidToken simulates two processes refreshing the
// same stored credential: whichever writes last, the store must hold a token
// the server still accepts (docs/oauth.md §9).
func TestRefreshRotationRaceKeepsValidToken(t *testing.T) {
	fake := newFakeOAuth(t)
	store := newStoreDir(t)
	stored := sampleCredential()
	if err := store.Save("work", stored); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	rotations := []string{"rotated-by-a", "rotated-by-b"}
	for i, rotated := range rotations {
		wg.Add(1)
		go func(i int, rotated string) {
			defer wg.Done()
			fake.mu.Lock()
			fake.rotateRefresh = rotated
			fake.tokenResponse = map[string]any{
				"access_token":  "access-" + rotated,
				"refresh_token": rotated,
				"expires_in":    3600,
			}
			fake.mu.Unlock()
			next, err := Refresh(context.Background(), RefreshOptions{
				ClientID: stored.ClientID, Credential: stored, Endpoints: fake.endpoints(),
			})
			if err != nil {
				t.Errorf("refresh %d: %v", i, err)
				return
			}
			if err := store.Save("work", next); err != nil {
				t.Errorf("save %d: %v", i, err)
			}
		}(i, rotated)
	}
	wg.Wait()

	last, ok, err := store.Load("work")
	if err != nil || !ok {
		t.Fatalf("load after race: ok=%v err=%v", ok, err)
	}
	valid := map[string]bool{rotations[0]: true, rotations[1]: true}
	if !valid[last.RefreshToken] {
		t.Fatalf("stored refresh token = %q, want one of the rotations", last.RefreshToken)
	}
	if last.AccessToken == "" {
		t.Fatal("stored access token is empty after the race")
	}
	// The stored token still works for a further refresh.
	if _, err := Refresh(context.Background(), RefreshOptions{
		ClientID: last.ClientID, Credential: last, Endpoints: fake.endpoints(),
	}); err != nil {
		t.Fatalf("refresh with the surviving token failed: %v", err)
	}
}

// ---- browser handoff (opener selection and fallbacks) ----------------------

func TestBrowserCandidatesPerOS(t *testing.T) {
	cases := []struct {
		goos string
		want []string
		args [][]string
	}{
		{"linux", []string{"xdg-open", "wslview"}, [][]string{nil, nil}},
		{"darwin", []string{"open"}, [][]string{nil}},
		{"windows", []string{"rundll32"}, [][]string{{"url.dll,FileProtocolHandler"}}},
	}
	for _, tc := range cases {
		got := browserCandidates(tc.goos)
		if len(got) != len(tc.want) {
			t.Fatalf("%s: %d candidates, want %d", tc.goos, len(got), len(tc.want))
		}
		for i, want := range tc.want {
			if got[i].Name != want {
				t.Fatalf("%s candidate %d = %q, want %q", tc.goos, i, got[i].Name, want)
			}
			if strings.Join(got[i].Args, " ") != strings.Join(tc.args[i], " ") {
				t.Fatalf("%s candidate %d args = %v, want %v", tc.goos, i, got[i].Args, tc.args[i])
			}
		}
		// The URL is never baked into a candidate: it is appended as an
		// argument, so nothing can be interpreted by a shell.
		for _, c := range got {
			for _, a := range c.Args {
				if strings.Contains(a, "://") {
					t.Fatalf("%s candidate carries a URL in its arguments: %v", tc.goos, c)
				}
			}
		}
	}
}

// withFakeOpener swaps the process seam for the duration of a test.
func withFakeOpener(t *testing.T, fn func(browserCandidate, string) error) {
	t.Helper()
	original := startOpener
	startOpener = fn
	t.Cleanup(func() { startOpener = original })
}

func TestOpenInBrowserFallsBackToNextCandidate(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		t.Skip("the fallback chain exists on the xdg-open platforms")
	}
	var tried []string
	withFakeOpener(t, func(c browserCandidate, target string) error {
		tried = append(tried, c.Name)
		if c.Name == "xdg-open" {
			return fmt.Errorf("xdg-open failed: exit status 3")
		}
		if !strings.HasPrefix(target, "http") {
			t.Fatalf("target %q is not a URL", target)
		}
		return nil
	})
	if err := openInBrowser("https://dash.cloudflare.com/oauth2/auth?x=1"); err != nil {
		t.Fatalf("openInBrowser: %v", err)
	}
	if strings.Join(tried, ",") != "xdg-open,wslview" {
		t.Fatalf("tried %v, want xdg-open then wslview", tried)
	}
}

func TestOpenInBrowserReportsWhenEveryCandidateFails(t *testing.T) {
	withFakeOpener(t, func(c browserCandidate, target string) error {
		return fmt.Errorf("%s failed: not found", c.Name)
	})
	err := openInBrowser("https://example.test/auth")
	if err == nil {
		t.Fatal("expected an error when no opener works")
	}
	if !strings.Contains(err.Error(), "no browser opener worked") {
		t.Fatalf("error = %v", err)
	}
	for _, name := range []string{"xdg-open", "wslview", "open", "rundll32"} {
		// Only the candidates for this platform are reported; at least one name
		// must appear.
		if strings.Contains(err.Error(), name) {
			return
		}
	}
	t.Fatalf("error names no candidate: %v", err)
}

// TestLoginKeepsWaitingWhenBrowserCannotOpen covers the fallback contract: the
// URL is printed exactly once with a clear message and the login still
// completes when the callback arrives.
func TestLoginKeepsWaitingWhenBrowserCannotOpen(t *testing.T) {
	fake := newFakeOAuth(t)
	var stdout, stderr syncBuffer
	done := make(chan error, 1)
	go func() {
		_, err := Login(context.Background(), LoginOptions{
			ClientID: "client-123", CallbackHost: "127.0.0.1", CallbackPort: 0,
			OpenBrowser: true, Timeout: 10 * time.Second,
			Endpoints: fake.endpoints(), Out: &stdout, ErrOut: &stderr,
			OpenURL: func(string) error { return fmt.Errorf("no browser opener worked (xdg-open failed: not found)") },
		})
		done <- err
	}()
	url := waitForAuthorizeURL(t, &stderr)
	if n := countURLs(stderr.String()); n != 1 {
		t.Fatalf("stderr has %d URL lines, want exactly 1:\n%s", n, stderr.String())
	}
	if !strings.Contains(stderr.String(), "could not open a browser automatically") {
		t.Fatalf("fallback message missing:\n%s", stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "" {
		t.Fatalf("stdout must stay clean:\n%s", stdout.String())
	}
	browser(t, url)
	if err := <-done; err != nil {
		t.Fatalf("login should still succeed: %v", err)
	}
}

// TestLoginBrowserPathWritesURLToErrOutOnly: with a browser handoff the URL must
// be visible on stderr (a blank browser window must never hide it) while stdout
// stays clean for machine-readable use.
func TestLoginBrowserPathWritesURLToErrOutOnly(t *testing.T) {
	fake := newFakeOAuth(t)
	var stdout, stderr syncBuffer
	openerCalled := false
	done := make(chan error, 1)
	go func() {
		_, err := Login(context.Background(), LoginOptions{
			ClientID: "client-123", CallbackHost: "127.0.0.1", CallbackPort: 0,
			OpenBrowser: true, Timeout: 10 * time.Second,
			Endpoints: fake.endpoints(), Out: &stdout, ErrOut: &stderr,
			OpenURL: func(target string) error {
				openerCalled = true
				go browser(t, target)
				return nil
			},
		})
		done <- err
	}()
	if err := <-done; err != nil {
		t.Fatalf("login: %v", err)
	}
	if !openerCalled {
		t.Fatal("the opener was not used")
	}
	if strings.TrimSpace(stdout.String()) != "" {
		t.Fatalf("stdout must stay clean in the browser path:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), browserURLNotice) {
		t.Fatalf("the handoff notice is missing:\n%s", stderr.String())
	}
	if n := countURLs(stderr.String()); n != 1 {
		t.Fatalf("stderr has %d URL lines, want exactly 1:\n%s", n, stderr.String())
	}
	if strings.Contains(stderr.String(), "Still waiting for the browser callback") {
		t.Fatalf("a completed login must not print the diagnostic:\n%s", stderr.String())
	}
}

// TestLoginBrowserDiagnosticFiresOnceAfterGrace: when no callback arrives, the
// URL is repeated exactly once with the three causes of a blank authorize page,
// and the login keeps waiting for --timeout (exit code 8).
func TestLoginBrowserDiagnosticFiresOnceAfterGrace(t *testing.T) {
	fake := newFakeOAuth(t)
	var stdout, stderr syncBuffer
	const grace = 50 * time.Millisecond
	port := freePort(t)
	_, err := Login(context.Background(), LoginOptions{
		ClientID: "client-123", CallbackHost: "127.0.0.1", CallbackPort: port,
		OpenBrowser: true, Timeout: 600 * time.Millisecond, BrowserGrace: grace,
		Endpoints: fake.endpoints(), Out: &stdout, ErrOut: &stderr,
		OpenURL: func(string) error { return nil }, // a browser "opened" but nothing came back
	})
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if code := exitCode(err); code != 8 {
		t.Fatalf("exit code = %d, want 8 (%v)", code, err)
	}
	if strings.TrimSpace(stdout.String()) != "" {
		t.Fatalf("stdout must stay clean in the browser path:\n%s", stdout.String())
	}
	if n := strings.Count(stderr.String(), "Still waiting for the browser callback"); n != 1 {
		t.Fatalf("the diagnostic appeared %d times, want exactly 1:\n%s", n, stderr.String())
	}
	// The redirect URI in use is printed with the port actually bound.
	meta := regexp.MustCompile(`registered on the client exactly as (http://127\.0\.0\.1:\d+/oauth/callback)`).FindStringSubmatch(stderr.String())
	if meta == nil {
		t.Fatalf("the diagnostic must print the registered redirect URI:\n%s", stderr.String())
	}
	if want := RedirectURI("127.0.0.1", port); meta[1] != want {
		t.Fatalf("the diagnostic printed redirect URI %q, want %q", meta[1], want)
	}
	if !strings.Contains(stderr.String(), "the client id is correct and the client belongs to this Cloudflare account") ||
		!strings.Contains(stderr.String(), "--scopes") {
		t.Fatalf("the diagnostic must name all three causes:\n%s", stderr.String())
	}
	if n := countURLs(stderr.String()); n != 2 { // the handoff notice plus the diagnostic
		t.Fatalf("stderr has %d URL lines, want 2 (notice + diagnostic):\n%s", n, stderr.String())
	}
	if !strings.Contains(err.Error(), "timed out waiting for the OAuth callback") {
		t.Fatalf("the timeout error must be unchanged: %v", err)
	}
}

// TestLoginNoBrowserSkipsBrowserDiagnostics: the --no-browser path keeps its
// single stdout URL line and adds nothing to stderr.
func TestLoginNoBrowserSkipsBrowserDiagnostics(t *testing.T) {
	fake := newFakeOAuth(t)
	var stdout, stderr syncBuffer
	_, err := Login(context.Background(), LoginOptions{
		ClientID: "client-123", CallbackHost: "127.0.0.1", CallbackPort: freePort(t),
		OpenBrowser: false, Timeout: 300 * time.Millisecond, BrowserGrace: 50 * time.Millisecond,
		Endpoints: fake.endpoints(), Out: &stdout, ErrOut: &stderr,
	})
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if code := exitCode(err); code != 8 {
		t.Fatalf("exit code = %d, want 8 (%v)", code, err)
	}
	if n := countURLs(stdout.String()); n != 1 {
		t.Fatalf("stdout has %d URL lines, want exactly 1:\n%s", n, stdout.String())
	}
	if !strings.Contains(stdout.String(), fake.endpoints().Auth) {
		t.Fatalf("stdout must carry the authorize URL:\n%s", stdout.String())
	}
	if strings.TrimSpace(stderr.String()) != "" {
		t.Fatalf("--no-browser must not write diagnostics to stderr:\n%s", stderr.String())
	}
}

// TestLoginNoDiagnosticWhenOpenerFails: a failed handoff already puts the URL and
// the reason in front of the user, so the grace diagnostic stays silent.
func TestLoginNoDiagnosticWhenOpenerFails(t *testing.T) {
	fake := newFakeOAuth(t)
	var stdout, stderr syncBuffer
	_, err := Login(context.Background(), LoginOptions{
		ClientID: "client-123", CallbackHost: "127.0.0.1", CallbackPort: freePort(t),
		OpenBrowser: true, Timeout: 400 * time.Millisecond, BrowserGrace: 50 * time.Millisecond,
		Endpoints: fake.endpoints(), Out: &stdout, ErrOut: &stderr,
		OpenURL: func(string) error { return fmt.Errorf("no browser opener worked (xdg-open failed: not found)") },
	})
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if strings.Contains(stderr.String(), "Still waiting for the browser callback") {
		t.Fatalf("no diagnostic after a failed handoff:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "could not open a browser automatically") {
		t.Fatalf("the handoff failure must be reported:\n%s", stderr.String())
	}
	if n := countURLs(stderr.String()); n != 1 {
		t.Fatalf("stderr has %d URL lines, want exactly 1:\n%s", n, stderr.String())
	}
}

// freePort returns a port that was free a moment ago. Tests use dedicated ports
// so parallel package runs never fight over the documented default (8976).
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

// countURLs counts printed lines that start with a URL.
func countURLs(output string) int {
	n := 0
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "http") {
			n++
		}
	}
	return n
}

// TestStartOpenerNonZeroExitIsFailure pins the process seam: a quick non-zero
// exit is a failed candidate, a successful run is not.
func TestStartOpenerNonZeroExitIsFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses the POSIX shell as a stand-in opener")
	}
	if err := startOpener(browserCandidate{Name: "sh", Args: []string{"-c", "exit 3"}}, "https://example.test/"); err == nil {
		t.Fatal("a non-zero exit must report failure")
	}
	if err := startOpener(browserCandidate{Name: "sh", Args: []string{"-c", "true"}}, "https://example.test/"); err != nil {
		t.Fatalf("a successful opener must not report failure: %v", err)
	}
	if err := startOpener(browserCandidate{Name: "definitely-not-a-real-opener-xyz"}, "https://example.test/"); err == nil {
		t.Fatal("a missing opener must report failure")
	}
}

// TestBrowserCandidatesFromEnv: an explicit $BROWSER replaces the platform
// chain (arguments allowed, no shell involved).
func TestBrowserCandidatesFromEnv(t *testing.T) {
	got := browserCandidatesFor("linux", "wslview --verbose")
	if len(got) != 1 || got[0].Name != "wslview" || strings.Join(got[0].Args, " ") != "--verbose" {
		t.Fatalf("BROWSER candidate = %+v", got)
	}
	if got := browserCandidatesFor("linux", ""); len(got) != 2 || got[0].Name != "xdg-open" {
		t.Fatalf("empty BROWSER must use the platform chain: %+v", got)
	}
}

// TestLoginWithFailedOpenerTimesOutWithNetworkError: the fallback must keep the
// documented exit code (8) and print the URL exactly once.
func TestLoginWithFailedOpenerTimesOutWithNetworkError(t *testing.T) {
	fake := newFakeOAuth(t)
	var printed syncBuffer
	_, err := Login(context.Background(), LoginOptions{
		ClientID: "client-123", CallbackHost: "127.0.0.1", CallbackPort: freePort(t),
		OpenBrowser: true, Timeout: 300 * time.Millisecond,
		Endpoints: fake.endpoints(), Out: &printed,
		OpenURL: func(string) error { return fmt.Errorf("no browser opener worked (xdg-open failed: not found)") },
	})
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if code := exitCode(err); code != 8 {
		t.Fatalf("exit code = %d, want 8 (%v)", code, err)
	}
	if n := countURLs(printed.String()); n != 1 {
		t.Fatalf("printed %d URL lines, want exactly 1:\n%s", n, printed.String())
	}
	if !strings.Contains(printed.String(), "could not open a browser automatically") {
		t.Fatalf("fallback message missing:\n%s", printed.String())
	}
}

// ---- authorize preflight (rejected requests are explained in the terminal) --

// authorizeBodyServer serves a fixed body at a URL that looks like the authorize
// endpoint and records the requests it received.
type authorizeBodyServer struct {
	server   *httptest.Server
	mu       sync.Mutex
	requests []recordedAuthorizeRequest
}

type recordedAuthorizeRequest struct {
	Method string
	Path   string
	Query  url.Values
	Auth   string
}

func newAuthorizeBodyServer(t *testing.T, status int, body string) *authorizeBodyServer {
	t.Helper()
	s := &authorizeBodyServer{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests = append(s.requests, recordedAuthorizeRequest{
			Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Auth: r.Header.Get("Authorization"),
		})
		header := r.Header.Get("Accept")
		s.mu.Unlock()
		if !strings.Contains(header, "text/html") {
			t.Errorf("the preflight must look like a browser request, Accept=%q", header)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if status != 0 {
			w.WriteHeader(status)
		}
		_, _ = io.WriteString(w, body)
	})
	s.server = httptest.NewServer(handler)
	t.Cleanup(s.server.Close)
	return s
}

func (s *authorizeBodyServer) url() string { return s.server.URL + "/oauth2/auth" }

func (s *authorizeBodyServer) seen() []recordedAuthorizeRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recordedAuthorizeRequest(nil), s.requests...)
}

// TestPreflightReportsInvalidClient: Cloudflare embeds error=invalid_client in a
// JavaScript-rendered page (HTTP 200); the terminal must name the code, quote the
// description and give the fix, while the login keeps waiting.
func TestPreflightReportsInvalidClient(t *testing.T) {
	fake := newFakeOAuth(t)
	body := `<!doctype html><html><head><title>Cloudflare</title></head><body>
<div id="root"></div><script>window.__DATA__ = {"error":"invalid_client","error_description":"The requested OAuth 2.0 Client does not exist"};</script></body></html>`
	auth := newAuthorizeBodyServer(t, http.StatusOK, body)
	endpoints := fake.endpoints()
	endpoints.Auth = auth.url()

	var stdout, stderr syncBuffer
	_, err := Login(context.Background(), LoginOptions{
		ClientID: "missing-client-id", CallbackHost: "127.0.0.1", CallbackPort: freePort(t),
		OpenBrowser: true, Timeout: 400 * time.Millisecond,
		Endpoints: endpoints, Out: &stdout, ErrOut: &stderr,
		OpenURL: func(string) error { return nil },
	})
	if err == nil {
		t.Fatal("expected the login to keep waiting and time out")
	}
	if code := exitCode(err); code != 8 {
		t.Fatalf("exit code = %d, want 8 (%v)", code, err)
	}
	if strings.TrimSpace(stdout.String()) != "" {
		t.Fatalf("stdout must stay clean:\\n%s", stdout.String())
	}
	for _, want := range []string{
		"Cloudflare rejected the authorization request: invalid_client - The requested OAuth 2.0 Client does not exist",
		"the client id does not exist on this Cloudflare account",
		"Manage Account > OAuth clients",
		"set oauth_client_id in the profile",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("diagnostic missing %q:\\n%s", want, stderr.String())
		}
	}
	// The probe is a plain GET on the authorize URL, unauthenticated.
	seen := auth.seen()
	if len(seen) != 1 {
		t.Fatalf("preflight requests = %d, want 1", len(seen))
	}
	if seen[0].Method != http.MethodGet || seen[0].Path != "/oauth2/auth" {
		t.Fatalf("preflight = %s %s, want GET /oauth2/auth", seen[0].Method, seen[0].Path)
	}
	if seen[0].Query.Get("client_id") != "missing-client-id" || seen[0].Query.Get("code_challenge") == "" {
		t.Fatalf("preflight must carry the authorize query: %v", seen[0].Query)
	}
	if seen[0].Auth != "" {
		t.Fatalf("the preflight must be unauthenticated, got Authorization=%q", seen[0].Auth)
	}
}

// TestPreflightReportsInvalidScope covers the query-string form of the code and
// its scope-specific fix.
func TestPreflightReportsInvalidScope(t *testing.T) {
	fake := newFakeOAuth(t)
	auth := newAuthorizeBodyServer(t, http.StatusOK,
		`<html><body><script>window.location.hash = "error=invalid_scope&amp;error_description=The%20requested%20scopes%20are%20not%20allowed"</script></body></html>`)
	endpoints := fake.endpoints()
	endpoints.Auth = auth.url()

	var stdout, stderr syncBuffer
	_, err := Login(context.Background(), LoginOptions{
		ClientID: "client-123", CallbackHost: "127.0.0.1", CallbackPort: freePort(t),
		OpenBrowser: true, Timeout: 300 * time.Millisecond,
		Endpoints: endpoints, Out: &stdout, ErrOut: &stderr,
		OpenURL: func(string) error { return nil },
	})
	if err == nil {
		t.Fatal("expected the login to keep waiting and time out")
	}
	if !strings.Contains(stderr.String(), "Cloudflare rejected the authorization request: invalid_scope") {
		t.Fatalf("scope diagnostic missing:\\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "not registered on this OAuth client") ||
		!strings.Contains(stderr.String(), "retry with --scopes") {
		t.Fatalf("scope fix missing:\\n%s", stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "" {
		t.Fatalf("stdout must stay clean:\\n%s", stdout.String())
	}
}

// TestPreflightSilentWithoutErrorString: a healthy authorize page and a body
// without a known code produce no extra output.
func TestPreflightSilentWithoutErrorString(t *testing.T) {
	for name, body := range map[string]string{
		"clean-page":      `<!doctype html><html><body><div id="root">Sign in to continue</div></body></html>`,
		"unknown-code":    `<html><body>{"error":"temporarily_unavailable"}</body></html>`,
		"irrelevant-text": `<html><body>error logging is disabled; see the docs for details</body></html>`,
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakeOAuth(t)
			auth := newAuthorizeBodyServer(t, http.StatusOK, body)
			endpoints := fake.endpoints()
			endpoints.Auth = auth.url()

			var stdout, stderr syncBuffer
			_, err := Login(context.Background(), LoginOptions{
				ClientID: "client-123", CallbackHost: "127.0.0.1", CallbackPort: freePort(t),
				OpenBrowser: true, Timeout: 200 * time.Millisecond,
				Endpoints: endpoints, Out: &stdout, ErrOut: &stderr,
				OpenURL: func(string) error { return nil },
			})
			if err == nil {
				t.Fatal("expected the login to keep waiting and time out")
			}
			if strings.Contains(stderr.String(), "Cloudflare rejected the authorization request") {
				t.Fatalf("no diagnostic may be printed:\\n%s", stderr.String())
			}
			if strings.TrimSpace(stdout.String()) != "" {
				t.Fatalf("stdout must stay clean:\\n%s", stdout.String())
			}
		})
	}
}

// TestPreflightFailureModesAreSilent: transport errors, non-200 and empty bodies
// carry no information; the login continues unchanged and is not delayed beyond
// the bounded budget.
func TestPreflightFailureModesAreSilent(t *testing.T) {
	fake := newFakeOAuth(t)

	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedURL := closed.URL + "/oauth2/auth"
	closed.Close()

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(400 * time.Millisecond)
		_, _ = io.WriteString(w, `<html>{"error":"invalid_client"}</html>`)
	}))
	t.Cleanup(slow.Close)

	cases := []struct {
		name string
		auth string
		body string
	}{
		{"connection-refused", closedURL, ""},
		{"server-error", "", `<html>{"error":"invalid_client"}</html>`},
		{"empty-body", "", ""},
		{"slow-beyond-budget", slow.URL + "/oauth2/auth", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			endpoints := fake.endpoints()
			status := http.StatusOK
			if tc.name == "server-error" {
				status = http.StatusBadGateway
			}
			auth := newAuthorizeBodyServer(t, status, tc.body)
			endpoints.Auth = tc.auth
			if endpoints.Auth == "" {
				endpoints.Auth = auth.url()
			}
			var stdout, stderr syncBuffer
			_, err := Login(context.Background(), LoginOptions{
				ClientID: "client-123", CallbackHost: "127.0.0.1", CallbackPort: freePort(t),
				OpenBrowser: true, Timeout: 300 * time.Millisecond, PreflightTimeout: 50 * time.Millisecond,
				Endpoints: endpoints, Out: &stdout, ErrOut: &stderr,
				OpenURL: func(string) error { return nil },
			})
			if err == nil {
				t.Fatal("expected the login to keep waiting and time out")
			}
			if code := exitCode(err); code != 8 {
				t.Fatalf("exit code = %d, want 8 (%v)", code, err)
			}
			if strings.Contains(stderr.String(), "Cloudflare rejected the authorization request") {
				t.Fatalf("a failed preflight must be silent:\\n%s", stderr.String())
			}
			if strings.TrimSpace(stdout.String()) != "" {
				t.Fatalf("stdout must stay clean:\\n%s", stdout.String())
			}
		})
	}
}

// TestPreflightSkippedWithNoBrowser: the --no-browser path prints the URL to
// stdout immediately and never probes.
func TestPreflightSkippedWithNoBrowser(t *testing.T) {
	fake := newFakeOAuth(t)
	auth := newAuthorizeBodyServer(t, http.StatusOK, `<html>{"error":"invalid_client"}</html>`)
	endpoints := fake.endpoints()
	endpoints.Auth = auth.url()

	var stdout, stderr syncBuffer
	_, err := Login(context.Background(), LoginOptions{
		ClientID: "client-123", CallbackHost: "127.0.0.1", CallbackPort: freePort(t),
		OpenBrowser: false, Timeout: 200 * time.Millisecond,
		Endpoints: endpoints, Out: &stdout, ErrOut: &stderr,
	})
	if err == nil {
		t.Fatal("expected the login to keep waiting and time out")
	}
	if n := countURLs(stdout.String()); n != 1 {
		t.Fatalf("stdout must carry exactly the authorize URL, got %d:\\n%s", n, stdout.String())
	}
	if strings.TrimSpace(stderr.String()) != "" {
		t.Fatalf("--no-browser must not probe or diagnose:\\n%s", stderr.String())
	}
	if seen := auth.seen(); len(seen) != 0 {
		t.Fatalf("--no-browser must not issue a preflight request, saw %d", len(seen))
	}
}

// TestPreflightDoesNotFollowRedirects: a redirect is "not an error page", and
// following it would let the probe complete the login through the loopback
// callback (or consume the state) without the user seeing anything.
func TestPreflightDoesNotFollowRedirects(t *testing.T) {
	fake := newFakeOAuth(t)
	var targetHits int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&targetHits, 1)
		_, _ = io.WriteString(w, `<html>{"error":"invalid_client"}</html>`)
	}))
	t.Cleanup(target.Close)

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/oauth2/auth?code=leaked", http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	endpoints := fake.endpoints()
	endpoints.Auth = redirector.URL + "/oauth2/auth"

	var stdout, stderr syncBuffer
	_, err := Login(context.Background(), LoginOptions{
		ClientID: "client-123", CallbackHost: "127.0.0.1", CallbackPort: freePort(t),
		OpenBrowser: true, Timeout: 200 * time.Millisecond,
		Endpoints: endpoints, Out: &stdout, ErrOut: &stderr,
		OpenURL: func(string) error { return nil },
	})
	if err == nil {
		t.Fatal("expected the login to keep waiting and time out")
	}
	if hits := atomic.LoadInt32(&targetHits); hits != 0 {
		t.Fatalf("the preflight followed the redirect %d time(s)", hits)
	}
	if strings.Contains(stderr.String(), "Cloudflare rejected the authorization request") {
		t.Fatalf("a redirect carries no error information:\\n%s", stderr.String())
	}
}

// TestPreflightDetectsRejectedRedirect reproduces Cloudflare's live behaviour: a
// rejected authorize request answers 302 to its own error page with
// error=invalid_client in the Location header (and a tiny anchor body), while a
// successful redirect carries code/state and must stay silent.
func TestPreflightDetectsRejectedRedirect(t *testing.T) {
	fake := newFakeOAuth(t)
	const description = "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist."
	errorPage := "https://dash.cloudflare.com/oauth/error?error=invalid_client&error_description=" + url.QueryEscape(description)
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := `<a href="` + strings.ReplaceAll(errorPage, "&", "&amp;") + `">Found</a>.` + "\n"
		w.Header().Set("Location", errorPage)
		w.WriteHeader(http.StatusFound)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(auth.Close)
	endpoints := fake.endpoints()
	endpoints.Auth = auth.URL + "/oauth2/auth"

	var stdout, stderr syncBuffer
	_, err := Login(context.Background(), LoginOptions{
		ClientID: "bogus-client", CallbackHost: "127.0.0.1", CallbackPort: freePort(t),
		OpenBrowser: true, Timeout: 300 * time.Millisecond,
		Endpoints: endpoints, Out: &stdout, ErrOut: &stderr,
		OpenURL: func(string) error { return nil },
	})
	if err == nil {
		t.Fatal("expected the login to keep waiting and time out")
	}
	if code := exitCode(err); code != 8 {
		t.Fatalf("exit code = %d, want 8 (%v)", code, err)
	}
	if !strings.Contains(stderr.String(), "Cloudflare rejected the authorization request: invalid_client") {
		t.Fatalf("the redirect-shaped rejection must be reported:\\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "The requested OAuth 2.0 Client does not exist") {
		t.Fatalf("the description from the Location header is missing:\\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "does not exist on this Cloudflare account") {
		t.Fatalf("the fix is missing:\\n%s", stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "" {
		t.Fatalf("stdout must stay clean:\\n%s", stdout.String())
	}
}

// TestPreflightIgnoresSuccessfulRedirect: the happy-path redirect carries
// code/state, never an error code, so it must produce no output.
func TestPreflightIgnoresSuccessfulRedirect(t *testing.T) {
	fake := newFakeOAuth(t)
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://127.0.0.1:1/oauth/callback?code=abc&state=def")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(auth.Close)
	endpoints := fake.endpoints()
	endpoints.Auth = auth.URL + "/oauth2/auth"

	var stdout, stderr syncBuffer
	_, err := Login(context.Background(), LoginOptions{
		ClientID: "client-123", CallbackHost: "127.0.0.1", CallbackPort: freePort(t),
		OpenBrowser: true, Timeout: 200 * time.Millisecond,
		Endpoints: endpoints, Out: &stdout, ErrOut: &stderr,
		OpenURL: func(string) error { return nil },
	})
	if err == nil {
		t.Fatal("expected the login to keep waiting and time out")
	}
	if strings.Contains(stderr.String(), "Cloudflare rejected the authorization request") {
		t.Fatalf("a success redirect must stay silent:\\n%s", stderr.String())
	}
}
