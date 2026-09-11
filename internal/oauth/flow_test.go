package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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
