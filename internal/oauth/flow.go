package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/hnkNkm/flareadm/internal/errors"
)

// CallbackPath is the fixed loopback callback path. The full redirect URI
// (http://<host>:<port>/oauth/callback) must be registered on the OAuth client
// (docs/oauth.md §5 Q1).
const CallbackPath = "/oauth/callback"

// DefaultCallbackHost and DefaultCallbackPort match docs/oauth.md §6.1.
const (
	DefaultCallbackHost = "127.0.0.1"
	DefaultCallbackPort = 8976
)

// DefaultLoginTimeout bounds how long a login waits for the browser callback
// (docs/oauth.md §6.1; the same five minutes Wrangler allows for its device
// flow).
const DefaultLoginTimeout = 5 * time.Minute

// RedirectURI builds the loopback redirect URI for a host and port.
func RedirectURI(host string, port int) string {
	if host == "" {
		host = DefaultCallbackHost
	}
	if port == 0 {
		port = DefaultCallbackPort
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(port)) + CallbackPath
}

// LoginOptions configures an Authorization Code + PKCE login.
type LoginOptions struct {
	ClientID string
	Scopes   []string
	// CallbackHost/CallbackPort select the loopback listener; the resulting
	// RedirectURI must be registered on the client.
	CallbackHost string
	CallbackPort int
	// OpenBrowser opens the authorize URL when true; when false the URL is
	// written to Out once so the user can complete the flow elsewhere.
	OpenBrowser bool
	// Timeout bounds the wait for the callback. Zero means DefaultLoginTimeout.
	Timeout   time.Duration
	Endpoints Endpoints
	// Out receives the authorize URL when OpenBrowser is false.
	Out io.Writer
	// HTTPClient is used for token requests. Nil means a client with Timeout.
	HTTPClient *http.Client
	// Protect registers credential material with the runtime's scrubbing
	// before any further use (docs/oauth.md §7.4). Optional but recommended.
	Protect func(string)
	// OpenURL opens the authorize URL; nil means the platform opener.
	OpenURL func(string) error
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Listener is a test seam for the loopback listener; nil means
	// net.Listen("tcp", host:port).
	Listener net.Listener
}

// RefreshOptions configures a refresh-token grant.
type RefreshOptions struct {
	ClientID   string
	Credential Credential
	Endpoints  Endpoints
	HTTPClient *http.Client
	Protect    func(string)
	Now        func() time.Time
}

// RevokeOptions configures refresh-token revocation.
type RevokeOptions struct {
	Credential Credential
	ClientID   string
	Endpoints  Endpoints
	HTTPClient *http.Client
	Protect    func(string)
}

// tokenResponse is the token endpoint's success payload (docs/oauth.md §5 Q4).
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

// Login runs the Authorization Code + PKCE flow: it starts the loopback
// listener, hands the authorize URL to the browser (or prints it), validates
// the callback state, exchanges the code without a client secret, and returns
// the credential for the caller to store.
func Login(ctx context.Context, opts LoginOptions) (Credential, error) {
	if opts.ClientID == "" {
		return Credential{}, errors.Usage("--client-id is required (or set oauth_client_id in the profile)")
	}
	if opts.Endpoints.Auth == "" || opts.Endpoints.Token == "" {
		return Credential{}, errors.Usage("OAuth endpoints are not configured")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	protect := opts.Protect
	if protect == nil {
		protect = func(string) {}
	}

	pkce, err := NewPKCE()
	if err != nil {
		return Credential{}, errors.New(errors.CodeUnclassified, "generating PKCE values: %s", err)
	}
	state, err := NewState()
	if err != nil {
		return Credential{}, errors.New(errors.CodeUnclassified, "generating OAuth state: %s", err)
	}
	redirectURI := RedirectURI(opts.CallbackHost, opts.CallbackPort)

	listener := opts.Listener
	if listener == nil {
		ln, err := net.Listen("tcp", net.JoinHostPort(orDefault(opts.CallbackHost, DefaultCallbackHost), strconv.Itoa(orDefaultInt(opts.CallbackPort, DefaultCallbackPort))))
		if err != nil {
			return Credential{}, errors.New(errors.CodeUnclassified, "starting the OAuth callback listener on %s: %s", redirectURI, err)
		}
		listener = ln
	}
	defer func() { _ = listener.Close() }()

	authorizeURL, err := authorizeURL(opts.Endpoints.Auth, opts.ClientID, redirectURI, opts.Scopes, state, pkce.Challenge)
	if err != nil {
		return Credential{}, err
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultLoginTimeout
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	codeCh := make(chan string, 1)
	failureCh := make(chan error, 1)
	server := &http.Server{Handler: callbackHandler(state, codeCh, failureCh), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	if opts.OpenBrowser {
		opener := opts.OpenURL
		if opener == nil {
			opener = openInBrowser
		}
		if err := opener(authorizeURL); err != nil && opts.Out != nil {
			_, _ = fmt.Fprintf(opts.Out, "Could not open a browser (%v). Open this URL to continue:\n%s\n", err, authorizeURL)
		}
	} else if opts.Out != nil {
		_, _ = fmt.Fprintln(opts.Out, authorizeURL)
	}

	var code string
	select {
	case code = <-codeCh:
	case err := <-failureCh:
		return Credential{}, err
	case <-waitCtx.Done():
		return Credential{}, errors.New(errors.CodeNetwork,
			"timed out waiting for the OAuth callback on %s after %s; open this URL to finish the login:\n%s",
			redirectURI, timeout, authorizeURL)
	}
	protect(code)

	cred, err := exchangeCode(waitCtx, opts, code, redirectURI, pkce.Verifier, now, protect)
	if err != nil {
		return Credential{}, err
	}
	return cred, nil
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func orDefaultInt(v, fallback int) int {
	if v == 0 {
		return fallback
	}
	return v
}

// authorizeURL builds the authorize request (docs/oauth.md §5 Q3): PKCE S256 is
// mandatory and offline_access (plus the non-standard offline alias the server
// expects) is always requested.
func authorizeURL(base, clientID, redirectURI string, scopes []string, state, challenge string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", errors.Usage("invalid OAuth authorization URL %q: %s", base, err)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(WithOfflineScopes(scopes), " "))
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// RequiredScopes are always requested: offline_access makes the server issue a
// refresh token (docs/oauth.md §5 Q3) and the non-standard `offline` alias is
// required alongside it by Cloudflare's server (verified in the cf CLI scope
// catalog, docs/oauth.md §5 Q5). `openid` is requested for identity.
var RequiredScopes = []string{"openid", "offline", "offline_access"}

// WithOfflineScopes returns scopes with the required entries appended when
// missing, preserving the caller's order.
func WithOfflineScopes(scopes []string) []string {
	have := map[string]bool{}
	for _, s := range scopes {
		have[s] = true
	}
	out := append([]string{}, scopes...)
	for _, required := range RequiredScopes {
		if !have[required] {
			out = append(out, required)
		}
	}
	return out
}

// callbackHandler accepts exactly one callback request, forwards the code, and
// answers the browser with a short page.
func callbackHandler(state string, codeCh chan<- string, failureCh chan<- error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != CallbackPath {
			http.NotFound(w, r)
			return
		}
		query := r.URL.Query()
		if errParam := query.Get("error"); errParam != "" {
			desc := query.Get("error_description")
			msg := "the OAuth login was not completed: " + errParam
			if desc != "" {
				msg += " (" + desc + ")"
			}
			writeCallbackPage(w, "Login failed", msg)
			failureCh <- errors.New(errors.CodeAuth, "%s", msg)
			return
		}
		if got := query.Get("state"); got != state {
			writeCallbackPage(w, "Login failed", "State mismatch; the login was rejected.")
			failureCh <- errors.New(errors.CodeAuth,
				"OAuth state mismatch: the callback did not match this login attempt (possible cross-site request); no credential was stored")
			return
		}
		code := query.Get("code")
		if code == "" {
			writeCallbackPage(w, "Login failed", "No authorization code was returned.")
			failureCh <- errors.New(errors.CodeAuth, "the OAuth callback did not include an authorization code")
			return
		}
		writeCallbackPage(w, "Login complete", "You can close this tab and return to the terminal.")
		codeCh <- code
	})
}

func writeCallbackPage(w http.ResponseWriter, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "<!doctype html><html><head><title>%s</title></head><body><h1>%s</h1><p>%s</p></body></html>",
		htmlEscape(title), htmlEscape(title), htmlEscape(message))
}

func htmlEscape(s string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return replacer.Replace(s)
}

// openInBrowser launches the platform's URL opener. Failures are reported to
// the caller, which falls back to printing the URL.
func openInBrowser(target string) error {
	var name string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		name = "open"
	case "windows":
		name, args = "rundll32", []string{"url.dll,FileProtocolHandler"}
	default:
		name = "xdg-open"
	}
	args = append(args, target)
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// exchangeCode performs the token request for an authorization code. No client
// secret is sent: CLI clients are public and authenticate with PKCE
// (docs/oauth.md §5 Q1, §5 Q3).
func exchangeCode(ctx context.Context, opts LoginOptions, code, redirectURI, verifier string, now func() time.Time, protect func(string)) (Credential, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", opts.ClientID)
	form.Set("code_verifier", verifier)

	resp, err := postForm(ctx, opts.HTTPClient, opts.Endpoints.Token, form)
	if err != nil {
		return Credential{}, err
	}
	token, err := decodeTokenResponse(resp)
	if err != nil {
		return Credential{}, err
	}
	if token.AccessToken == "" {
		return Credential{}, errors.New(errors.CodeAuth, "the token endpoint returned no access token")
	}
	protect(token.AccessToken)
	protect(token.RefreshToken)
	return credentialFromToken(token, opts.ClientID, now()), nil
}

// credentialFromToken maps a token response onto the stored credential shape
// (docs/oauth.md §7.1). Scopes are space-delimited in the response.
func credentialFromToken(token tokenResponse, clientID string, at time.Time) Credential {
	cred := Credential{
		Version:      StoreVersion,
		ClientID:     clientID,
		TokenType:    orDefault(token.TokenType, "Bearer"),
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Scopes:       splitScopes(token.Scope),
		ObtainedAt:   at.UTC(),
	}
	if token.ExpiresIn > 0 {
		cred.ExpiresAt = at.Add(time.Duration(token.ExpiresIn) * time.Second).UTC()
	}
	return cred
}

func splitScopes(scope string) []string {
	if strings.TrimSpace(scope) == "" {
		return nil
	}
	return strings.Fields(scope)
}

// Refresh exchanges a stored refresh token for a fresh access token. A
// refresh_token returned by the server replaces the stored one; when the server
// omits it the previous value stays valid (RFC 6749 §6, docs/oauth.md §5 Q4).
func Refresh(ctx context.Context, opts RefreshOptions) (Credential, error) {
	if opts.Credential.RefreshToken == "" {
		return Credential{}, errors.New(errors.CodeAuth,
			"the stored OAuth credential has no refresh token; run 'flareadm auth login' to sign in again")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	protect := opts.Protect
	if protect == nil {
		protect = func(string) {}
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", opts.Credential.RefreshToken)
	if opts.ClientID != "" {
		form.Set("client_id", opts.ClientID)
	}
	resp, err := postForm(ctx, opts.HTTPClient, opts.Endpoints.Token, form)
	if err != nil {
		return Credential{}, err
	}
	token, err := decodeTokenResponse(resp)
	if err != nil {
		return Credential{}, err
	}
	if token.AccessToken == "" {
		return Credential{}, errors.New(errors.CodeAuth, "the token endpoint returned no access token")
	}
	protect(token.AccessToken)
	protect(token.RefreshToken)

	clientID := opts.Credential.ClientID
	if opts.ClientID != "" {
		clientID = opts.ClientID
	}
	next := credentialFromToken(token, clientID, now())
	if next.RefreshToken == "" {
		next.RefreshToken = opts.Credential.RefreshToken
	}
	if len(next.Scopes) == 0 {
		next.Scopes = opts.Credential.Scopes
	}
	next.AccountID = opts.Credential.AccountID
	return next, nil
}

// Revoke revokes a refresh token at the revocation endpoint (docs/oauth.md §5
// Q4). The request follows RFC 7009 conventions: form-encoded token,
// token_type_hint and client_id.
func Revoke(ctx context.Context, opts RevokeOptions) error {
	if opts.Endpoints.Revoke == "" {
		return errors.Usage("the OAuth revocation endpoint is not configured")
	}
	form := url.Values{}
	form.Set("token", opts.Credential.RefreshToken)
	form.Set("token_type_hint", "refresh_token")
	if opts.ClientID != "" {
		form.Set("client_id", opts.ClientID)
	}
	resp, err := postForm(ctx, opts.HTTPClient, opts.Endpoints.Revoke, form)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 400 {
		return errors.New(errors.CodeAuth, "the revocation endpoint rejected the request (HTTP %d)", resp.StatusCode)
	}
	return nil
}

// postForm sends an application/x-www-form-urlencoded request and returns the
// response. Transport failures map to the network exit code; OAuth error
// responses map to the authentication exit code with the server's error code.
func postForm(ctx context.Context, client *http.Client, endpoint string, form url.Values) (*http.Response, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errors.Usage("invalid OAuth endpoint %q: %s", endpoint, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New(errors.CodeNetwork, "calling the OAuth endpoint %s failed: %s", endpoint, err)
	}
	return resp, nil
}

// decodeTokenResponse reads a token endpoint response, mapping OAuth errors to
// exit code 3 with the server's error code in the message.
func decodeTokenResponse(resp *http.Response) (tokenResponse, error) {
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return tokenResponse{}, errors.New(errors.CodeNetwork, "reading the token response failed: %s", err)
	}
	if resp.StatusCode >= 400 {
		var oauthErr struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &oauthErr)
		if oauthErr.Error != "" {
			msg := "the OAuth token endpoint rejected the request: " + oauthErr.Error
			if oauthErr.Description != "" {
				msg += " (" + oauthErr.Description + ")"
			}
			return tokenResponse{}, errors.New(errors.CodeAuth, "%s", msg)
		}
		return tokenResponse{}, errors.New(errors.CodeAuth, "the OAuth token endpoint failed (HTTP %d)", resp.StatusCode)
	}
	var token tokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return tokenResponse{}, errors.New(errors.CodeAuth, "the OAuth token endpoint returned an unreadable response")
	}
	return token, nil
}
