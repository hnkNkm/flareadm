package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
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
	// Out receives the authorize URL when OpenBrowser is false, and is the only
	// stream that ever carries it (stdout stays machine-readable).
	Out io.Writer
	// ErrOut receives the browser handoff notice and the one-time diagnostic
	// explaining a blank or failing authorize page. Nil falls back to Out, so a
	// handoff is never silent.
	ErrOut io.Writer
	// BrowserGrace overrides browserGrace, the delay before the diagnostic is
	// repeated; tests set it small.
	BrowserGrace time.Duration
	// PreflightTimeout overrides preflightTimeout, the budget for the
	// unauthenticated probe of the authorize URL; tests set it small.
	PreflightTimeout time.Duration
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
	fc := failureContext{Stage: "authorization request", Scopes: WithOfflineScopes(opts.Scopes), RedirectURI: redirectURI, ClientID: opts.ClientID}
	server := &http.Server{Handler: callbackHandler(state, fc, codeCh, failureCh), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	errOut := opts.ErrOut
	if errOut == nil {
		errOut = opts.Out
	}
	browserOpened := false
	if opts.OpenBrowser {
		opener := opts.OpenURL
		if opener == nil {
			opener = openInBrowser
		}
		// The URL is always shown, on stderr, before the handoff: an opened
		// browser window may render nothing, and the user still needs the URL
		// to copy. stdout is left clean for machine-readable use.
		if errOut != nil {
			_, _ = fmt.Fprintf(errOut, "%s\n%s\n", browserURLNotice, authorizeURL)
		}
		// Opening a browser is best effort: a missing or failing opener must
		// never break the login, so the failure is reported (the URL was just
		// printed above) and the flow keeps waiting for the loopback callback
		// until the timeout.
		if err := opener(authorizeURL); err != nil {
			if errOut != nil {
				_, _ = fmt.Fprintf(errOut, "could not open a browser automatically (%v); use the URL above.\n", err)
			}
		} else {
			browserOpened = true
		}
	} else if opts.Out != nil {
		_, _ = fmt.Fprintln(opts.Out, authorizeURL)
	}

	// The diagnostic is armed only when a browser was actually handed the URL:
	// with --no-browser the URL is the command's stdout output, and after a
	// failed handoff the user is already looking at the URL and the error.
	var graceCh <-chan time.Time
	if browserOpened && errOut != nil {
		grace := opts.BrowserGrace
		if grace <= 0 {
			grace = browserGrace
		}
		timer := time.NewTimer(grace)
		defer timer.Stop()
		graceCh = timer.C
	}

	// Best-effort preflight: the same unauthenticated GET the browser makes, so
	// a rejected authorization request (which renders as a blank page in the
	// browser) is explained here instead. It is advisory only: no information,
	// no output, and the login keeps waiting either way.
	if opts.OpenBrowser && errOut != nil {
		client := opts.HTTPClient
		if client == nil {
			// The probe must never follow a redirect: a redirect means "not an
			// error page", and following it could complete the flow through the
			// loopback callback (or consume the state) behind the user's back.
			client = &http.Client{
				Timeout:       preflightTimeout,
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			}
		}
		if code, description, ok := preflightAuthorize(waitCtx, client, authorizeURL, opts.PreflightTimeout); ok {
			_, _ = fmt.Fprintln(errOut, authorizeErrorDiagnostic(code, description))
		}
	}

	var code string
	for code == "" {
		select {
		case code = <-codeCh:
		case err := <-failureCh:
			return Credential{}, err
		case <-graceCh:
			// Fires at most once: the timer is never reset, so the channel is
			// nil from here on and the login keeps waiting until --timeout.
			graceCh = nil
			_, _ = fmt.Fprintln(errOut, browserDiagnostic(redirectURI, authorizeURL))
		case <-waitCtx.Done():
			return Credential{}, errors.New(errors.CodeNetwork,
				"timed out waiting for the OAuth callback on %s after %s; open this URL to finish the login:\n%s",
				redirectURI, timeout, authorizeURL)
		}
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

// RequiredScopes are always requested, and `offline_access` is the only one:
//
//   - Cloudflare answers an authorize request for this client type with
//     HTTP 303 to the loopback callback carrying
//     `error=invalid_scope` ("The OAuth 2.0 Client is not allowed to request
//     scope 'openid'") when `openid` or `offline` is present. Neither is in the
//     live `GET /oauth/scopes` list (neither is an id at all), so they must not
//     be requested. Verified against the real authorize endpoint.
//   - `offline_access` is what makes the server issue a refresh token, and it
//     must accompany the `refresh_token` grant.
//   - The CLI's identity call (GET /user) is authorized by the
//     `user-details.read` API permission, not by the OIDC `openid` scope.
var RequiredScopes = []string{"offline_access"}

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

// failureContext describes the request an OAuth error came from, so the
// remediation can name the concrete values the user has to compare (a scope
// list, the redirect URI) instead of generic advice.
type failureContext struct {
	Stage       string
	Scopes      []string
	RedirectURI string
	ClientID    string
}

// ScopeExample is the explicit --scopes list the invalid_scope remediation
// suggests. It must contain live ids: the --scopes validator rejects the pre-0.4
// colon form, so an example like account:read,zone:read would send the user
// straight into a usage error. cmd/auth's
// TestScopeRemediationExampleIsValidatable and this package's
// TestInvalidScopeRemediationUsesLiveScopeExample keep the two sides in step.
const ScopeExample = "zone.read,dns.read"

// oauthFailure renders an actionable exit-3 error for an OAuth error response:
// the error code and Cloudflare's description are always included, followed by
// a remediation chosen per code. Scope problems point at --scopes; client and
// redirect problems name the redirect URI and never mention --scopes.
func oauthFailure(fc failureContext, code, description, uri string) error {
	var b strings.Builder
	stage := fc.Stage
	if stage == "" {
		stage = "request"
	}
	fmt.Fprintf(&b, "OAuth %s was rejected: %s", stage, code)
	if description != "" {
		fmt.Fprintf(&b, " — %s", description)
	}
	if uri != "" {
		fmt.Fprintf(&b, " (see %s)", uri)
	}
	b.WriteString("\n")
	switch code {
	case "invalid_scope":
		b.WriteString("the requested scope set was not accepted")
		if len(fc.Scopes) > 0 {
			fmt.Fprintf(&b, " (requested: %s)", strings.Join(fc.Scopes, " "))
		}
		b.WriteString(". Retry with an explicit list, for example 'flareadm auth login --scopes " + ScopeExample +
			"', and check which scopes the client is registered for in the Cloudflare dashboard (Manage Account > OAuth clients).")
	case "unauthorized_client", "invalid_client":
		b.WriteString("the client was rejected")
		if fc.RedirectURI != "" {
			fmt.Fprintf(&b, "; this login used the redirect URI %s", fc.RedirectURI)
		}
		b.WriteString(". Check --client-id (and the profile's oauth_client_id) and compare the redirect URI above with the client's registered redirect URL in the Cloudflare dashboard (Manage Account > OAuth clients).")
	case "invalid_request":
		b.WriteString("the request was rejected as malformed")
		if fc.RedirectURI != "" {
			fmt.Fprintf(&b, "; this login used the redirect URI %s", fc.RedirectURI)
		}
		b.WriteString(". A redirect URI that does not match the registered one causes this; compare it with the client's registered redirect URL in the Cloudflare dashboard (Manage Account > OAuth clients).")
	case "invalid_grant":
		b.WriteString("the authorization code or refresh token was rejected; both are single use and short lived. Run 'flareadm auth login' again to start a fresh login.")
	case "access_denied":
		b.WriteString("the consent screen was declined, or the client is not authorized for this account; a private client can only be authorized by members of its parent Cloudflare account. Re-run 'flareadm auth login' to try again.")
	default:
		if fc.RedirectURI != "" {
			fmt.Fprintf(&b, "this login used the redirect URI %s and client id %s; compare both with the client's registration in the Cloudflare dashboard (Manage Account > OAuth clients), then run 'flareadm auth login' again.",
				fc.RedirectURI, orDefault(fc.ClientID, "(unset)"))
		} else {
			b.WriteString("run 'flareadm auth login' again; if it persists, check the OAuth client registration in the Cloudflare dashboard (Manage Account > OAuth clients).")
		}
	}
	return errors.New(errors.CodeAuth, "%s", b.String())
}

// callbackHandler accepts exactly one callback request, forwards the code, and
// answers the browser with a short page.
func callbackHandler(state string, fc failureContext, codeCh chan<- string, failureCh chan<- error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != CallbackPath {
			http.NotFound(w, r)
			return
		}
		query := r.URL.Query()
		if errParam := query.Get("error"); errParam != "" {
			msg := oauthFailure(fc, errParam, query.Get("error_description"), query.Get("error_uri"))
			writeCallbackPage(w, "Login failed", msg.Error())
			failureCh <- msg
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
			failureCh <- errors.New(errors.CodeAuth,
				"the OAuth callback did not include an authorization code, so the login was not completed\nrun 'flareadm auth login' again to retry")
			return
		}
		writeCallbackPage(w, "Login complete", "You can close this tab and return to the terminal.")
		codeCh <- code
	})
}

// writeCallbackPage answers the browser and flushes immediately: the login
// goroutine closes the listener as soon as it has the code or the failure, so
// an unflushed response would be cut off (the browser would see EOF).
func writeCallbackPage(w http.ResponseWriter, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "<!doctype html><html><head><title>%s</title></head><body><h1>%s</h1><p>%s</p></body></html>",
		htmlEscape(title), htmlEscape(title), htmlEscape(message))
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

func htmlEscape(s string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return replacer.Replace(s)
}

// browserGrace is how long the login waits, after handing the URL to a browser,
// before repeating the URL with troubleshooting hints. Long enough that a
// browser which really opened the page is not nagged, short enough that a user
// staring at a blank tab learns something useful without waiting out --timeout.
const browserGrace = 15 * time.Second

// browserURLNotice labels the URL written to stderr before a browser handoff. It
// exists because the browser window may stay blank, and the user must still be
// able to see and copy the URL. stdout stays machine-readable: it carries the
// URL only with --no-browser.
const browserURLNotice = "Opening this URL in your browser (use --no-browser to print it and complete the login elsewhere):"

// browserDiagnostic is the one-time hint printed when no callback arrived within
// browserGrace. The bullet points are the causes that actually produce a blank
// or failing authorize page.
func browserDiagnostic(redirectURI, authorizeURL string) string {
	return fmt.Sprintf(`Still waiting for the browser callback on %s. If the page is blank or the login did not finish, check that:
  - the client id is correct and the client belongs to this Cloudflare account;
  - the redirect URI is registered on the client exactly as %s;
  - the requested scopes are registered on the client (pass --scopes for an explicit list).
Open this URL manually if needed:
%s`, redirectURI, redirectURI, authorizeURL)
}

// preflightTimeout bounds the unauthenticated probe of the authorize URL. The
// probe exists so a rejected authorization request (a blank JavaScript-rendered
// page in the browser) is explained in the terminal instead. It is advisory and
// strictly bounded: the login never waits on it longer than this.
const preflightTimeout = 10 * time.Second

// preflightBodyLimit caps how much of the authorize response is scanned. The
// known rejection pages are ~23 KB; a page larger than this is truncated, which
// only makes detection less likely, never wrong.
const preflightBodyLimit = 256 << 10

// authorizeErrorCodes are the rejection codes Cloudflare embeds in the
// authorize page, in the forms `error=invalid_client`, `"error":"invalid_client"`
// and as bare strings inside the JavaScript shell.
var authorizeErrorCodes = []string{"invalid_client", "invalid_scope", "unauthorized_client", "invalid_request"}

// authorizeErrorCodePatterns matches a known code as a whole word, used when the
// page embeds the code without an `error=` assignment.
var authorizeErrorCodePatterns = func() map[string]*regexp.Regexp {
	patterns := make(map[string]*regexp.Regexp, len(authorizeErrorCodes))
	for _, code := range authorizeErrorCodes {
		patterns[code] = regexp.MustCompile(`\b` + code + `\b`)
	}
	return patterns
}()

// authorizeErrorHints is the concrete fix printed for each rejection code.
var authorizeErrorHints = map[string]string{
	"invalid_client": "  - the client id does not exist on this Cloudflare account;\n" +
		"  - verify it in the dashboard under Manage Account > OAuth clients;\n" +
		"  - or set oauth_client_id in the profile.",
	"invalid_scope": "  - the requested scopes are not registered on this OAuth client;\n" +
		"  - retry with --scopes, listing only scopes the client may request.",
	"unauthorized_client": "  - this OAuth client is not allowed to use the authorization code flow;\n" +
		"  - check its configuration in the dashboard under Manage Account > OAuth clients.",
	"invalid_request": "  - the authorization request was rejected as malformed;\n" +
		"  - retry with the documented --callback-host/--callback-port and --scopes values.",
}

// authorizeErrorPattern matches the shapes Cloudflare uses for the error code:
// `error=invalid_client`, `"error": "invalid_client"`, `error: 'invalid_client'`.
var authorizeErrorPattern = regexp.MustCompile(`(?i)\berror\b["']?\s*[:=]\s*["']?([a-z_]{3,40})`)

// authorizeErrorDescriptionPattern matches the human-readable description that
// accompanies the code, in JSON or query-string form.
var authorizeErrorDescriptionPattern = regexp.MustCompile(`(?i)\berror_description\b["']?\s*[:=]\s*["']?([^"'&<>\n]{1,300})`)

// detectAuthorizeError looks for a rejection code in an authorize response body.
// It reports false unless a known code is found: an empty, truncated or
// unfamiliar body simply carries no information.
func detectAuthorizeError(body []byte) (code, description string, ok bool) {
	text := string(body)
	found := false
	if m := authorizeErrorPattern.FindStringSubmatch(text); m != nil {
		candidate := strings.ToLower(m[1])
		for _, known := range authorizeErrorCodes {
			if candidate == known {
				code, found = known, true
			}
		}
		if !found {
			// A code we do not have a fix for: report nothing rather than guess.
			return "", "", false
		}
	} else if strings.Contains(strings.ToLower(text), "error") {
		// The JavaScript shell may embed the code as a bare string without an
		// `error=` assignment; only treat it as an error when the page mentions
		// errors at all.
		for _, known := range authorizeErrorCodes {
			if authorizeErrorCodePatterns[known].MatchString(text) {
				code, found = known, true
				break
			}
		}
		if !found {
			return "", "", false
		}
	}
	if !found {
		// Neither shape appeared: the page carries no information.
		return "", "", false
	}
	if m := authorizeErrorDescriptionPattern.FindStringSubmatch(text); m != nil {
		description = cleanAuthorizeDescription(m[1])
	}
	return code, description, true
}

// cleanAuthorizeDescription normalises the human-readable text Cloudflare embeds:
// HTML entities, percent-encoding and JavaScript escaping are undone when they
// decode cleanly, and the raw value is kept otherwise.
func cleanAuthorizeDescription(raw string) string {
	text := html.UnescapeString(strings.TrimSpace(raw))
	if decoded, err := url.QueryUnescape(text); err == nil {
		text = decoded
	}
	return strings.TrimSpace(strings.TrimRight(text, "\\\"'"))
}

// authorizeErrorDiagnostic renders the operator-facing explanation of a
// rejected authorization request.
func authorizeErrorDiagnostic(code, description string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Cloudflare rejected the authorization request: %s", code)
	if description != "" {
		fmt.Fprintf(&b, " - %s", description)
	}
	b.WriteString("\n")
	b.WriteString(authorizeErrorHints[code])
	return b.String()
}

// preflightAuthorize issues the same unauthenticated GET a browser would and
// reports the rejection Cloudflare embedded in the response, if any. Every
// failure mode (transport error, non-200, empty or unrecognised body) means "no
// information": the caller prints nothing and the login continues.
func preflightAuthorize(ctx context.Context, client *http.Client, authorizeURL string, budget time.Duration) (code, description string, ok bool) {
	if budget <= 0 {
		budget = preflightTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, authorizeURL, nil)
	if err != nil {
		return "", "", false
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		// A rejected request is not always a 200 page: Cloudflare today answers a
		// bad client id with a 302 to its own error page, carrying
		// `error=invalid_client&error_description=...` in the Location header (and
		// in the tiny anchor body). Without this the login stays silent and the
		// user is back to a stalled handoff, so the same strict code matching is
		// applied to the Location and to that body. A success redirect carries
		// `code=...&state=...` and cannot match.
		if code, description, ok := detectAuthorizeError([]byte(resp.Header.Get("Location"))); ok {
			return code, description, true
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, preflightBodyLimit))
		if err != nil || len(body) == 0 {
			return "", "", false
		}
		return detectAuthorizeError(body)
	}
	if resp.StatusCode != http.StatusOK {
		// Any other status is an intermediary or gateway page: no information.
		return "", "", false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, preflightBodyLimit))
	if err != nil || len(body) == 0 {
		return "", "", false
	}
	return detectAuthorizeError(body)
}

// browserCandidate is one way to open a URL on a platform. The URL is always
// appended as an argument: nothing is ever passed through a shell, so a URL
// containing shell metacharacters cannot be interpreted.
type browserCandidate struct {
	Name string
	Args []string
}

// browserCandidates lists the openers to try, in order, for a GOOS.
//
//   - darwin: `open` (the documented URL opener).
//   - windows: rundll32 with url.dll,FileProtocolHandler, which Microsoft
//     documents for opening a protocol/URL. `cmd /c start` is deliberately not
//     used: it needs a shell and hand-built quoting.
//   - everything else: `xdg-open` (freedesktop), then `wslview` (wslu), which is
//     what a WSL distribution without WSLg has available.
func browserCandidates(goos string) []browserCandidate {
	switch goos {
	case "darwin":
		return []browserCandidate{{Name: "open"}}
	case "windows":
		return []browserCandidate{{Name: "rundll32", Args: []string{"url.dll,FileProtocolHandler"}}}
	default:
		return []browserCandidate{{Name: "xdg-open"}, {Name: "wslview"}}
	}
}

// openerGrace bounds how long a freshly started opener is watched for an
// immediate failure. An opener still running after the grace period is assumed
// to be working and is left in the background, so the login never blocks on it.
const openerGrace = 3 * time.Second

// startOpener is the process seam: it starts one candidate and reports whether
// it looks like it worked (a start failure or a quick non-zero exit means it
// did not). Tests replace it to exercise the fallbacks deterministically.
var startOpener = func(candidate browserCandidate, target string) error {
	args := append(append([]string{}, candidate.Args...), target)
	cmd := exec.Command(candidate.Name, args...)
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("%s failed: %w", candidate.Name, err)
		}
		return nil
	case <-time.After(openerGrace):
		// Still running: assume it opened something. Do not wait for it.
		return nil
	}
}

// browserCandidatesFor resolves the openers to try: an explicit $BROWSER wins
// (the conventional override, and the reason WSL and headless users can point
// the CLI at wslview or a custom script), otherwise the platform chain is used.
// A $BROWSER value may carry arguments, split on whitespace; nothing is passed
// through a shell.
func browserCandidatesFor(goos, browserEnv string) []browserCandidate {
	if fields := strings.Fields(browserEnv); len(fields) > 0 {
		return []browserCandidate{{Name: fields[0], Args: fields[1:]}}
	}
	return browserCandidates(goos)
}

// openInBrowser tries each opener in order and reports an error only when every
// candidate failed, so the caller can print the URL instead of failing the
// login.
func openInBrowser(target string) error {
	var failures []string
	for _, candidate := range browserCandidatesFor(runtime.GOOS, os.Getenv("BROWSER")) {
		if err := startOpener(candidate, target); err != nil {
			failures = append(failures, err.Error())
			continue
		}
		return nil
	}
	return fmt.Errorf("no browser opener worked (%s)", strings.Join(failures, "; "))
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
	fc := failureContext{Stage: "token request", Scopes: WithOfflineScopes(opts.Scopes), RedirectURI: redirectURI, ClientID: opts.ClientID}
	token, err := decodeTokenResponse(resp, fc)
	if err != nil {
		return Credential{}, err
	}
	if token.AccessToken == "" {
		return Credential{}, errors.New(errors.CodeAuth,
			"the OAuth token request returned no access token\nrun 'flareadm auth login' again; if it persists, check the OAuth client registration in the Cloudflare dashboard (Manage Account > OAuth clients)")
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
	token, err := decodeTokenResponse(resp, failureContext{Stage: "refresh request", Scopes: opts.Credential.Scopes, ClientID: opts.ClientID})
	if err != nil {
		return Credential{}, err
	}
	if token.AccessToken == "" {
		return Credential{}, errors.New(errors.CodeAuth,
			"the OAuth refresh returned no access token\nrun 'flareadm auth login' again to sign in")
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
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		var oauthErr struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
			URI         string `json:"error_uri"`
		}
		_ = json.Unmarshal(body, &oauthErr)
		if oauthErr.Error != "" {
			return oauthFailure(failureContext{Stage: "revocation request"}, oauthErr.Error, oauthErr.Description, oauthErr.URI)
		}
		return errors.New(errors.CodeAuth,
			"the OAuth revocation request failed with HTTP %d\nretry 'flareadm auth logout'; if it persists the credential may already be revoked, in which case retry with --local",
			resp.StatusCode)
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
func decodeTokenResponse(resp *http.Response, fc failureContext) (tokenResponse, error) {
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return tokenResponse{}, errors.New(errors.CodeNetwork, "reading the token response failed: %s", err)
	}
	if resp.StatusCode >= 400 {
		var oauthErr struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
			URI         string `json:"error_uri"`
		}
		_ = json.Unmarshal(body, &oauthErr)
		if oauthErr.Error != "" {
			return tokenResponse{}, oauthFailure(fc, oauthErr.Error, oauthErr.Description, oauthErr.URI)
		}
		stage := fc.Stage
		if stage == "" {
			stage = "token request"
		}
		msg := fmt.Sprintf("the OAuth %s failed with HTTP %d and no error code", stage, resp.StatusCode)
		if fc.RedirectURI != "" {
			msg += fmt.Sprintf("\nthis login used the redirect URI %s; compare it with the client's registered redirect URL (Cloudflare dashboard: Manage Account > OAuth clients)", fc.RedirectURI)
		}
		return tokenResponse{}, errors.New(errors.CodeAuth, "%s", msg)
	}
	var token tokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return tokenResponse{}, errors.New(errors.CodeAuth, "the OAuth token endpoint returned an unreadable response")
	}
	return token, nil
}
