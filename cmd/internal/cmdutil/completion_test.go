package cmdutil

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/config"
	"github.com/hnkNkm/flareadm/internal/oauth"
)

// newCompletionRuntime builds an initialized runtime over buffered streams so a
// test can prove that a completion printed nothing.
func newCompletionRuntime(t *testing.T, token string) (*app.Runtime, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("APPDATA", t.TempDir())
	for _, name := range []string{"FLAREADM_API_TOKEN", "CLOUDFLARE_API_TOKEN", "CF_API_TOKEN", "FLAREADM_PROFILE"} {
		t.Setenv(name, "")
	}
	if token != "" {
		t.Setenv("FLAREADM_API_TOKEN", token)
	}
	var out, errOut bytes.Buffer
	rt := app.NewRuntime(strings.NewReader(""), &out, &errOut)
	if err := rt.Init(); err != nil {
		t.Fatalf("runtime init: %v", err)
	}
	return rt, &out, &errOut
}

// writeConfig writes a configuration file into the runtime's config home.
func writeConfig(t *testing.T, toml string) {
	t.Helper()
	path := config.DefaultPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEnumsOffersTheValidatedSetInOrder(t *testing.T) {
	fn := Enums("on", "off")
	for _, tc := range []struct {
		toComplete string
		want       string
	}{
		{"", "on,off"},
		{"o", "on,off"},
		{"on", "on"},
		{"off", "off"},
		{"x", ""},
	} {
		got, directive := fn(nil, nil, tc.toComplete)
		if strings.Join(got, ",") != tc.want {
			t.Errorf("Enums(%q) = %v, want %q", tc.toComplete, got, tc.want)
		}
		if directive != cobra.ShellCompDirectiveNoFileComp {
			t.Errorf("Enums(%q) directive = %v, want NoFileComp", tc.toComplete, directive)
		}
	}
}

// TestProfilesCompletesConfiguredNamesLocally: the profile names come from the
// configuration file, with no credential resolved and no API call - proven by
// the fact that the completion works in a runtime whose endpoint is a server
// that fails the test when it is contacted.
func TestProfilesCompletesConfiguredNamesLocally(t *testing.T) {
	rt, out, errOut := newCompletionRuntime(t, "")
	rt.EndpointURLFlag = unreachable(t)
	writeConfig(t, "[profile.work]\naccount_id = \"acct-1\"\n\n[profile.staging]\naccount_id = \"acct-2\"\n\n[profile.bare]\n")

	got, directive := Profiles(rt)(nil, nil, "")
	if strings.Join(got, ",") != "bare,staging,work" {
		t.Fatalf("profiles = %v, want every configured name in config order", got)
	}
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("directive = %v, want NoFileComp", directive)
	}
	if out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("completion printed: stdout=%q stderr=%q", out.String(), errOut.String())
	}
}

// TestAccountIDsCompletesConfiguredIDs: only locally recorded ids are offered,
// deduplicated and in profile-name order, and a profile without one is skipped.
func TestAccountIDsCompletesConfiguredIDs(t *testing.T) {
	rt, _, _ := newCompletionRuntime(t, "")
	rt.EndpointURLFlag = unreachable(t)
	writeConfig(t, "[profile.work]\naccount_id = \"acct-2\"\n\n"+
		"[profile.staging]\naccount_id = \"acct-1\"\n\n"+
		"[profile.twin]\naccount_id = \"acct-2\"\n\n"+
		"[profile.bare]\n")

	got, directive := AccountIDs(rt)(nil, nil, "")
	if strings.Join(got, ",") != "acct-1,acct-2" {
		t.Fatalf("account ids = %v, want the distinct configured ids", got)
	}
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Fatalf("directive = %v, want NoFileComp", directive)
	}
}

func TestZoneCompletionsListsNamesThenIDs(t *testing.T) {
	rt, out, errOut := newCompletionRuntime(t, "tok")
	rt.EndpointURLFlag = zoneAPI(t, `{"success":true,"errors":[],"messages":[],"result":[
		{"id":"023e105f4ecef8ad9ca31a8372d0c353","name":"example.com","status":"active"},
		{"id":"11111111111111111111111111111111","name":"other.test","status":"active"}]}`)

	got := ZoneCompletions(context.Background(), rt, "", 5*time.Second)
	want := []string{"example.com", "other.test", "023e105f4ecef8ad9ca31a8372d0c353", "11111111111111111111111111111111"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("zones = %v, want %v", got, want)
	}
	if out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("completion printed: stdout=%q stderr=%q", out.String(), errOut.String())
	}
}

func TestZoneCompletionsFiltersByPrefix(t *testing.T) {
	rt, _, _ := newCompletionRuntime(t, "tok")
	rt.EndpointURLFlag = zoneAPI(t, `{"success":true,"errors":[],"messages":[],"result":[
		{"id":"023e105f4ecef8ad9ca31a8372d0c353","name":"example.com","status":"active"},
		{"id":"11111111111111111111111111111111","name":"other.test","status":"active"}]}`)

	got := ZoneCompletions(context.Background(), rt, "exa", 5*time.Second)
	if strings.Join(got, ",") != "example.com" {
		t.Fatalf("zones = %v, want just the matching name", got)
	}
}

// TestZoneCompletionsIsSilentWhenTheAPIFails: a rejected request yields no
// candidates, prints nothing, and never reports an error - the shell must fall
// back to "no suggestions" instead of showing an API failure while a prompt is
// open.
func TestZoneCompletionsIsSilentWhenTheAPIFails(t *testing.T) {
	rt, out, errOut := newCompletionRuntime(t, "tok")
	rt.EndpointURLFlag = zoneAPIStatus(t, http.StatusInternalServerError)

	start := time.Now()
	got := ZoneCompletions(context.Background(), rt, "", 5*time.Second)
	if len(got) != 0 {
		t.Fatalf("zones = %v, want none", got)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("a failed completion took %s, want an immediate answer", elapsed)
	}
	if out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("completion printed: stdout=%q stderr=%q", out.String(), errOut.String())
	}
}

// TestZoneCompletionsWithoutCredentialIsSilentAndOffline: with no credential
// the completion must not even try the API.
func TestZoneCompletionsWithoutCredentialIsSilentAndOffline(t *testing.T) {
	rt, out, errOut := newCompletionRuntime(t, "")
	called := false
	rt.EndpointURLFlag = zoneAPIWith(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	if got := ZoneCompletions(context.Background(), rt, "", 5*time.Second); len(got) != 0 {
		t.Fatalf("zones = %v, want none without a credential", got)
	}
	if called {
		t.Fatal("the API was called without a credential")
	}
	if out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("completion printed: stdout=%q stderr=%q", out.String(), errOut.String())
	}
}

// TestZoneCompletionsHonoursTheBudget: a server that never answers must not hold
// the shell. The budget is the whole call, so the test uses a short one instead
// of sleeping.
func TestZoneCompletionsHonoursTheBudget(t *testing.T) {
	rt, out, errOut := newCompletionRuntime(t, "tok")
	// The handler is released by the deferred close, which runs before the
	// server's own Close cleanup: httptest waits for in-flight handlers, so the
	// release must not be registered as an earlier cleanup.
	release := make(chan struct{})
	defer close(release)
	rt.EndpointURLFlag = zoneAPIWith(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})

	start := time.Now()
	got := ZoneCompletions(context.Background(), rt, "", 40*time.Millisecond)
	elapsed := time.Since(start)
	if len(got) != 0 {
		t.Fatalf("zones = %v, want none after the budget expired", got)
	}
	if elapsed > time.Second {
		t.Fatalf("completion waited %s, want it bounded by the budget", elapsed)
	}
	if out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("completion printed: stdout=%q stderr=%q", out.String(), errOut.String())
	}
}

// TestZoneCompletionsBudgetCoversACredentialRefresh: resolving an expired OAuth
// credential refreshes it with a timeout of its own (--timeout, 30s by
// default), so the budget must bound the whole call, not just the listing.
func TestZoneCompletionsBudgetCoversACredentialRefresh(t *testing.T) {
	rt, out, errOut := newCompletionRuntime(t, "")
	// See TestZoneCompletionsHonoursTheBudget: the refresh this test starts is
	// deliberately abandoned, so its handler must be released before the test
	// server is closed.
	release := make(chan struct{})
	defer close(release)
	tokenURL := zoneAPIWith(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	rt.EndpointURLFlag = tokenURL
	t.Setenv("FLAREADM_OAUTH_TOKEN_URL", tokenURL)
	store := rt.OAuthStore()
	if err := store.Save("default", oauth.Credential{
		Version:      1,
		AccessToken:  "expired-access",
		RefreshToken: "refresh-me",
		ExpiresAt:    time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("store credential: %v", err)
	}

	start := time.Now()
	got := ZoneCompletions(context.Background(), rt, "", 40*time.Millisecond)
	elapsed := time.Since(start)
	if len(got) != 0 {
		t.Fatalf("zones = %v, want none while the refresh hangs", got)
	}
	if elapsed > time.Second {
		t.Fatalf("completion waited %s for a hanging credential refresh, want it bounded", elapsed)
	}
	if out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("completion printed: stdout=%q stderr=%q", out.String(), errOut.String())
	}
}

// unreachable returns an endpoint URL whose server fails the test when it is
// contacted.
func unreachable(t *testing.T) string {
	t.Helper()
	return zoneAPIWith(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected API call: %s %s", r.Method, r.URL.Path)
	})
}

// zoneAPI serves a fixed body at /zones.
func zoneAPI(t *testing.T, body string) string {
	t.Helper()
	return zoneAPIWith(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/zones" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	})
}

// zoneAPIStatus serves an empty envelope with the given status.
func zoneAPIStatus(t *testing.T, status int) string {
	t.Helper()
	return zoneAPIWith(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":1000,"message":"nope"}],"messages":[],"result":null}`)
	})
}

func zoneAPIWith(t *testing.T, handle http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewServer(handle)
	t.Cleanup(srv.Close)
	return srv.URL
}
