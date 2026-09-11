package oauth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// newStoreDir points the process at a temporary configuration home and returns
// a store rooted under it, mirroring how the CLI resolves the credential
// directory (docs/oauth.md §7.1).
func newStoreDir(t *testing.T) Store {
	t.Helper()
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("APPDATA", home)
	return Store{Dir: filepath.Join(home, "flareadm", "oauth")}
}

func sampleCredential() Credential {
	return Credential{
		ClientID:     "client-123",
		AccessToken:  "access-secret-value",
		RefreshToken: "refresh-secret-value",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		Scopes:       []string{"openid", "account:read"},
		ObtainedAt:   time.Now().UTC().Truncate(time.Second),
	}
}

func TestStoreRoundTripAndPermissions(t *testing.T) {
	store := newStoreDir(t)
	cred := sampleCredential()
	if err := store.Save("work", cred); err != nil {
		t.Fatalf("save: %v", err)
	}

	// The file carries the version field and both tokens.
	raw, err := os.ReadFile(store.Path("work"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("credential is not JSON: %v", err)
	}
	if decoded["version"] != float64(StoreVersion) {
		t.Fatalf("version = %v, want %d", decoded["version"], StoreVersion)
	}
	if decoded["refresh_token"] != "refresh-secret-value" {
		t.Fatalf("refresh token not stored: %v", decoded["refresh_token"])
	}

	loaded, ok, err := store.Load("work")
	if err != nil || !ok {
		t.Fatalf("load: ok=%v err=%v", ok, err)
	}
	if loaded.AccessToken != cred.AccessToken || loaded.RefreshToken != cred.RefreshToken {
		t.Fatalf("loaded credential mismatch: %+v", loaded)
	}
	if loaded.ClientID != "client-123" || len(loaded.Scopes) != 2 {
		t.Fatalf("loaded metadata mismatch: %+v", loaded)
	}

	if runtime.GOOS != "windows" {
		dirInfo, err := os.Stat(store.Dir)
		if err != nil {
			t.Fatal(err)
		}
		if perm := dirInfo.Mode().Perm(); perm != 0o700 {
			t.Fatalf("credential directory mode = %o, want 700", perm)
		}
		fileInfo, err := os.Stat(store.Path("work"))
		if err != nil {
			t.Fatal(err)
		}
		if perm := fileInfo.Mode().Perm(); perm != 0o600 {
			t.Fatalf("credential file mode = %o, want 600", perm)
		}
	}

	// Deletion is idempotent.
	if err := store.Delete("work"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := store.Delete("work"); err != nil {
		t.Fatalf("second delete: %v", err)
	}
	if _, ok, err := store.Load("work"); err != nil || ok {
		t.Fatalf("credential still present after delete: ok=%v err=%v", ok, err)
	}
}

func TestStoreMissingAndUnsupportedVersion(t *testing.T) {
	store := newStoreDir(t)
	if _, ok, err := store.Load("nobody"); err != nil || ok {
		t.Fatalf("missing credential: ok=%v err=%v", ok, err)
	}

	if err := os.MkdirAll(store.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.Path("future"), []byte(`{"version":99,"access_token":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load("future"); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("want a version error, got %v", err)
	}
}

func TestStoreRejectsUnsafeProfileNames(t *testing.T) {
	store := newStoreDir(t)
	for _, name := range []string{"", ".", "..", "../escape", "a/b", `a\b`, "with space"} {
		if err := store.Save(name, sampleCredential()); err == nil {
			t.Fatalf("profile %q should be rejected", name)
		}
		if _, _, err := store.Load(name); err == nil {
			t.Fatalf("load %q should be rejected", name)
		}
	}
}

// TestStorePathFollowsConfigHome pins the location contract: the credential
// lives in <config dir>/oauth/<profile>.json on every platform, so the Windows
// %APPDATA% behaviour comes from the shared path resolver (docs/oauth.md §7.1).
func TestStorePathFollowsConfigHome(t *testing.T) {
	store := newStoreDir(t)
	home := os.Getenv("XDG_CONFIG_HOME")
	want := filepath.Join(home, "flareadm", "oauth", "work.json")
	if got := store.Path("work"); got != want {
		t.Fatalf("Path = %q, want %q", got, want)
	}
}

func TestStoreUnwritableDirectoryFailsLoudly(t *testing.T) {
	home := t.TempDir()
	blocker := filepath.Join(home, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := Store{Dir: filepath.Join(blocker, "oauth")}
	err := store.Save("work", sampleCredential())
	if err == nil {
		t.Fatal("saving into an uncreatable directory should fail")
	}
	if !strings.Contains(err.Error(), store.Dir) {
		t.Fatalf("error should name the directory: %v", err)
	}
}

func TestCredentialExpiryWindow(t *testing.T) {
	now := time.Now()
	cred := sampleCredential()
	cred.ExpiresAt = now.Add(4 * time.Minute)
	if !cred.Expired(now) {
		t.Fatal("a credential expiring inside the window must refresh proactively")
	}
	cred.ExpiresAt = now.Add(30 * time.Minute)
	if cred.Expired(now) {
		t.Fatal("a fresh credential must not refresh")
	}
	cred.ExpiresAt = time.Time{}
	if cred.Expired(now) {
		t.Fatal("an unknown expiry must not force a refresh")
	}
}
