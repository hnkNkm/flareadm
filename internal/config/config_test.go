package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeEnv(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDefaultPathXDG(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix path logic")
	}
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg-test")
	got := DefaultPath()
	want := filepath.Join("/tmp/xdg-test", "flareadm", "config.toml")
	if got != want {
		t.Fatalf("DefaultPath() = %q, want %q", got, want)
	}
}

func TestDefaultPathHomeFallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix path logic")
	}
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "/home/testuser")
	got := DefaultPath()
	want := filepath.Join("/home/testuser", ".config", "flareadm", "config.toml")
	if got != want {
		t.Fatalf("DefaultPath() = %q, want %q", got, want)
	}
}

func TestDefaultPathAPPDATA(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows path logic")
	}
	t.Setenv("APPDATA", `C:\Users\test\AppData\Roaming`)
	got := DefaultPath()
	want := filepath.Join(`C:\Users\test\AppData\Roaming`, "flareadm", "config.toml")
	if got != want {
		t.Fatalf("DefaultPath() = %q, want %q", got, want)
	}
}

func TestLoadMissingFile(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nope", "config.toml"))
	if err != nil {
		t.Fatalf("Load(missing) error: %v", err)
	}
	if !cfg.Empty() {
		t.Fatal("missing file should yield an empty config")
	}
}

func TestLoadSaveRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flareadm", "config.toml")
	writeEnv(t, path, `
[profile.default]
account_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
api_token_env = "CLOUDFLARE_API_TOKEN"

[profile.personal]
account_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
api_token_env = "CF_PERSONAL_TOKEN"
default_zone = "example.com"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Names(); len(got) != 2 || got[0] != "default" || got[1] != "personal" {
		t.Fatalf("Names() = %v", got)
	}
	p, ok := cfg.Profile("personal")
	if !ok {
		t.Fatal("personal profile missing")
	}
	if p.AccountID != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" || p.APITokenEnv != "CF_PERSONAL_TOKEN" || p.DefaultZone != "example.com" {
		t.Fatalf("personal = %+v", p)
	}
	// Set/delete mutations.
	cfg.Set("work", Profile{AccountID: "cccccccccccccccccccccccccccccccc"})
	if !cfg.Delete("default") {
		t.Fatal("delete default should report true")
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Round-trip through a fresh load; output must be deterministic.
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := reloaded.Names(); len(got) != 2 || got[0] != "personal" || got[1] != "work" {
		t.Fatalf("reloaded Names() = %v", got)
	}
	w, ok := reloaded.Profile("work")
	if !ok || w.AccountID != "cccccccccccccccccccccccccccccccc" {
		t.Fatalf("work profile after reload = %+v ok=%v", w, ok)
	}
	if _, ok := reloaded.Profile("default"); ok {
		t.Fatal("default should be gone")
	}
}

func TestSaveCreatesFileAndPerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission checks are unix-only")
	}
	path := filepath.Join(t.TempDir(), "deep", "dir", "config.toml")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Set("default", Profile{APITokenEnv: "FLAREADM_API_TOKEN", DefaultZone: "example.com"})
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("config file mode = %o, want 600", perm)
	}
	dir, _ := os.Stat(filepath.Dir(path))
	if perm := dir.Mode().Perm(); perm != 0o700 {
		t.Fatalf("config dir mode = %o, want 700", perm)
	}
}

func TestLoadInvalidTOML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	writeEnv(t, path, "this is not [ toml")
	if _, err := Load(path); err == nil {
		t.Fatal("invalid TOML should fail")
	}
}

func TestDeterministicSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	writeEnv(t, path, `
[profile.z]
default_zone = "zeta.example"
[profile.a]
api_token_env = "TOKEN_A"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(path)
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(path)
	if string(first) != string(second) {
		t.Fatalf("Save output not deterministic:\n%s\nvs\n%s", first, second)
	}
	if !strings.Contains(string(first), "[profile.a]") {
		t.Fatalf("missing profile.a section:\n%s", first)
	}
	if !strings.Contains(string(first), `api_token_env = "TOKEN_A"`) {
		t.Fatalf("missing api_token_env value:\n%s", first)
	}
}
