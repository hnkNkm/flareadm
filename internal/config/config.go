// Package config loads, saves and mutates the FlareADM configuration file.
//
// File layout (TOML, per docs/configuration.md):
//
//	[profile.default]
//	account_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
//	api_token_env = "CLOUDFLARE_API_TOKEN"
//
//	[profile.personal]
//	account_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
//	api_token_env = "CF_PERSONAL_TOKEN"
//	default_zone = "example.com"
//
// The file is stored at $XDG_CONFIG_HOME/flareadm/config.toml (falling back
// to ~/.config/flareadm/config.toml) on Unix and %APPDATA%\flareadm\
// config.toml on Windows. Writes are atomic and the file is created with
// owner-only permissions where the platform supports it.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// Profile is a single [profile.<name>] table in the configuration file.
// api_token_env names the environment variable that holds the API token;
// FlareADM never stores tokens in the file.
type Profile struct {
	AccountID   string `toml:"account_id" json:"account_id,omitempty" yaml:"account_id,omitempty"`
	APITokenEnv string `toml:"api_token_env" json:"api_token_env,omitempty" yaml:"api_token_env,omitempty"`
	DefaultZone string `toml:"default_zone" json:"default_zone,omitempty" yaml:"default_zone,omitempty"`
}

// fileConfig mirrors the on-disk TOML structure.
type fileConfig struct {
	Profile map[string]Profile `toml:"profile"`
}

// Config is an in-memory configuration document bound to a file path.
type Config struct {
	path     string
	profiles map[string]Profile
}

// DefaultFileName is the configuration file name inside the config home.
const DefaultFileName = "config.toml"

// DefaultDirName is the application directory inside the config home.
const DefaultDirName = "flareadm"

// DefaultPath returns the platform configuration file path:
// Unix: $XDG_CONFIG_HOME/flareadm/config.toml or ~/.config/flareadm/config.toml.
// Windows: %APPDATA%\flareadm\config.toml.
func DefaultPath() string {
	if runtime.GOOS == "windows" {
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, DefaultDirName, DefaultFileName)
		}
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, DefaultDirName, DefaultFileName)
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".", ".config", DefaultDirName, DefaultFileName)
	}
	return filepath.Join(home, ".config", DefaultDirName, DefaultFileName)
}

// Load reads the configuration at path. A missing file is not an error: it
// yields an empty configuration document that commands may write to.
func Load(path string) (*Config, error) {
	c := &Config{path: path, profiles: map[string]Profile{}}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}
	var fc fileConfig
	if _, err := toml.Decode(string(data), &fc); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}
	if fc.Profile != nil {
		for name, p := range fc.Profile {
			c.profiles[name] = p
		}
	}
	return c, nil
}

// Path returns the file path this configuration is bound to.
func (c *Config) Path() string { return c.path }

// Profile returns a profile by name.
func (c *Config) Profile(name string) (Profile, bool) {
	p, ok := c.profiles[name]
	return p, ok
}

// Names returns profile names in sorted order (deterministic output).
func (c *Config) Names() []string {
	names := make([]string, 0, len(c.profiles))
	for n := range c.profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Set upserts a profile.
func (c *Config) Set(name string, p Profile) {
	c.profiles[name] = p
}

// Delete removes a profile, reporting whether it existed.
func (c *Config) Delete(name string) bool {
	if _, ok := c.profiles[name]; !ok {
		return false
	}
	delete(c.profiles, name)
	return true
}

// Empty reports whether the configuration holds no profiles.
func (c *Config) Empty() bool { return len(c.profiles) == 0 }

// Save writes the configuration atomically. The directory is created with
// 0700 permissions and the file with 0600 where supported.
func (c *Config) Save() error {
	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating config directory %s: %w", dir, err)
	}

	var sb strings.Builder
	for _, name := range c.Names() {
		p := c.profiles[name]
		fmt.Fprintf(&sb, "[profile.%s]\n", escape(name))
		if p.AccountID != "" {
			fmt.Fprintf(&sb, "account_id = %s\n", quote(p.AccountID))
		}
		if p.APITokenEnv != "" {
			fmt.Fprintf(&sb, "api_token_env = %s\n", quote(p.APITokenEnv))
		}
		if p.DefaultZone != "" {
			fmt.Fprintf(&sb, "default_zone = %s\n", quote(p.DefaultZone))
		}
		sb.WriteString("\n")
	}

	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temporary config file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		_ = tmp.Close()
		return fmt.Errorf("setting config file permissions: %w", err)
	}
	if _, err := tmp.WriteString(sb.String()); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing config file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing config file: %w", err)
	}
	if err := os.Rename(tmpName, c.path); err != nil {
		return fmt.Errorf("replacing config file %s: %w", c.path, err)
	}
	return nil
}

// escape escapes a TOML bare key if needed and quotes it otherwise.
// Profile names are kept simple in practice; this handles exotic input.
func escape(name string) string {
	if name != "" && bareKey(name) {
		return name
	}
	return quote(name)
}

// bareKey reports whether s can be a TOML bare key.
func bareKey(s string) bool {
	for _, r := range s {
		switch {
		case r == '_' || r == '-':
		case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return s != ""
}

// quote renders s as a TOML basic string literal.
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\u%04X`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
