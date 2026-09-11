// Package oauth implements the OAuth credential store and the Authorization
// Code + PKCE login flow described in docs/oauth.md.
//
// Nothing here performs a network call unless a caller starts a flow: the
// package is pure plumbing (store, PKCE, endpoint URLs, token exchange) so the
// whole flow is testable offline against fake endpoints.
package oauth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/hnkNkm/flareadm/internal/errors"
)

// StoreVersion is the on-disk credential format version (docs/oauth.md §7.1).
const StoreVersion = 1

// ExpiryWindow is how long before expiry a credential is refreshed proactively
// (docs/oauth.md §9: refresh when less than five minutes remain).
const ExpiryWindow = 5 * time.Minute

// Credential is one stored OAuth credential. AccessToken and RefreshToken are
// credentials: they must be registered with the runtime's secret scrubbing
// before they are used anywhere.
type Credential struct {
	Version      int       `json:"version"`
	ClientID     string    `json:"client_id,omitempty"`
	AccountID    string    `json:"account_id,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	Scopes       []string  `json:"scopes,omitempty"`
	ObtainedAt   time.Time `json:"obtained_at,omitempty"`
}

// Expired reports whether the access token should be refreshed before use.
func (c Credential) Expired(now time.Time) bool {
	if c.ExpiresAt.IsZero() {
		return false
	}
	return now.Add(ExpiryWindow).After(c.ExpiresAt)
}

// Store is a per-profile credential store rooted at a directory (normally
// <config dir>/oauth, docs/oauth.md §7.1).
type Store struct {
	Dir string
}

// profileNameRE keeps profile names to characters that cannot escape the store
// directory. Profile names are user input, so path separators and traversal
// sequences are rejected rather than sanitized.
var profileNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// ValidateProfile reports whether a profile name is safe to use as a file name.
func ValidateProfile(profile string) error {
	if profile == "" {
		return errors.Usage("a profile name is required")
	}
	if profile == "." || profile == ".." || !profileNameRE.MatchString(profile) {
		return errors.Usage("invalid profile name %q: use letters, digits, '.', '_' or '-'", profile)
	}
	return nil
}

// Path returns the credential file path for a profile.
func (s Store) Path(profile string) string {
	return filepath.Join(s.Dir, profile+".json")
}

// Load reads the stored credential for a profile. A missing file is not an
// error: ok is false and err is nil.
func (s Store) Load(profile string) (Credential, bool, error) {
	if err := ValidateProfile(profile); err != nil {
		return Credential{}, false, err
	}
	data, err := os.ReadFile(s.Path(profile))
	if err != nil {
		if os.IsNotExist(err) {
			return Credential{}, false, nil
		}
		return Credential{}, false, errors.New(errors.CodeUnclassified, "reading OAuth credential %s: %s", s.Path(profile), err)
	}
	var cred Credential
	if err := json.Unmarshal(data, &cred); err != nil {
		return Credential{}, false, errors.New(errors.CodeUnclassified, "parsing OAuth credential %s: %s", s.Path(profile), err)
	}
	if cred.Version != StoreVersion {
		return Credential{}, false, errors.New(errors.CodeUnclassified,
			"unsupported OAuth credential version %d in %s (this build understands version %d)",
			cred.Version, s.Path(profile), StoreVersion)
	}
	if cred.AccessToken == "" {
		return Credential{}, false, errors.New(errors.CodeUnclassified, "OAuth credential %s has no access token", s.Path(profile))
	}
	return cred, true, nil
}

// Save writes the credential atomically with owner-only permissions: the
// directory is created 0o700 and the file 0o600 where the platform supports
// it. The pattern matches the configuration writer so the v1.0 Windows fix
// applies here too.
func (s Store) Save(profile string, cred Credential) error {
	if err := ValidateProfile(profile); err != nil {
		return err
	}
	cred.Version = StoreVersion
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return errors.New(errors.CodeUnclassified, "creating OAuth credential directory %s: %s", s.Dir, err)
	}
	payload, err := json.MarshalIndent(cred, "", "  ")
	if err != nil {
		return errors.New(errors.CodeUnclassified, "encoding OAuth credential: %s", err)
	}
	payload = append(payload, '\n')

	tmp, err := os.CreateTemp(s.Dir, ".credential-*.tmp")
	if err != nil {
		return errors.New(errors.CodeUnclassified, "creating a temporary credential file in %s: %s", s.Dir, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	// os.Chmod is a no-op on Windows; never let it fail the write there.
	if err := tmp.Chmod(0o600); err != nil && !isWindows() {
		_ = tmp.Close()
		return errors.New(errors.CodeUnclassified, "setting credential file permissions: %s", err)
	}
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return errors.New(errors.CodeUnclassified, "writing credential file: %s", err)
	}
	if err := tmp.Close(); err != nil {
		return errors.New(errors.CodeUnclassified, "writing credential file: %s", err)
	}
	if err := os.Rename(tmpName, s.Path(profile)); err != nil {
		return errors.New(errors.CodeUnclassified, "replacing credential file %s: %s", s.Path(profile), err)
	}
	return nil
}

// Delete removes the stored credential for a profile. A missing file is not an
// error.
func (s Store) Delete(profile string) error {
	if err := ValidateProfile(profile); err != nil {
		return err
	}
	if err := os.Remove(s.Path(profile)); err != nil && !os.IsNotExist(err) {
		return errors.New(errors.CodeUnclassified, "deleting OAuth credential %s: %s", s.Path(profile), err)
	}
	return nil
}

// Describe renders a non-secret summary of a credential for `auth status`.
func (c Credential) Describe() string {
	parts := []string{fmt.Sprintf("%d scope(s)", len(c.Scopes))}
	if !c.ExpiresAt.IsZero() {
		parts = append(parts, "expires "+c.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if c.RefreshToken != "" {
		parts = append(parts, "refresh token stored")
	}
	return strings.Join(parts, ", ")
}
