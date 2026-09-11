// Package auth resolves API-token credentials for the selected profile and
// guards credential hygiene.
//
// Credential resolution order (per profile, docs/configuration.md):
//
//  1. the environment variable named by the profile's api_token_env;
//  2. FLAREADM_API_TOKEN;
//  3. CLOUDFLARE_API_TOKEN;
//  4. CF_API_TOKEN.
//
// Tokens are never accepted from CLI flags and are never printed.
package auth

import (
	"os"
	"regexp"
	"strings"

	"github.com/hnkNkm/flareadm/internal/config"
	"github.com/hnkNkm/flareadm/internal/errors"
)

// CredentialEnvOrder is the environment-variable fallback chain used when no
// api_token_env override applies.
var CredentialEnvOrder = []string{
	"FLAREADM_API_TOKEN",
	"CLOUDFLARE_API_TOKEN",
	"CF_API_TOKEN",
}

// Credential is a resolved token together with the name of the source
// (environment variable) it came from. The source name is safe to display;
// the token itself must never be printed or logged.
type Credential struct {
	Token  string
	Source string
}

// Resolve walks the documented resolution order and returns the first
// token found. profile may be nil (no selected profile exists yet).
func Resolve(profile *config.Profile) (Credential, bool) {
	return resolve(profile, os.Getenv)
}

func resolve(profile *config.Profile, env func(string) string) (Credential, bool) {
	if profile != nil && profile.APITokenEnv != "" {
		if v := env(profile.APITokenEnv); v != "" {
			return Credential{Token: v, Source: profile.APITokenEnv}, true
		}
	}
	for _, name := range CredentialEnvOrder {
		if v := env(name); v != "" {
			return Credential{Token: v, Source: name}, true
		}
	}
	return Credential{}, false
}

// OAuthSource supplies the stored OAuth credential for the active profile.
// Implementations refresh an expired credential before returning it and must
// report ok=false when nothing is stored. It is the last step of the
// resolution chain (docs/oauth.md §8).
type OAuthSource func() (Credential, bool, error)

// Require resolves credentials or fails with an actionable authentication
// error (exit code 3).
func Require(profile *config.Profile) (Credential, error) {
	cred, ok := Resolve(profile)
	if !ok {
		return Credential{}, missingCredentialError(profile)
	}
	return cred, nil
}

// RequireWithOAuth resolves credentials with the documented chain: the
// environment first (absolutely unchanged: CI behaviour must not move), then
// the stored OAuth credential. When neither source has a credential the error
// is identical to Require's.
func RequireWithOAuth(profile *config.Profile, oauth OAuthSource) (Credential, error) {
	if cred, ok := Resolve(profile); ok {
		return cred, nil
	}
	if oauth != nil {
		cred, ok, err := oauth()
		if err != nil {
			return Credential{}, err
		}
		if ok {
			return cred, nil
		}
	}
	return Credential{}, missingCredentialError(profile)
}

// missingCredentialError builds the shared "no credential" diagnostic.
func missingCredentialError(profile *config.Profile) error {
	msg := "no API token found; set FLAREADM_API_TOKEN, CLOUDFLARE_API_TOKEN or CF_API_TOKEN"
	if profile != nil && profile.APITokenEnv != "" {
		msg += ", or set the profile api_token_env variable (" + profile.APITokenEnv + ")"
	}
	msg += ", or run 'flareadm configure init'"
	return errors.New(errors.CodeAuth, "%s", msg)
}

// pemBlockRE matches any PEM private-key block (optionally a whole body).
var pemBlockRE = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`)

// RedactPEMBlocks removes full PEM private-key blocks from s. Used as a
// defense-in-depth scrub so upstream error bodies echoing request material
// can never surface key content.
func RedactPEMBlocks(s string) string {
	return pemBlockRE.ReplaceAllString(s, "[REDACTED PRIVATE KEY]")
}

// Redact replaces the token (and any "Bearer <token>" occurrences) in s with
// a placeholder. Debug logs are scrubbed with this before being written so
// Authorization headers can never leak through logging.
func Redact(s, token string) string {
	if token == "" {
		return s
	}
	s = strings.ReplaceAll(s, token, "[REDACTED]")
	s = strings.ReplaceAll(s, "Bearer [REDACTED]", "[REDACTED]")
	return s
}
