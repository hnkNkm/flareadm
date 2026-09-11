package oauth

import "strings"

// Default Cloudflare OAuth endpoints (docs/oauth.md §5 Q1, from the discovery
// document at https://dash.cloudflare.com/.well-known/openid-configuration).
const (
	DefaultAuthURL   = "https://dash.cloudflare.com/oauth2/auth"
	DefaultTokenURL  = "https://dash.cloudflare.com/oauth2/token"
	DefaultRevokeURL = "https://dash.cloudflare.com/oauth2/revoke"
)

// Environment overrides for the OAuth endpoints. They exist so the whole flow
// is testable offline (docs/oauth.md §11) and so staging/compliance hosts can
// be targeted; they are not needed in normal use.
const (
	EnvAuthURL   = "FLAREADM_OAUTH_AUTH_URL"
	EnvTokenURL  = "FLAREADM_OAUTH_TOKEN_URL"
	EnvRevokeURL = "FLAREADM_OAUTH_REVOKE_URL"
)

// Endpoints holds the three OAuth URLs the flow talks to.
type Endpoints struct {
	Auth   string
	Token  string
	Revoke string
}

// EndpointsFromEnv resolves the endpoints, falling back to the documented
// production URLs. getenv is normally the runtime's environment accessor.
func EndpointsFromEnv(getenv func(string) string) Endpoints {
	pick := func(key, fallback string) string {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			return v
		}
		return fallback
	}
	return Endpoints{
		Auth:   pick(EnvAuthURL, DefaultAuthURL),
		Token:  pick(EnvTokenURL, DefaultTokenURL),
		Revoke: pick(EnvRevokeURL, DefaultRevokeURL),
	}
}
