package auth

import (
	"strings"

	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/oauth"
)

// Scope catalog.
//
// The names come from the unified `cf` CLI's OAuth registration, the most
// complete public scope list (docs/oauth.md §5 Q5). It is a *candidate* set:
// Phase 0 of the OAuth plan reconciles it with `GET /oauth/scopes`, which is
// authoritative per account. Command groups with no publicly verifiable scope
// (ruleset, waf, cache rule, redirect rule, page-rule, r2 bucket, hyperdrive,
// healthcheck, analytics, logs query) are intentionally absent, so OAuth cannot
// be promised for them yet.
var readOnlyScopes = []string{
	"account:read",
	"access:read",
	"auditlogs:read",
	"cfone:read",
	"dns_records:read",
	"lb:read",
	"logpush:read",
	"notification:read",
	"pages:read",
	"registrar:read",
	"teams:read",
	"user:read",
	"workers:read",
	"workers_builds:read",
	"workers_deployments:read",
	"workers_observability:read",
	"zone:read",
}

var writeScopes = []string{
	"access:write",
	"cfone:write",
	"d1:write",
	"dex:write",
	"dns_records:edit",
	"dns_settings:read",
	"lb:edit",
	"logpush:write",
	"notification:write",
	"pages:write",
	"queues:write",
	"registrar:write",
	"ssl_certs:write",
	"teams:pii",
	"teams:secure_location",
	"teams:write",
	"vectorize:write",
	"workers:write",
	"workers_builds:write",
	"workers_kv:write",
	"workers_observability:write",
	"workers_routes:write",
	"workers_scripts:write",
}

// scopeSet indexes the catalog for validation.
func scopeSet() map[string]bool {
	set := make(map[string]bool, len(readOnlyScopes)+len(writeScopes))
	for _, s := range append(append([]string{}, readOnlyScopes...), writeScopes...) {
		set[s] = true
	}
	for _, s := range oauth.RequiredScopes {
		set[s] = true
	}
	return set
}

// selectScopes turns the login flags into the scope list to request. The
// default is the read-only set (docs/oauth.md §6.1); --scopes overrides it and
// --all-scopes requests everything in the catalog.
func selectScopes(list string, all, readOnly bool) ([]string, error) {
	if list != "" && (all || readOnly) {
		return nil, errors.Usage("--scopes cannot be combined with --all-scopes or --read-only")
	}
	if all && readOnly {
		return nil, errors.Usage("--all-scopes and --read-only are mutually exclusive")
	}
	switch {
	case list != "":
		requested := splitScopes(list)
		if len(requested) == 0 {
			return nil, errors.Usage("--scopes must not be empty")
		}
		known := scopeSet()
		var unknown []string
		for _, s := range requested {
			if !known[s] {
				unknown = append(unknown, s)
			}
		}
		if len(unknown) > 0 {
			return nil, errors.Usage("unknown scope(s): %s; run with --all-scopes for the full catalog",
				strings.Join(unknown, ", "))
		}
		return requested, nil
	case all:
		out := append([]string{}, readOnlyScopes...)
		return append(out, writeScopes...), nil
	default:
		return append([]string{}, readOnlyScopes...), nil
	}
}

func splitScopes(list string) []string {
	parts := strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// describeScopes renders a scope list for humans.
func describeScopes(scopes []string) string {
	if len(scopes) == 0 {
		return "(none reported)"
	}
	return strings.Join(scopes, " ")
}
