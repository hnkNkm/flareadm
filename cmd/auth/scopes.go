package auth

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/oauth"
)

// Scope catalog.
//
// Two layers, deliberately separated:
//
//   - scopes_generated.go holds the authoritative live list from
//     `GET /oauth/scopes` (385 dot-delimited ids in 13 categories, captured
//     2026-09-13). It is regenerated with tools/scopegen and is what `--scopes`
//     validates against, so any id Cloudflare reports can be requested.
//   - scopeGroups below maps the command groups this CLI implements onto the
//     live ids they need. Reads are requested by default (`--read-only`), writes
//     only with `--all-scopes`, so a login never asks for more than the user's
//     client is likely to have registered.
//
// The protocol scopes (openid, offline, offline_access) are not ids and stay in
// oauth.RequiredScopes, which is always appended.

// liveScopeGroup is one category of the live scope list.
type liveScopeGroup struct {
	Category string
	IDs      []string
}

// scopeGroup maps one flareadm command group to the live scope ids its commands
// need. Group names mirror the command groups in cmd/.
type scopeGroup struct {
	Group string
	Read  []string
	Write []string
}

// scopeGroups is the catalog this CLI requests. Every id must exist in
// liveScopeGroups (TestScopeCatalogIDsExistLive enforces it), and the mapping
// notes the semantic remaps from the pre-0.4 colon-delimited names.
var scopeGroups = []scopeGroup{
	{Group: "account", Read: []string{"memberships.read", "account-settings.read"}},                                                // was account:read
	{Group: "access", Read: []string{"access.read"}, Write: []string{"access.write"}},                                              // was access:read/write
	{Group: "logs", Read: []string{"account-logs.read"}, Write: []string{"logs.write"}},                                            // was auditlogs:read, logpush:write
	{Group: "dns", Read: []string{"dns.read"}, Write: []string{"dns.write"}},                                                       // was dns_records:read/edit
	{Group: "dns-settings", Write: []string{"zone-dns-settings.read"}},                                                             // was dns_settings:read
	{Group: "load-balancer", Read: []string{"load-balancers.read"}, Write: []string{"load-balancers.write"}},                       // was lb:read/edit
	{Group: "logpush", Read: []string{"logs.read"}},                                                                                // logpush.* is not a live family; logs.* is
	{Group: "notifications", Read: []string{"notifications.read"}, Write: []string{"notifications.write"}},                         // was notification:read/write
	{Group: "pages", Read: []string{"page.read"}, Write: []string{"page.write"}},                                                   // was pages:read/write
	{Group: "registrar", Read: []string{"registrar-domains.read"}, Write: []string{"registrar-domains.admin"}},                     // was registrar:read/write
	{Group: "ssl-certificates", Write: []string{"ssl-and-certificates.write"}},                                                     // was ssl_certs:write
	{Group: "zero-trust", Read: []string{"teams.read"}, Write: []string{"teams.write", "teams-pii.read", "teams-secure.location"}}, // was teams:read/write/pii/secure_location
	{Group: "cloudforce-one", Read: []string{"cloudforce-one.read"}, Write: []string{"cloudforce-one.write"}},                      // was cfone:read/write
	{Group: "dex", Write: []string{"teams-dex.write"}},                                                                             // was dex:write
	{Group: "user", Read: []string{"user-details.read"}},                                                                           // was user:read
	{Group: "workers", Read: []string{"workers-scripts.read"}, Write: []string{"workers-scripts.write"}},                           // was workers:read, workers_scripts:write
	{Group: "workers-builds", Read: []string{"workers-ci.read"}, Write: []string{"workers-ci.write"}},                              // was workers_builds:read/write
	{Group: "workers-kv", Write: []string{"workers-kv-storage.write"}},                                                             // was workers_kv:write
	{Group: "workers-observability", Read: []string{"workers-observability.read"}, Write: []string{"workers-observability.write"}}, // was workers_observability:read/write
	{Group: "workers-routes", Write: []string{"workers-routes.write"}},                                                             // was workers_routes:write
	{Group: "d1", Write: []string{"d1.write"}},                                                                                     // was d1:write
	{Group: "queues", Write: []string{"queues.write"}},                                                                             // was queues:write
	{Group: "vectorize", Write: []string{"vectorize.write"}},                                                                       // was vectorize:write
	{Group: "zone", Read: []string{"zone.read"}},                                                                                   // was zone:read
	// workers_deployments:* is deliberately absent: no live family exists for it
	// and workers-scripts.write already covers deploying a Worker.
}

// readOnlyScopes is the default request: the union of every group's reads.
var readOnlyScopes = catalogScopes(func(group scopeGroup) []string { return group.Read })

// writeScopes is what --all-scopes adds on top of readOnlyScopes.
var writeScopes = catalogScopes(func(group scopeGroup) []string { return group.Write })

// catalogScopes collects one side of the group mapping into a stable,
// deduplicated list (group order, then declaration order).
func catalogScopes(pick func(scopeGroup) []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, group := range scopeGroups {
		for _, id := range pick(group) {
			if seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// liveScopeIndex maps every live scope id to its category.
var liveScopeIndex = func() map[string]string {
	index := map[string]string{}
	for _, group := range liveScopeGroups {
		for _, id := range group.IDs {
			index[id] = group.Category
		}
	}
	return index
}()

// scopeSet indexes every id the live API reports, plus the protocol scopes, for
// validating --scopes.
func scopeSet() map[string]bool {
	set := make(map[string]bool, len(liveScopeIndex)+len(oauth.RequiredScopes))
	for id := range liveScopeIndex {
		set[id] = true
	}
	for _, s := range oauth.RequiredScopes {
		set[s] = true
	}
	return set
}

// maxSuggestionDistance bounds how far an unknown scope id may be from a live
// one and still be reported as a likely typo of it.
const maxSuggestionDistance = 2

// suggestScope names the live id an unknown scope was probably meant to be, in
// three steps: an exact match after separator normalisation (zone:read ->
// zone.read), the longest token-boundary prefix some live id continues
// (dns_records:read -> dns.read, workers_kv:write -> workers-kv-storage.*), and
// finally the live family whose name is within maxSuggestionDistance edits
// (notifcation.read -> notifications.read). It returns "" when nothing is close.
func suggestScope(unknown string) string {
	want := normalizeScopeID(unknown)
	if _, ok := liveScopeIndex[want]; ok {
		return want
	}

	head := want
	if i := strings.IndexByte(head, '.'); i >= 0 {
		head = head[:i]
	}
	// Only token boundaries are tried ("dns-records" -> "dns"): a prefix that
	// stops mid-token ("dns-") would match dns-view/dns-firewall instead of the
	// plain dns.read/dns.write pair.
	tokens := strings.Split(head, "-")
	for n := len(tokens); n > 0; n-- {
		if matches := liveIDsWithPrefix(strings.Join(tokens[:n], "-")); len(matches) > 0 {
			return strings.Join(matches, ", ")
		}
	}

	bestHead, bestDistance := "", maxSuggestionDistance+1
	for id := range liveScopeIndex {
		candidate := id
		if i := strings.IndexByte(candidate, '.'); i >= 0 {
			candidate = candidate[:i]
		}
		distance := levenshtein(head, candidate)
		if distance < bestDistance || (distance == bestDistance && candidate < bestHead) {
			bestHead, bestDistance = candidate, distance
		}
	}
	if bestDistance > maxSuggestionDistance {
		return ""
	}
	return strings.Join(liveIDsWithPrefix(bestHead), ", ")
}

// liveIDsWithPrefix returns at most three live ids that continue prefix at a
// token boundary, shortest first: the plain read/write pair of a family is what
// a stale name was reaching for.
func liveIDsWithPrefix(prefix string) []string {
	var matches []string
	for id := range liveScopeIndex {
		rest := strings.TrimPrefix(id, prefix)
		if rest == id {
			continue
		}
		if rest != "" && rest[0] != '.' && rest[0] != '-' {
			continue
		}
		matches = append(matches, id)
	}
	if len(matches) == 0 {
		return nil
	}
	sort.Slice(matches, func(i, j int) bool {
		if len(matches[i]) != len(matches[j]) {
			return len(matches[i]) < len(matches[j])
		}
		return matches[i] < matches[j]
	})
	if len(matches) > 3 {
		matches = matches[:3]
	}
	return matches
}

// normalizeScopeID folds the pre-0.4 separator conventions onto the live ones so
// `zone:read`, `zone_read` and `zone.read` all compare equal.
func normalizeScopeID(id string) string {
	return strings.NewReplacer(":", ".", "_", "-").Replace(strings.ToLower(id))
}

// levenshtein is the edit distance between two strings.
func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	previous := make([]int, len(b)+1)
	current := make([]int, len(b)+1)
	for j := range previous {
		previous[j] = j
	}
	for i := 1; i <= len(a); i++ {
		current[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			current[j] = min3(current[j-1]+1, previous[j]+1, previous[j-1]+cost)
		}
		previous, current = current, previous
	}
	return previous[len(b)]
}

func min3(a, b, c int) int {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
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
				if suggestion := suggestScope(s); suggestion != "" {
					unknown = append(unknown, fmt.Sprintf("%s (did you mean %s?)", s, suggestion))
					continue
				}
				unknown = append(unknown, s)
			}
		}
		if len(unknown) > 0 {
			return nil, errors.Usage("unknown scope(s): %s; `flareadm api request GET /oauth/scopes` lists every scope id the API reports",
				strings.Join(unknown, ", "))
		}
		return requested, nil
	case all:
		seen := map[string]bool{}
		out := make([]string, 0, len(readOnlyScopes)+len(writeScopes))
		for _, id := range append(append([]string{}, readOnlyScopes...), writeScopes...) {
			if seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
		return out, nil
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
