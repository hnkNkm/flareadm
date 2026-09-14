package auth

import (
	stderrors "errors"
	"strings"
	"testing"

	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/oauth"
)

// TestLiveCatalogShape pins the invariants of the generated list: dot-delimited
// ids only (the pre-0.4 colon form is gone), every id unique, categories sorted
// and ids sorted inside them.
func TestLiveCatalogShape(t *testing.T) {
	if len(liveScopeGroups) == 0 {
		t.Fatal("the generated catalog is empty")
	}
	seen := map[string]string{}
	for i, group := range liveScopeGroups {
		if group.Category == "" {
			t.Fatalf("group %d has no category", i)
		}
		if i > 0 && liveScopeGroups[i-1].Category >= group.Category {
			t.Fatalf("categories are not sorted: %q then %q", liveScopeGroups[i-1].Category, group.Category)
		}
		if len(group.IDs) == 0 {
			t.Fatalf("category %q has no ids", group.Category)
		}
		for j, id := range group.IDs {
			if strings.ContainsAny(id, ":") {
				t.Fatalf("scope id %q uses the pre-0.4 colon form", id)
			}
			if j > 0 && group.IDs[j-1] >= id {
				t.Fatalf("ids in %q are not sorted: %q then %q", group.Category, group.IDs[j-1], id)
			}
			if previous, ok := seen[id]; ok {
				t.Fatalf("scope id %q appears in %q and %q", id, previous, group.Category)
			}
			seen[id] = group.Category
		}
	}
	if len(liveScopeIndex) != len(seen) {
		t.Fatalf("index has %d ids, catalog has %d", len(liveScopeIndex), len(seen))
	}
}

// TestRequestedCatalogIDsExistLive is the contract between the two layers: every
// id this CLI asks for by default or with --all-scopes must be one Cloudflare
// actually reports.
func TestRequestedCatalogIDsExistLive(t *testing.T) {
	if len(scopeGroups) == 0 {
		t.Fatal("scopeGroups is empty")
	}
	for _, group := range scopeGroups {
		for _, id := range append(append([]string{}, group.Read...), group.Write...) {
			if _, ok := liveScopeIndex[id]; !ok {
				t.Fatalf("group %q requests %q, which the live catalog does not report", group.Group, id)
			}
			if strings.HasPrefix(strings.TrimPrefix(id, "workers-"), "workers_") {
				t.Fatalf("group %q still uses an underscore id: %q", group.Group, id)
			}
		}
	}
	for _, id := range append(append([]string{}, readOnlyScopes...), writeScopes...) {
		if _, ok := liveScopeIndex[id]; !ok {
			t.Fatalf("catalog id %q is not in the live list", id)
		}
	}
	if len(readOnlyScopes) == 0 || len(writeScopes) == 0 {
		t.Fatalf("catalog halves must not be empty: read=%d write=%d", len(readOnlyScopes), len(writeScopes))
	}
}

// TestSelectScopesDefaultAndAll: the default is the read-only half, --all-scopes
// adds the write half exactly once and never repeats an id.
func TestSelectScopesDefaultAndAll(t *testing.T) {
	def, err := selectScopes("", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(def, " ") != strings.Join(readOnlyScopes, " ") {
		t.Fatalf("default scopes = %v, want the read-only catalog %v", def, readOnlyScopes)
	}
	all, err := selectScopes("", true, false)
	if err != nil {
		t.Fatal(err)
	}
	want := len(readOnlyScopes) + len(writeScopes)
	if len(all) != want {
		t.Fatalf("--all-scopes returned %d ids, want %d", len(all), want)
	}
	seen := map[string]bool{}
	for _, id := range all {
		if seen[id] {
			t.Fatalf("--all-scopes repeated %q", id)
		}
		seen[id] = true
		if _, ok := liveScopeIndex[id]; !ok {
			t.Fatalf("--all-scopes requested %q, which is not a live id", id)
		}
	}
	// The returned slices are copies: a caller must not be able to mutate the
	// catalog.
	def[0] = "mutated"
	if readOnlyScopes[0] == "mutated" {
		t.Fatal("selectScopes handed out the package catalog slice")
	}
}

// TestSelectScopesAcceptsLiveIDs: ids from the live list are accepted, in the
// order given, and the protocol scopes stay valid.
func TestSelectScopesAcceptsLiveIDs(t *testing.T) {
	got, err := selectScopes("zone.read,dns.write teams-dex.read", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, " ") != "zone.read dns.write teams-dex.read" {
		t.Fatalf("--scopes returned %v", got)
	}
	for _, protocol := range oauth.RequiredScopes {
		if _, err := selectScopes(protocol, false, false); err != nil {
			t.Fatalf("protocol scope %q rejected: %v", protocol, err)
		}
	}
	// An id that exists live but is not part of our command mapping is still a
	// legitimate request.
	if _, err := selectScopes("workers-r2.metadata_read", false, false); err != nil {
		t.Fatalf("live id rejected: %v", err)
	}
	// openid and offline are not requestable: Cloudflare answers an authorize
	// request containing them with error=invalid_scope, so the validator must
	// reject them instead of letting the user hit that wall.
	for _, rejected := range []string{"openid", "offline"} {
		if _, err := selectScopes(rejected, false, false); err == nil {
			t.Fatalf("%q must not be accepted as a --scopes value", rejected)
		}
	}
	// offline_access stays valid: the login appends it itself.
	if _, err := selectScopes("offline_access", false, false); err != nil {
		t.Fatalf("offline_access must stay requestable: %v", err)
	}
}

// TestSelectScopesRejectsUnknownWithSuggestion: a typo or a pre-0.4 id is named
// with its closest live match; an unrelated string is rejected bare.
func TestSelectScopesRejectsUnknownWithSuggestion(t *testing.T) {
	cases := []struct {
		request string
		want    string
	}{
		{"zone:read", "zone.read"},
		{"notifcation.read", "notifications.read"},
		{"ssl_certs:write", "ssl-and-certificates."},
		{"dns_records:read", "dns."},
		{"workers_kv:write", "workers-kv"},
	}
	for _, tc := range cases {
		_, err := selectScopes(tc.request, false, false)
		if err == nil {
			t.Fatalf("%q must be rejected", tc.request)
		}
		var exit *errors.ExitError
		if !stderrors.As(err, &exit) || exit.Code != errors.CodeInvalid {
			t.Fatalf("%q: exit code = %v, want 2 (%v)", tc.request, exit, err)
		}
		if !strings.Contains(err.Error(), "did you mean") || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%q: suggestion %q missing from %q", tc.request, tc.want, err.Error())
		}
	}

	_, err := selectScopes("totally.unknown", false, false)
	if err == nil {
		t.Fatal("an unknown scope must be rejected")
	}
	if strings.Contains(err.Error(), "did you mean") {
		t.Fatalf("no suggestion expected for an unrelated id: %v", err)
	}
	if !strings.Contains(err.Error(), "totally.unknown") {
		t.Fatalf("the rejected id must be named: %v", err)
	}
}

// TestSuggestScopePrefersThePlainPair documents the ranking: the shortest id in
// the family (the plain read/write pair) comes first.
func TestSuggestScopePrefersThePlainPair(t *testing.T) {
	if got := suggestScope("dns_records:read"); !strings.HasPrefix(got, "dns.") {
		t.Fatalf("suggestion = %q, want the dns family first", got)
	}
	if got := suggestScope("zone:read"); got != "zone.read" {
		t.Fatalf("suggestion = %q, want zone.read", got)
	}
	if got := suggestScope("not-a-scope-at-all"); got != "" {
		t.Fatalf("suggestion = %q, want none", got)
	}
}

// TestScopeRowsViews: the three views and the category filter, all offline.
func TestScopeRowsViews(t *testing.T) {
	catalog, err := scopeRows(false, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog) != len(readOnlyScopes)+len(writeScopes) {
		t.Fatalf("catalog rows = %d, want %d", len(catalog), len(readOnlyScopes)+len(writeScopes))
	}
	seen := map[string]bool{}
	for i, row := range catalog {
		if seen[row.ID] {
			t.Fatalf("duplicate row %q", row.ID)
		}
		seen[row.ID] = true
		if i > 0 && catalog[i-1].ID >= row.ID {
			t.Fatalf("rows are not sorted: %q then %q", catalog[i-1].ID, row.ID)
		}
		if row.Name == "" || row.Category == "" || row.Group == "" {
			t.Fatalf("row %q is incomplete: %+v", row.ID, row)
		}
		if !row.DefaultScopes {
			continue
		}
		found := false
		for _, id := range readOnlyScopes {
			if id == row.ID {
				found = true
			}
		}
		if !found {
			t.Fatalf("row %q claims to be in the default set", row.ID)
		}
	}

	readOnly, err := scopeRows(false, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(readOnly) != len(readOnlyScopes) {
		t.Fatalf("--read-only rows = %d, want %d", len(readOnly), len(readOnlyScopes))
	}
	for _, row := range readOnly {
		if !row.DefaultScopes {
			t.Fatalf("--read-only listed %q", row.ID)
		}
	}

	all, err := scopeRows(true, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != len(liveScopeIndex) {
		t.Fatalf("--all rows = %d, want the whole live list (%d)", len(all), len(liveScopeIndex))
	}
	for _, row := range all {
		if _, ok := liveScopeIndex[row.ID]; !ok {
			t.Fatalf("--all listed %q, which is not a live id", row.ID)
		}
	}

	filtered, err := scopeRows(true, false, "dns_and_zones")
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) == 0 {
		t.Fatal("category filter returned nothing")
	}
	for _, row := range filtered {
		if row.Category != "dns_and_zones" {
			t.Fatalf("category filter leaked %q (%s)", row.ID, row.Category)
		}
	}

	if _, err := scopeRows(false, false, "nope"); err == nil {
		t.Fatal("an unknown category must be rejected")
	}
}

// TestScopeRemediationExampleIsValidatable pins the property that matters for the
// invalid_scope remediation text: the ids it suggests must be accepted by the
// --scopes validator (scopeSet) and by selectScopes. The pre-0.4 colon form must
// never come back, because suggesting it sends the user into a usage error
// instead of a working login.
func TestScopeRemediationExampleIsValidatable(t *testing.T) {
	example := oauth.ScopeExample
	if example == "" {
		t.Fatal("oauth.ScopeExample is empty")
	}
	ids := splitScopes(example)
	if len(ids) == 0 {
		t.Fatalf("the remediation example has no scope ids: %q", example)
	}
	known := scopeSet()
	for _, id := range ids {
		if !known[id] {
			t.Fatalf("the remediation suggests %q, which the --scopes validator rejects (example: %q)", id, example)
		}
		if strings.Contains(id, ":") {
			t.Fatalf("the remediation still uses a colon-delimited id: %q", id)
		}
	}
	if _, err := selectScopes(example, false, false); err != nil {
		t.Fatalf("selectScopes(%q) = %v", example, err)
	}
}
