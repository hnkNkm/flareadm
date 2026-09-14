package cmdutil

import (
	"context"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/output"
	"github.com/hnkNkm/flareadm/internal/pagination"
)

// Shell completion is best effort by contract: the shell is blocked while it
// waits for an answer, so a completion may never hold the prompt, prompt the
// user, call the network without a deadline, retry, or print anything. Every
// failure path in this file therefore yields "no suggestions" instead of an
// error, and no function here writes to a stream - the only output a completion
// produces is the candidate list cobra prints to stdout.
const (
	// completionBudget bounds one network-backed completion. It is a ceiling on
	// the whole call, not on a single request: past it the candidate list is
	// dropped and the shell offers nothing.
	completionBudget = 1500 * time.Millisecond

	// completionMaxItems caps the candidates offered for one argument. Only the
	// first page is read: a completion is a pick list, not a report, and a
	// second page would cost another round trip in front of a waiting prompt.
	completionMaxItems = pagination.DefaultPageSize
)

// Enums completes a value from a fixed set. The candidates keep the caller's
// order, which should be the order the flag documents.
func Enums(values ...string) cobra.CompletionFunc { return EnumsOf(values) }

// EnumsOf is Enums for a value set that already exists as a slice.
func EnumsOf(values []string) cobra.CompletionFunc {
	return func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return prefixMatches(values, toComplete), cobra.ShellCompDirectiveNoFileComp
	}
}

// OutputFormats completes --output with the values internal/output accepts.
func OutputFormats() cobra.CompletionFunc { return EnumsOf(output.Formats) }

// Profiles completes --profile with the profile names recorded in the
// configuration file. It is local-only by design: no credential is resolved and
// the API is never called. A missing, unreadable or empty configuration yields
// no suggestions rather than an error, so completion stays silent for a user
// who has not configured anything yet.
func Profiles(rt *app.Runtime) cobra.CompletionFunc {
	return func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return prefixMatches(configuredProfiles(rt), toComplete), cobra.ShellCompDirectiveNoFileComp
	}
}

// AccountIDs completes --account-id with the account ids the configuration file
// records. Only locally known ids are offered: resolving the accessible
// accounts would be an API call, and a completion that quietly spends a request
// on every tab press is not worth it (the error for an id that is wrong names
// the accepted sources).
func AccountIDs(rt *app.Runtime) cobra.CompletionFunc {
	return func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return prefixMatches(configuredAccountIDs(rt), toComplete), cobra.ShellCompDirectiveNoFileComp
	}
}

// Zones completes a zone reference (name or id) for --zone and for the
// positional zone argument of zone-scoped commands. The candidates come from
// the API, so the result is strictly best effort: bounded by completionBudget,
// one attempt, and silent - no credential, no zone, no network and no
// permission all degrade to "no suggestions" without printing anything.
func Zones(rt *app.Runtime) cobra.CompletionFunc {
	return func(cmd *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		ctx := context.Background()
		if cmd != nil && cmd.Context() != nil {
			ctx = cmd.Context()
		}
		return ZoneCompletions(ctx, rt, toComplete, completionBudget), cobra.ShellCompDirectiveNoFileComp
	}
}

// ZoneCompletions lists the zone names and ids matching prefix. It is Zones
// without the cobra plumbing, and it is exported so tests can drive it with a
// short budget instead of waiting out the real one. It reports nothing when the
// list cannot be fetched in time.
func ZoneCompletions(ctx context.Context, rt *app.Runtime, toComplete string, budget time.Duration) []string {
	if budget <= 0 {
		budget = completionBudget
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	// Resolving a credential can refresh an expired OAuth token, which is a
	// network call the runtime bounds with its own timeout rather than with
	// ctx, so the listing runs in a goroutine the budget can abandon. Nothing
	// else happens after a completion is printed (the process exits), so an
	// abandoned listing cannot affect anything else.
	answers := make(chan []string, 1)
	go func() { answers <- listZones(ctx, rt, toComplete) }()
	select {
	case zones := <-answers:
		return zones
	case <-ctx.Done():
		return nil
	}
}

// listZones performs the bounded zone listing behind ZoneCompletions.
func listZones(ctx context.Context, rt *app.Runtime, prefix string) []string {
	client, err := rt.CompletionClient()
	if err != nil || client == nil {
		return nil
	}
	res, err := client.ListZones(ctx, cloudflare.ZoneListQuery{},
		pagination.Policy{PageSize: completionMaxItems, NoPaginate: true})
	if err != nil || res == nil {
		return nil
	}
	// Names first: they are what a user types. Ids are accepted by every
	// zone-scoped command too, so they are offered as well, and the caller's
	// budget still caps the total.
	names := make([]string, 0, len(res.Items))
	ids := make([]string, 0, len(res.Items))
	for _, zone := range res.Items {
		if zone.Name != "" && strings.HasPrefix(zone.Name, prefix) {
			names = append(names, zone.Name)
		}
		if zone.ID != "" && strings.HasPrefix(zone.ID, prefix) {
			ids = append(ids, zone.ID)
		}
	}
	return append(names, ids...)
}

// configuredProfiles lists the profile names in the configuration file,
// reporting nothing when the file cannot be read.
func configuredProfiles(rt *app.Runtime) []string {
	cfg, err := rt.Config()
	if err != nil || cfg == nil {
		return nil
	}
	return cfg.Names()
}

// configuredAccountIDs lists the distinct account ids the profiles carry, in
// profile-name order, reporting nothing when the file cannot be read.
func configuredAccountIDs(rt *app.Runtime) []string {
	cfg, err := rt.Config()
	if err != nil || cfg == nil {
		return nil
	}
	ids := make([]string, 0, len(cfg.Names()))
	for _, name := range cfg.Names() {
		p, ok := cfg.Profile(name)
		if !ok || p.AccountID == "" {
			continue
		}
		if !contains(ids, p.AccountID) {
			ids = append(ids, p.AccountID)
		}
	}
	return ids
}

// prefixMatches filters a candidate list down to the entries starting with
// toComplete. The shell filters too, but doing it here keeps bash (whose
// generated script feeds the raw list to compgen) and the "no candidates at
// all" case behaving the same everywhere.
func prefixMatches(candidates []string, toComplete string) []string {
	matches := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if strings.HasPrefix(candidate, toComplete) {
			matches = append(matches, candidate)
		}
	}
	return matches
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
