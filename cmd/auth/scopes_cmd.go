package auth

import (
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

// scopeRow is one row of `auth scopes`.
type scopeRow struct {
	ID            string `json:"id" yaml:"id"`
	Name          string `json:"name,omitempty" yaml:"name,omitempty"`
	Category      string `json:"category,omitempty" yaml:"category,omitempty"`
	DefaultScopes bool   `json:"default" yaml:"default"`
	Group         string `json:"group,omitempty" yaml:"group,omitempty"`
}

// scopeRows builds the rows for the requested view: the catalog this CLI
// requests (default), only its read-only half (--read-only), or every id
// Cloudflare reports (--all), optionally limited to one category.
func scopeRows(all, readOnly bool, category string) ([]scopeRow, error) {
	defaults := map[string]bool{}
	for _, id := range readOnlyScopes {
		defaults[id] = true
	}
	groups := map[string]string{}
	for _, group := range scopeGroups {
		for _, id := range append(append([]string{}, group.Read...), group.Write...) {
			if groups[id] == "" {
				groups[id] = group.Group
			}
		}
	}

	var ids []string
	switch {
	case all:
		ids = make([]string, 0, len(liveScopeIndex))
		for id := range liveScopeIndex {
			ids = append(ids, id)
		}
	case readOnly:
		ids = append(ids, readOnlyScopes...)
	default:
		ids = append(ids, readOnlyScopes...)
		ids = append(ids, writeScopes...)
	}
	sort.Strings(ids)

	if category != "" {
		found := false
		for _, group := range liveScopeGroups {
			if group.Category == category {
				found = true
				break
			}
		}
		if !found {
			known := make([]string, 0, len(liveScopeGroups))
			for _, group := range liveScopeGroups {
				known = append(known, group.Category)
			}
			return nil, errors.Usage("unknown category %q; categories are: %s", category, strings.Join(known, ", "))
		}
	}

	rows := make([]scopeRow, 0, len(ids))
	for _, id := range ids {
		if category != "" && liveScopeIndex[id] != category {
			continue
		}
		rows = append(rows, scopeRow{
			ID:            id,
			Name:          liveScopeNames[id],
			Category:      liveScopeIndex[id],
			DefaultScopes: defaults[id],
			Group:         groups[id],
		})
	}
	return rows, nil
}

// newScopes implements `auth scopes`.
func newScopes(rt *app.Runtime) *cobra.Command {
	var (
		all      bool
		readOnly bool
		category string
	)
	cmd := &cobra.Command{
		Use:   "scopes",
		Short: "List the OAuth scope ids this CLI uses",
		Long: "List the OAuth scope ids that `flareadm auth login` can request.\n\n" +
			"These are the values to put in the `scopes` array when creating the OAuth\n" +
			"client in the Cloudflare dashboard (Manage Account > OAuth clients), and the\n" +
			"same dot-delimited strings the login sends in the authorize request:\n" +
			"registering a scope here is what makes it requestable. The protocol scope\n" +
			"`offline_access` is added by the login itself (it is what makes the server\n" +
			"issue a refresh token) and is not listed; the OIDC `openid`/`offline` scopes\n" +
			"are rejected by Cloudflare for this client type and are never requested.\n\n" +
			"The DEFAULT column marks the set the login requests when no scope flag is\n" +
			"given (`--read-only` is the default for `auth login`); rows without it are\n" +
			"requested only with `--all-scopes`. `--all` lists every scope id Cloudflare\n" +
			"reports, which is also what `auth login --scopes` accepts.\n\n" +
			"The command is offline: it reads the catalog embedded in the binary and\n" +
			"never calls the API or reads configuration.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if all && readOnly {
				return errors.Usage("--all and --read-only are mutually exclusive")
			}
			rows, err := scopeRows(all, readOnly, category)
			if err != nil {
				return err
			}
			row := func(s scopeRow) []string {
				scope := "no"
				if s.DefaultScopes {
					scope = "yes"
				}
				group := s.Group
				if group == "" {
					group = "-"
				}
				return []string{s.ID, s.Name, s.Category, scope, group}
			}
			res := &cloudflare.ListResult[scopeRow]{Items: rows}
			return app.RenderList(rt, res, []string{"ID", "NAME", "CATEGORY", "DEFAULT", "GROUP"}, row)
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "list every scope id Cloudflare reports, not just the ones this CLI requests")
	cmd.Flags().BoolVar(&readOnly, "read-only", false, "list only the scopes the default login requests")
	cmd.Flags().StringVar(&category, "category", "", "list only the scopes in this category (see the CATEGORY column)")
	// Same source as the --category validation in scopeRows: the categories
	// of the generated catalog.
	known := make([]string, 0, len(liveScopeGroups))
	for _, group := range liveScopeGroups {
		known = append(known, group.Category)
	}
	_ = cmd.RegisterFlagCompletionFunc("category", cmdutil.EnumsOf(known))
	return cmd
}
