// Package cache implements `flareadm cache purge`.
package cache

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/phaserulecmd"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
)

// New builds the cache command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Cache administration",
	}
	cmd.AddCommand(newPurge(rt))
	cmd.AddCommand(phaserulecmd.New(rt, phaserulecmd.Config{
		Phase:     "http_request_cache_settings",
		Short:     "Cache rules",
		RuleNoun:  "cache",
		PhasesRef: "http_request_cache_settings",
		Example:   `flareadm cache rule create --zone example.com --action set_cache_settings --expression "(http.host eq \"www.example.com\")" --action-parameters @params.json`,
	}))
	return cmd
}

func newPurge(rt *app.Runtime) *cobra.Command {
	var everything bool
	var files, hosts, tags, prefixes []string
	cmd := &cobra.Command{
		Use:   "purge",
		Short: "Purge cached content of a zone",
		Long: "Purge cached content of a zone: everything, or specific files, hosts,\n" +
			"cache tags or URL prefixes. Destructive: prompts for confirmation unless\n" +
			"--yes is given; --dry-run previews the purge.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			targets := cloudflare.PurgeTargets{
				PurgeEverything: everything,
				Files:           files,
				Hosts:           hosts,
				Tags:            tags,
				Prefixes:        prefixes,
			}
			if _, err := buildPurgeDescription(targets); err != nil {
				return err
			}
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			description, err := buildPurgeDescription(targets)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				if rt.Format() == output.Table {
					_, _ = fmt.Fprintf(rt.Out, "Would purge %s for zone %s\n", description, zoneID)
					return nil
				}
				return rt.Printer().Emit(map[string]string{"preview": fmt.Sprintf("Would purge %s for zone %s", description, zoneID)})
			}
			if err := rt.Confirm(fmt.Sprintf("Purge %s for zone %s?", description, zoneID)); err != nil {
				return err
			}
			res, err := client.PurgeCache(cmd.Context(), zoneID, targets)
			if err != nil {
				return err
			}
			row := func(p cloudflare.PurgeResult) []string { return []string{p.ID} }
			return app.RenderGet(rt, res, []string{"PURGE ID"}, row)
		},
	}
	cmd.Flags().BoolVar(&everything, "everything", false, "purge all cached content of the zone")
	cmd.Flags().StringArrayVar(&files, "file", nil, "purge one file URL (repeatable)")
	cmd.Flags().StringArrayVar(&hosts, "host", nil, "purge one hostname (repeatable)")
	cmd.Flags().StringArrayVar(&tags, "tag", nil, "purge one cache tag (repeatable)")
	cmd.Flags().StringArrayVar(&prefixes, "prefix", nil, "purge one URL prefix (repeatable)")
	return cmd
}

// buildPurgeDescription validates that exactly one purge kind is selected
// and returns a human description of it.
func buildPurgeDescription(t cloudflare.PurgeTargets) (string, error) {
	count := 0
	for _, list := range [][]string{t.Files, t.Hosts, t.Tags, t.Prefixes} {
		if len(list) > 0 {
			count++
		}
	}
	if t.PurgeEverything {
		count++
	}
	if count == 0 {
		return "", errors.Usage("specify what to purge: --everything, or one of --file, --host, --tag, --prefix")
	}
	if count > 1 {
		return "", errors.Usage("purge targets are mutually exclusive: choose --everything or one of --file, --host, --tag, --prefix")
	}
	switch {
	case t.PurgeEverything:
		return "all cached content", nil
	case len(t.Files) > 0:
		return "files " + strings.Join(t.Files, ", "), nil
	case len(t.Hosts) > 0:
		return "hosts " + strings.Join(t.Hosts, ", "), nil
	case len(t.Tags) > 0:
		return "tags " + strings.Join(t.Tags, ", "), nil
	default:
		return "prefixes " + strings.Join(t.Prefixes, ", "), nil
	}
}
