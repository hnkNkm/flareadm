package waf

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
)

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func dateOnly(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

func wafRow(r cloudflare.Ruleset) []string {
	return []string{r.ID, r.Name, r.Phase, r.Kind, r.Version, dateOnly(r.LastUpdated)}
}

func newRulesetGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ruleset",
		Short: "WAF rulesets (managed and custom firewall phases)",
	}
	cmd.AddCommand(newRulesetList(rt))
	cmd.AddCommand(newRulesetGet(rt))
	cmd.AddCommand(newRulesetUpdate(rt))
	return cmd
}

func newRulesetList(rt *app.Runtime) *cobra.Command {
	var phaseFlag string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List WAF rulesets",
		Long: "List WAF rulesets across the firewall phases:\n" +
			"http_request_firewall_managed, http_request_firewall_custom,\n" +
			"http_ratelimit, http_response_firewall_managed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			q := cloudflare.RulesetListQuery{Phases: wafPhases}
			if cmd.Flags().Changed("phase") {
				if !contains(wafPhases, phaseFlag) {
					return errors.Usage("invalid WAF --phase %q (supported: %s)", phaseFlag, strings.Join(wafPhases, ", "))
				}
				q = cloudflare.RulesetListQuery{Phase: phaseFlag}
			}
			client, scope, err := cmdutil.ClientAndScope(cmd.Context(), rt)
			if err != nil {
				return err
			}
			res, err := client.ListRulesets(cmd.Context(), scope, q, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, []string{"ID", "NAME", "PHASE", "KIND", "VERSION", "UPDATED"}, wafRow)
		},
	}
	cmd.Flags().StringVar(&phaseFlag, "phase", "", "only this WAF phase")
	return cmd
}

// fetchWAF validates that the ruleset belongs to a WAF phase.
func fetchWAF(rt *app.Runtime, cmd *cobra.Command, id string) (*cloudflare.Client, cloudflare.RulesetScope, cloudflare.Ruleset, error) {
	client, scope, err := cmdutil.ClientAndScope(cmd.Context(), rt)
	if err != nil {
		return nil, cloudflare.RulesetScope{}, cloudflare.Ruleset{}, err
	}
	res, err := client.GetRuleset(cmd.Context(), scope, id)
	if err != nil {
		return nil, cloudflare.RulesetScope{}, cloudflare.Ruleset{}, err
	}
	if !contains(wafPhases, res.Item.Phase) {
		return nil, cloudflare.RulesetScope{}, cloudflare.Ruleset{}, errors.Usage(
			"ruleset %s is in phase %s, which is not a WAF phase; use 'flareadm ruleset get %s'",
			id, res.Item.Phase, id)
	}
	return client, scope, res.Item, nil
}

func newRulesetGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get RULESET_ID",
		Short: "Show one WAF ruleset",
		Long:  "Show one WAF ruleset. Rules include the currently deployed managed rules and any overrides.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, scope, _, err := fetchWAF(rt, cmd, args[0])
			if err != nil {
				return err
			}
			res, err := client.GetRuleset(cmd.Context(), scope, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"ID", "NAME", "PHASE", "KIND", "VERSION", "UPDATED"}, wafRow)
		},
	}
}

func newRulesetUpdate(rt *app.Runtime) *cobra.Command {
	var rulesFlag string
	cmd := &cobra.Command{
		Use:   "update RULESET_ID",
		Short: "Update WAF ruleset overrides",
		Long: "Replace the rules array of a WAF ruleset with the provided overrides.\n" +
			"For Cloudflare-managed rulesets this writes the override list (enabled,\n" +
			"action and action_parameters per rule), which is how managed rule behavior\n" +
			"is customized.\n\n" +
			"Example:\n" +
			"  flareadm waf ruleset update <ruleset-id> --zone example.com --rules @overrides.json\n\n" +
			"--dry-run asks the API to validate the overrides without persisting them.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("rules") {
				return errors.Usage("--rules is required (JSON array of rule overrides, inline or @file)")
			}
			parsed, err := cmdutil.ParseJSONArray("rules", rulesFlag)
			if err != nil {
				return err
			}
			client, scope, _, err := fetchWAF(rt, cmd, args[0])
			if err != nil {
				return err
			}
			res, err := client.UpdateRuleset(cmd.Context(), scope, args[0], cloudflare.RulesetUpdate{Rules: parsed}, rt.DryRunFlag)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				if rt.Format() == output.Table {
					_, _ = fmt.Fprintln(rt.Out, "Would update WAF ruleset overrides for "+args[0])
					return nil
				}
				return rt.Printer().Emit(map[string]string{"preview": "Would update WAF ruleset overrides for " + args[0]})
			}
			return app.RenderGet(rt, res, []string{"ID", "NAME", "PHASE", "KIND", "VERSION", "UPDATED"}, wafRow)
		},
	}
	cmd.Flags().StringVar(&rulesFlag, "rules", "", "rule overrides as a JSON array, inline or @file")
	return cmd
}
