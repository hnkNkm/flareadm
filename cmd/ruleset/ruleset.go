// Package ruleset implements `flareadm ruleset ...`: the zone and account
// rules engine surface (rulesets CRUD).
package ruleset

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

// kindValues are the ruleset kinds accepted as filters.
var kindValues = []string{"managed", "custom", "root", "zone"}

// creatableKindValues are the kinds a user can create.
var creatableKindValues = []string{"custom", "root", "zone"}

// New builds the ruleset command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ruleset",
		Short: "Zone and account rulesets (rules engine)",
		Long: "Manage rulesets over /zones/{zone_id}/rulesets or /accounts/{account_id}/rulesets.\n" +
			"Scope selection: --zone (or the profile default_zone) targets a zone;\n" +
			"--account-id targets an account. The two are mutually exclusive.",
	}
	cmd.AddCommand(newList(rt))
	cmd.AddCommand(newGet(rt))
	cmd.AddCommand(newCreate(rt))
	cmd.AddCommand(newUpdate(rt))
	cmd.AddCommand(newDelete(rt))
	return cmd
}

func rulesetRow(r cloudflare.Ruleset) []string {
	return []string{r.ID, r.Name, r.Phase, r.Kind, r.Version, dateOnly(r.LastUpdated)}
}

func dateOnly(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func newList(rt *app.Runtime) *cobra.Command {
	var phaseFlag, kindFlag string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List rulesets",
		Long: "List rulesets. --phase and --kind are applied client-side (the API does not\n" +
			"filter rulesets server-side).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if kindFlag != "" && !contains(kindValues, kindFlag) {
				return errors.Usage("invalid --kind %q (supported: %s)", kindFlag, strings.Join(kindValues, ", "))
			}
			client, scope, err := cmdutil.ClientAndScope(cmd.Context(), rt)
			if err != nil {
				return err
			}
			q := cloudflare.RulesetListQuery{Phase: phaseFlag, Kind: kindFlag}
			res, err := client.ListRulesets(cmd.Context(), scope, q, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, []string{"ID", "NAME", "PHASE", "KIND", "VERSION", "UPDATED"}, rulesetRow)
		},
	}
	cmd.Flags().StringVar(&phaseFlag, "phase", "", "only rulesets in this phase")
	cmd.Flags().StringVar(&kindFlag, "kind", "", "only rulesets of this kind (managed, custom, root, zone)")
	return cmd
}

func newGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get RULESET_ID",
		Short: "Show one ruleset",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, scope, err := cmdutil.ClientAndScope(cmd.Context(), rt)
			if err != nil {
				return err
			}
			res, err := client.GetRuleset(cmd.Context(), scope, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"ID", "NAME", "PHASE", "KIND", "VERSION", "UPDATED"}, rulesetRow)
		},
	}
}

func newCreate(rt *app.Runtime) *cobra.Command {
	var phaseFlag, nameFlag, descriptionFlag, kindFlag, rulesFlag string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a ruleset",
		Long: "Create a ruleset.\n\n" +
			"Example:\n" +
			"  flareadm ruleset create --zone example.com --phase http_request_firewall_custom \\\n" +
			"    --name \"my rules\" --kind zone --rules @rules.json\n\n" +
			"--rules takes a JSON array of rule objects (inline or @file). --dry-run asks\n" +
			"the API to validate the ruleset without persisting it.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if phaseFlag == "" {
				return errors.Usage("--phase is required")
			}
			if nameFlag == "" {
				return errors.Usage("--name is required")
			}
			kind := kindFlag
			if kind == "" {
				if rt.AccountIDFlag != "" && rt.ZoneFlag == "" {
					return errors.Usage("--kind is required for account-scoped rulesets")
				}
				kind = "zone"
			}
			if !contains(creatableKindValues, kind) {
				return errors.Usage("invalid --kind %q (creatable: %s)", kind, strings.Join(creatableKindValues, ", "))
			}
			var rules []byte
			if cmd.Flags().Changed("rules") {
				parsed, err := cmdutil.ParseJSONArray("rules", rulesFlag)
				if err != nil {
					return err
				}
				rules = parsed
			}
			client, scope, err := cmdutil.ClientAndScope(cmd.Context(), rt)
			if err != nil {
				return err
			}
			res, err := client.CreateRuleset(cmd.Context(), scope, cloudflare.RulesetWrite{
				Kind: kind, Name: nameFlag, Phase: phaseFlag, Description: descriptionFlag, Rules: rules,
			}, rt.DryRunFlag)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would create ruleset "+nameFlag+" in phase "+phaseFlag)
			}
			return app.RenderGet(rt, res, []string{"ID", "NAME", "PHASE", "KIND", "VERSION", "UPDATED"}, rulesetRow)
		},
	}
	cmd.Flags().StringVar(&phaseFlag, "phase", "", "ruleset phase (for example http_request_firewall_custom)")
	cmd.Flags().StringVar(&nameFlag, "name", "", "ruleset name")
	cmd.Flags().StringVar(&descriptionFlag, "description", "", "ruleset description")
	cmd.Flags().StringVar(&kindFlag, "kind", "", "ruleset kind (custom, root, zone; default zone for zone scope)")
	cmd.Flags().StringVar(&rulesFlag, "rules", "", "rules as a JSON array, inline or @file")
	return cmd
}

func newUpdate(rt *app.Runtime) *cobra.Command {
	var nameFlag, descriptionFlag, rulesFlag string
	cmd := &cobra.Command{
		Use:   "update RULESET_ID",
		Short: "Update a ruleset",
		Long: "Update a ruleset. Provided fields override the existing ruleset; when\n" +
			"--rules is given it replaces the whole rules array, otherwise the existing\n" +
			"rules are preserved verbatim.\n\n" +
			"--dry-run asks the API to validate the update without persisting it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("name") && !cmd.Flags().Changed("description") && !cmd.Flags().Changed("rules") {
				return errors.Usage("nothing to update; pass at least one of --name, --description, --rules")
			}
			var rules []byte
			if cmd.Flags().Changed("rules") {
				parsed, err := cmdutil.ParseJSONArray("rules", rulesFlag)
				if err != nil {
					return err
				}
				rules = parsed
			}
			up := cloudflare.RulesetUpdate{Rules: rules}
			if cmd.Flags().Changed("name") {
				up.Name = &nameFlag
			}
			if cmd.Flags().Changed("description") {
				up.Description = &descriptionFlag
			}
			client, scope, err := cmdutil.ClientAndScope(cmd.Context(), rt)
			if err != nil {
				return err
			}
			res, err := client.UpdateRuleset(cmd.Context(), scope, args[0], up, rt.DryRunFlag)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would update ruleset "+args[0])
			}
			return app.RenderGet(rt, res, []string{"ID", "NAME", "PHASE", "KIND", "VERSION", "UPDATED"}, rulesetRow)
		},
	}
	cmd.Flags().StringVar(&nameFlag, "name", "", "new ruleset name")
	cmd.Flags().StringVar(&descriptionFlag, "description", "", "new ruleset description")
	cmd.Flags().StringVar(&rulesFlag, "rules", "", "replacement rules as a JSON array, inline or @file")
	return cmd
}

func newDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete RULESET_ID",
		Short: "Delete a ruleset",
		Long: "Delete a ruleset. Destructive: prompts for confirmation unless --yes is\n" +
			"given; --dry-run asks the API to validate the deletion without persisting it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, scope, err := cmdutil.ClientAndScope(cmd.Context(), rt)
			if err != nil {
				return err
			}
			existing, err := client.GetRuleset(cmd.Context(), scope, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				if err := client.DeleteRuleset(cmd.Context(), scope, args[0], true); err != nil {
					return err
				}
				return previewLine(rt, "Would delete ruleset "+existing.Item.ID+" ("+existing.Item.Name+")")
			}
			if err := rt.Confirm("Delete ruleset " + existing.Item.Name + "?"); err != nil {
				return err
			}
			if err := client.DeleteRuleset(cmd.Context(), scope, args[0], false); err != nil {
				return err
			}
			rt.Logger().Infof("deleted ruleset %s", args[0])
			return nil
		},
	}
	return cmd
}

func previewLine(rt *app.Runtime, line string) error {
	if rt.Format() == output.Table {
		_, _ = fmt.Fprintln(rt.Out, line)
		return nil
	}
	return rt.Printer().Emit(map[string]string{"preview": line})
}
