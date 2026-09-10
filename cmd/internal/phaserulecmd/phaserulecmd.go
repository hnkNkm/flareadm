// Package phaserulecmd builds the phase-scoped rule convenience commands
// (`cache rule ...`, `redirect rule ...`) over the rulesets phase entrypoint
// API so operators never hand-write ruleset JSON.
package phaserulecmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
	"github.com/hnkNkm/flareadm/internal/phaserules"
)

// Config describes one phase-scoped rule command group.
type Config struct {
	Phase     string // rulesets phase, e.g. http_request_cache_settings
	Short     string // group short description
	Example   string // example command line for help
	RuleNoun  string // "cache" or "redirect" (used in prompts/messages)
	PhasesRef string // help note about the underlying phase
}

// New builds the `rule` command group for one phase.
func New(rt *app.Runtime, cfg Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rule",
		Short: cfg.Short,
		Long:  fmt.Sprintf("%s\n\nRules live in the %s phase entrypoint ruleset; this command group\nreads and edits that entrypoint.", cfg.Short, cfg.PhasesRef),
	}
	cmd.AddCommand(newList(rt, cfg))
	cmd.AddCommand(newGet(rt, cfg))
	cmd.AddCommand(newCreate(rt, cfg))
	cmd.AddCommand(newUpdate(rt, cfg))
	cmd.AddCommand(newDelete(rt, cfg))
	return cmd
}

func resolveZone(ctx context.Context, rt *app.Runtime) (*cloudflare.Client, string, error) {
	return rt.ResolveZone(ctx)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func row(r phaserules.Rule) []string {
	return []string{r.ID, r.Action, truncate(r.Expression, 60), r.Description, yesNo(r.Enabled)}
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func newList(rt *app.Runtime, cfg Config) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List " + cfg.RuleNoun + " rules",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, zoneID, err := resolveZone(cmd.Context(), rt)
			if err != nil {
				return err
			}
			res, err := client.GetEntrypointRules(cmd.Context(), cloudflare.RulesetScope{ZoneID: zoneID}, cfg.Phase)
			if err != nil {
				return err
			}
			views, err := phaserules.Views(res.Item.Rules)
			if err != nil {
				return err
			}
			if rt.Raw() {
				return rt.Printer().Raw(res.RawBody)
			}
			if rt.Format() == output.Table {
				rows := make([][]string, 0, len(views))
				for _, v := range views {
					rows = append(rows, row(v))
				}
				return rt.Printer().PrintTable([]string{"ID", "ACTION", "EXPRESSION", "DESCRIPTION", "ENABLED"}, rows)
			}
			return rt.Printer().Emit(views)
		},
	}
}

func newGet(rt *app.Runtime, cfg Config) *cobra.Command {
	return &cobra.Command{
		Use:   "get RULE_ID",
		Short: "Show one " + cfg.RuleNoun + " rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, zoneID, err := resolveZone(cmd.Context(), rt)
			if err != nil {
				return err
			}
			res, err := client.GetEntrypointRules(cmd.Context(), cloudflare.RulesetScope{ZoneID: zoneID}, cfg.Phase)
			if err != nil {
				return err
			}
			idx, err := phaserules.Find(res.Item.Rules, args[0])
			if err != nil {
				return err
			}
			view, err := phaserules.View(res.Item.Rules[idx])
			if err != nil {
				return err
			}
			item := &cloudflare.GetResult[phaserules.Rule]{Item: view, RawBody: res.RawBody}
			return app.RenderGet(rt, item, []string{"ID", "ACTION", "EXPRESSION", "DESCRIPTION", "ENABLED"}, row)
		},
	}
}

// ruleFlags are the shared create/update flags.
type ruleFlags struct {
	action       string
	expression   string
	description  string
	actionParams string
	enabled      bool
}

func addRuleFlags(cmd *cobra.Command, rf *ruleFlags) {
	cmd.Flags().StringVar(&rf.action, "action", "", "rule action (for example set_cache_settings, redirect)")
	cmd.Flags().StringVar(&rf.expression, "expression", "", "rule expression")
	cmd.Flags().StringVar(&rf.description, "description", "", "rule description")
	cmd.Flags().StringVar(&rf.actionParams, "action-parameters", "", "action parameters as a JSON object, inline or @file")
	cmd.Flags().BoolVar(&rf.enabled, "enabled", true, "whether the rule is enabled (use --enabled=false to disable)")
}

// applyRuleFlags writes the changed flags into a rule map.
func applyRuleFlags(cmd *cobra.Command, rf *ruleFlags, m map[string]any) error {
	if cmd.Flags().Changed("action") {
		if rf.action == "" {
			return errors.Usage("--action must not be empty")
		}
		m["action"] = rf.action
	}
	if cmd.Flags().Changed("expression") {
		if rf.expression == "" {
			return errors.Usage("--expression must not be empty")
		}
		m["expression"] = rf.expression
	}
	if cmd.Flags().Changed("description") {
		m["description"] = rf.description
	}
	if cmd.Flags().Changed("enabled") {
		m["enabled"] = rf.enabled
	}
	if cmd.Flags().Changed("action-parameters") {
		params, err := cmdutil.ParseJSONObject("action-parameters", rf.actionParams)
		if err != nil {
			return err
		}
		m["action_parameters"] = params
	}
	return nil
}

func changedRuleFlags(cmd *cobra.Command) bool {
	for _, name := range []string{"action", "expression", "description", "action-parameters", "enabled"} {
		if cmd.Flags().Changed(name) {
			return true
		}
	}
	return false
}

func previewRule(rt *app.Runtime, line string) error {
	if rt.Format() == output.Table {
		_, _ = fmt.Fprintln(rt.Out, line)
		return nil
	}
	return rt.Printer().Emit(map[string]string{"preview": rt.Redact(line)})
}

func newCreate(rt *app.Runtime, cfg Config) *cobra.Command {
	var rf ruleFlags
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a " + cfg.RuleNoun + " rule",
		Long:  "Create a rule in the " + cfg.PhasesRef + " phase entrypoint.\n\nExamples:\n  " + cfg.Example,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("action") || rf.action == "" {
				return errors.Usage("--action is required")
			}
			if !cmd.Flags().Changed("expression") || rf.expression == "" {
				return errors.Usage("--expression is required")
			}
			m := map[string]any{"action": rf.action, "expression": rf.expression, "enabled": rf.enabled}
			if err := applyRuleFlags(cmd, &rf, m); err != nil {
				return err
			}
			client, zoneID, err := resolveZone(cmd.Context(), rt)
			if err != nil {
				return err
			}
			scope := cloudflare.RulesetScope{ZoneID: zoneID}
			current, err := client.GetEntrypointRules(cmd.Context(), scope, cfg.Phase)
			if err != nil {
				return err
			}
			rules, err := phaserules.Append(current.Item.Rules, m)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				if _, err := client.PutEntrypointRules(cmd.Context(), scope, cfg.Phase, rules, true); err != nil {
					return err
				}
				return previewRule(rt, fmt.Sprintf("Would create a %s rule (%s) in phase %s", cfg.RuleNoun, rf.action, cfg.Phase))
			}
			res, err := client.PutEntrypointRules(cmd.Context(), scope, cfg.Phase, rules, false)
			if err != nil {
				return err
			}
			return renderRules(rt, res)
		},
	}
	addRuleFlags(cmd, &rf)
	return cmd
}

func newUpdate(rt *app.Runtime, cfg Config) *cobra.Command {
	var rf ruleFlags
	cmd := &cobra.Command{
		Use:   "update RULE_ID",
		Short: "Update a " + cfg.RuleNoun + " rule",
		Long:  "Update a rule in the " + cfg.PhasesRef + " phase entrypoint. Omitted fields keep\ntheir values; the rest of the entrypoint is preserved.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !changedRuleFlags(cmd) {
				return errors.Usage("nothing to update; pass at least one of --action, --expression, --description, --action-parameters, --enabled")
			}
			client, zoneID, err := resolveZone(cmd.Context(), rt)
			if err != nil {
				return err
			}
			scope := cloudflare.RulesetScope{ZoneID: zoneID}
			current, err := client.GetEntrypointRules(cmd.Context(), scope, cfg.Phase)
			if err != nil {
				return err
			}
			idx, err := phaserules.Find(current.Item.Rules, args[0])
			if err != nil {
				return err
			}
			m, err := phaserules.Map(current.Item.Rules[idx])
			if err != nil {
				return err
			}
			if err := applyRuleFlags(cmd, &rf, m); err != nil {
				return err
			}
			rules, err := phaserules.Replace(current.Item.Rules, idx, m)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				if _, err := client.PutEntrypointRules(cmd.Context(), scope, cfg.Phase, rules, true); err != nil {
					return err
				}
				return previewRule(rt, fmt.Sprintf("Would update %s rule %s in phase %s", cfg.RuleNoun, args[0], cfg.Phase))
			}
			res, err := client.PutEntrypointRules(cmd.Context(), scope, cfg.Phase, rules, false)
			if err != nil {
				return err
			}
			return renderRules(rt, res)
		},
	}
	addRuleFlags(cmd, &rf)
	return cmd
}

func newDelete(rt *app.Runtime, cfg Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete RULE_ID",
		Short: "Delete a " + cfg.RuleNoun + " rule",
		Long: "Delete a rule from the " + cfg.PhasesRef + " phase entrypoint. Destructive:\n" +
			"prompts for confirmation unless --yes is given; --dry-run validates the\n" +
			"deletion server-side without persisting it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, zoneID, err := resolveZone(cmd.Context(), rt)
			if err != nil {
				return err
			}
			scope := cloudflare.RulesetScope{ZoneID: zoneID}
			current, err := client.GetEntrypointRules(cmd.Context(), scope, cfg.Phase)
			if err != nil {
				return err
			}
			idx, err := phaserules.Find(current.Item.Rules, args[0])
			if err != nil {
				return err
			}
			view, err := phaserules.View(current.Item.Rules[idx])
			if err != nil {
				return err
			}
			rules := phaserules.Remove(current.Item.Rules, idx)
			if rt.DryRunFlag {
				if _, err := client.PutEntrypointRules(cmd.Context(), scope, cfg.Phase, rules, true); err != nil {
					return err
				}
				return previewRule(rt, "Would delete "+cfg.RuleNoun+" rule "+phaserules.Describe(view))
			}
			if err := rt.Confirm(fmt.Sprintf("Delete %s rule %s?", cfg.RuleNoun, phaserules.Describe(view))); err != nil {
				return err
			}
			if _, err := client.PutEntrypointRules(cmd.Context(), scope, cfg.Phase, rules, false); err != nil {
				return err
			}
			rt.Logger().Infof("deleted %s rule %s from phase %s", cfg.RuleNoun, args[0], cfg.Phase)
			return nil
		},
	}
	return cmd
}

// renderRules prints the resulting rules of the entrypoint after a write.
func renderRules(rt *app.Runtime, res *cloudflare.GetResult[cloudflare.EntrypointRuleset]) error {
	if rt.Raw() {
		return rt.Printer().Raw(res.RawBody)
	}
	views, err := phaserules.Views(res.Item.Rules)
	if err != nil {
		return err
	}
	if rt.Format() == output.Table {
		rows := make([][]string, 0, len(views))
		for _, v := range views {
			rows = append(rows, row(v))
		}
		return rt.Printer().PrintTable([]string{"ID", "ACTION", "EXPRESSION", "DESCRIPTION", "ENABLED"}, rows)
	}
	return rt.Printer().Emit(views)
}
