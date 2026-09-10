// Package pagerule implements `flareadm page-rule ...`: legacy zone Page
// Rules (Cloudflare keeps these available for all zones while migrating to
// the Rules engine; they are legacy and the ruleset commands are preferred).
package pagerule

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
)

var statusValues = []string{"active", "disabled"}

// New builds the page-rule command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "page-rule",
		Short: "Legacy zone Page Rules",
		Long: "Legacy Page Rules (available for all zones while Cloudflare migrates to\n" +
			"the Rules engine). Prefer `ruleset`/`cache rule`/`redirect rule` for new\n" +
			"configuration.",
	}
	cmd.AddCommand(newList(rt))
	cmd.AddCommand(newGet(rt))
	cmd.AddCommand(newCreate(rt))
	cmd.AddCommand(newUpdate(rt))
	cmd.AddCommand(newDelete(rt))
	return cmd
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// firstTargetValue extracts the constraint value of the first target.
func firstTargetValue(raw json.RawMessage) string {
	var targets []struct {
		Constraint struct {
			Value string `json:"value"`
		} `json:"constraint"`
	}
	if err := json.Unmarshal(raw, &targets); err != nil || len(targets) == 0 {
		return ""
	}
	return targets[0].Constraint.Value
}

// actionCount counts the actions array entries.
func actionCount(raw json.RawMessage) string {
	var actions []json.RawMessage
	if err := json.Unmarshal(raw, &actions); err != nil {
		return ""
	}
	return fmt.Sprintf("%d", len(actions))
}

func row(r cloudflare.PageRule) []string {
	return []string{r.ID, r.Status, fmt.Sprintf("%d", r.Priority), truncate(firstTargetValue(r.Targets), 40), actionCount(r.Actions)}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func newList(rt *app.Runtime) *cobra.Command {
	var statusFlag, orderFlag, directionFlag, matchFlag string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List page rules",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if statusFlag != "" && !contains(statusValues, statusFlag) {
				return errors.Usage("invalid --status %q (supported: %s)", statusFlag, strings.Join(statusValues, ", "))
			}
			if directionFlag != "" && directionFlag != "asc" && directionFlag != "desc" {
				return errors.Usage("invalid --direction %q (supported: asc, desc)", directionFlag)
			}
			if matchFlag != "" && matchFlag != "all" && matchFlag != "any" {
				return errors.Usage("invalid --match %q (supported: all, any)", matchFlag)
			}
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			q := cloudflare.PageRuleQuery{Status: statusFlag, Order: orderFlag, Direction: directionFlag, Match: matchFlag}
			res, err := client.ListPageRules(cmd.Context(), zoneID, q)
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, []string{"ID", "STATUS", "PRIORITY", "TARGET", "ACTIONS"}, row)
		},
	}
	cmd.Flags().StringVar(&statusFlag, "status", "", "only rules with this status (active, disabled)")
	cmd.Flags().StringVar(&orderFlag, "order", "", "sort field (API-defined)")
	cmd.Flags().StringVar(&directionFlag, "direction", "", "sort direction (asc, desc)")
	cmd.Flags().StringVar(&matchFlag, "match", "", "match mode (all, any)")
	return cmd
}

func newGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get PAGERULE_ID",
		Short: "Show one page rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetPageRule(cmd.Context(), zoneID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"ID", "STATUS", "PRIORITY", "TARGET", "ACTIONS"}, row)
		},
	}
}

// ruleWrite parses the shared page-rule flags.
func ruleWrite(cmd *cobra.Command, targets, actions string, priority int64, status string) (cloudflare.PageRuleWrite, error) {
	w := cloudflare.PageRuleWrite{}
	var err error
	if cmd.Flags().Changed("targets") {
		w.Targets, err = cmdutil.ParseJSONArray("targets", targets)
		if err != nil {
			return w, err
		}
	}
	if cmd.Flags().Changed("actions") {
		w.Actions, err = cmdutil.ParseJSONArray("actions", actions)
		if err != nil {
			return w, err
		}
	}
	if cmd.Flags().Changed("priority") {
		if priority < 1 {
			return w, errors.Usage("invalid --priority %d (must be >= 1)", priority)
		}
		w.Priority = &priority
	}
	if cmd.Flags().Changed("status") {
		if !contains(statusValues, status) {
			return w, errors.Usage("invalid --status %q (supported: %s)", status, strings.Join(statusValues, ", "))
		}
		w.Status = &status
	}
	return w, nil
}

func addWriteFlags(cmd *cobra.Command, targets, actions *string, priority *int64, status *string) {
	cmd.Flags().StringVar(targets, "targets", "", "targets as a JSON array, inline or @file")
	cmd.Flags().StringVar(actions, "actions", "", "actions as a JSON array, inline or @file")
	cmd.Flags().Int64Var(priority, "priority", 0, "rule priority (1 runs first)")
	cmd.Flags().StringVar(status, "status", "", "rule status (active, disabled)")
}

func newCreate(rt *app.Runtime) *cobra.Command {
	var targets, actions, status string
	var priority int64
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a page rule",
		Long: "Create a page rule.\n\n" +
			"Example:\n" +
			"  flareadm page-rule create --zone example.com \\\n" +
			"    --targets '[{\"target\":\"url\",\"constraint\":{\"operator\":\"matches\",\"value\":\"example.com/*\"}}]' \\\n" +
			"    --actions '[{\"id\":\"always_use_https\"}]' --priority 1",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			w, err := ruleWrite(cmd, targets, actions, priority, status)
			if err != nil {
				return err
			}
			if len(w.Targets) == 0 {
				return errors.Usage("--targets is required (JSON array)")
			}
			if len(w.Actions) == 0 {
				return errors.Usage("--actions is required (JSON array)")
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would create page rule with "+actionCount(w.Actions)+" action(s)")
			}
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreatePageRule(cmd.Context(), zoneID, w)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"ID", "STATUS", "PRIORITY", "TARGET", "ACTIONS"}, row)
		},
	}
	addWriteFlags(cmd, &targets, &actions, &priority, &status)
	return cmd
}

func newUpdate(rt *app.Runtime) *cobra.Command {
	var targets, actions, status string
	var priority int64
	cmd := &cobra.Command{
		Use:   "update PAGERULE_ID",
		Short: "Update a page rule",
		Long: "Update a page rule. Provided fields override the existing rule; omitted\n" +
			"fields keep their values (PATCH).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			changed := false
			for _, name := range []string{"targets", "actions", "priority", "status"} {
				changed = changed || cmd.Flags().Changed(name)
			}
			if !changed {
				return errors.Usage("nothing to update; pass at least one of --targets, --actions, --priority, --status")
			}
			w, err := ruleWrite(cmd, targets, actions, priority, status)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would update page rule "+args[0])
			}
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdatePageRule(cmd.Context(), zoneID, args[0], w)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"ID", "STATUS", "PRIORITY", "TARGET", "ACTIONS"}, row)
		},
	}
	addWriteFlags(cmd, &targets, &actions, &priority, &status)
	return cmd
}

func newDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete PAGERULE_ID",
		Short: "Delete a page rule",
		Long: "Delete a page rule. Destructive: prompts for confirmation unless --yes is\n" +
			"given; --dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetPageRule(cmd.Context(), zoneID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would delete page rule "+existing.Item.ID+" ("+firstTargetValue(existing.Item.Targets)+")")
			}
			if err := rt.Confirm("Delete page rule " + existing.Item.ID + "?"); err != nil {
				return err
			}
			if err := client.DeletePageRule(cmd.Context(), zoneID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted page rule %s", args[0])
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
