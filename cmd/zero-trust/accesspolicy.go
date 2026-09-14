package zerotrust

import (
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func accessPolicyRow(p cloudflare.AccessPolicy) []string {
	return []string{p.ID, p.Name, p.Decision, strconv.FormatInt(p.Precedence, 10), p.SessionDuration}
}

func accessPolicyHeaders() []string {
	return []string{"ID", "NAME", "DECISION", "PRECEDENCE", "SESSION DURATION"}
}

func reusablePolicyRow(p cloudflare.AccessPolicy) []string {
	return append(accessPolicyRow(p), strconv.FormatInt(p.AppCount, 10))
}

func reusablePolicyHeaders() []string {
	return append(accessPolicyHeaders(), "APPS")
}

// policyFlagValues collects the shared create/update flags of Access policies.
type policyFlagValues struct {
	rt                  *app.Runtime
	Name                string
	Decision            string
	SessionDuration     string
	PurposePrompt       string
	Include             string
	Exclude             string
	Require             string
	Settings            string
	Precedence          int64
	ApprovalRequired    bool
	IsolationRequired   bool
	PurposeJustRequired bool
}

func addPolicyFlags(rt *app.Runtime, cmd *cobra.Command, f *policyFlagValues) {
	f.rt = rt
	cmd.Flags().StringVar(&f.Name, "name", "", "policy name (required on create)")
	cmd.Flags().StringVar(&f.Decision, "decision", "", "policy decision: "+strings.Join(cloudflare.AccessPolicyDecisionValues, ", "))
	_ = cmd.RegisterFlagCompletionFunc("decision", cmdutil.EnumsOf(cloudflare.AccessPolicyDecisionValues))
	cmd.Flags().StringVar(&f.Include, "include", "", "include rules as a JSON array (required on create), inline or @file")
	cmd.Flags().StringVar(&f.Exclude, "exclude", "", "exclude rules as a JSON array, inline or @file")
	cmd.Flags().StringVar(&f.Require, "require", "", "require rules as a JSON array, inline or @file")
	cmd.Flags().StringVar(&f.SessionDuration, "session-duration", "", "session duration (for example 24h)")
	cmd.Flags().Int64Var(&f.Precedence, "precedence", 0, "evaluation precedence")
	cmd.Flags().BoolVar(&f.ApprovalRequired, "approval-required", false, "require approval before granting access")
	cmd.Flags().BoolVar(&f.IsolationRequired, "isolation-required", false, "require isolated browsing")
	cmd.Flags().BoolVar(&f.PurposeJustRequired, "purpose-justification-required", false, "require a purpose justification")
	cmd.Flags().StringVar(&f.PurposePrompt, "purpose-justification-prompt", "", "prompt shown when asking for a justification")
	cmd.Flags().StringVar(&f.Settings, "settings", "", "additional policy fields as a JSON object, inline or @file")
}

func (f *policyFlagValues) overrides(cmd *cobra.Command) (map[string]any, error) {
	body := map[string]any{}
	changed := func(name string) bool { return cmd.Flags().Changed(name) }
	if changed("name") {
		body["name"] = f.Name
	}
	if changed("decision") {
		if !contains(cloudflare.AccessPolicyDecisionValues, f.Decision) {
			return nil, errors.Usage("invalid --decision %q (supported: %s)", f.Decision, strings.Join(cloudflare.AccessPolicyDecisionValues, ", "))
		}
		body["decision"] = f.Decision
	}
	for _, item := range []struct {
		flag  string
		value string
		key   string
	}{
		{"include", f.Include, "include"},
		{"exclude", f.Exclude, "exclude"},
		{"require", f.Require, "require"},
	} {
		if !changed(item.flag) {
			continue
		}
		arr, err := parseJSONArrayList(item.flag, item.value)
		if err != nil {
			return nil, err
		}
		body[item.key] = arr
	}
	if changed("session-duration") {
		body["session_duration"] = f.SessionDuration
	}
	if changed("precedence") {
		body["precedence"] = f.Precedence
	}
	if changed("approval-required") {
		body["approval_required"] = f.ApprovalRequired
	}
	if changed("isolation-required") {
		body["isolation_required"] = f.IsolationRequired
	}
	if changed("purpose-justification-required") {
		body["purpose_justification_required"] = f.PurposeJustRequired
	}
	if changed("purpose-justification-prompt") {
		body["purpose_justification_prompt"] = f.PurposePrompt
	}
	if changed("settings") {
		extra, err := parseSecretCarryingSettings(f.rt, "settings", f.Settings)
		if err != nil {
			return nil, err
		}
		for k, v := range extra {
			body[k] = v
		}
	}
	return body, nil
}

func validatePolicyCreate(cmd *cobra.Command, f *policyFlagValues) error {
	if f.Name == "" {
		return errors.Usage("--name is required")
	}
	if f.Decision == "" {
		return errors.Usage("--decision is required")
	}
	if !cmd.Flags().Changed("include") {
		return errors.Usage("--include is required (JSON array of rules)")
	}
	return nil
}

// newAccessPolicyGroup builds `zero-trust access policy ...`: reusable
// account-level policies (/accounts/{a}/access/policies).
func newAccessPolicyGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Reusable account-level Access policies",
		Long:  "Reusable Access policies, shared by applications (/accounts/{account_id}/access/policies). Application-scoped policies live under `zero-trust access app policy`.",
	}
	cmd.AddCommand(newAccessPolicyList(rt))
	cmd.AddCommand(newAccessPolicyGet(rt))
	cmd.AddCommand(newAccessPolicyCreate(rt))
	cmd.AddCommand(newAccessPolicyUpdate(rt))
	cmd.AddCommand(newAccessPolicyDelete(rt))
	return cmd
}

func newAccessPolicyList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List reusable Access policies",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListAccessPolicies(cmd.Context(), ref.ID, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, reusablePolicyHeaders(), reusablePolicyRow)
		},
	}
}

func newAccessPolicyGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get POLICY_ID",
		Short: "Show one reusable Access policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetAccessPolicy(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, reusablePolicyHeaders(), reusablePolicyRow)
		},
	}
}

func newAccessPolicyCreate(rt *app.Runtime) *cobra.Command {
	var f policyFlagValues
	cmd := &cobra.Command{
		Use:   "create --name NAME --decision DECISION --include @rules.json",
		Short: "Create a reusable Access policy",
		Long: "Create a reusable account-level Access policy.\n\n" +
			"Example:\n" +
			"  flareadm zero-trust access policy create --name \"office only\" \\\n" +
			"    --decision allow --include @include.json\n\n" +
			"--include/--exclude/--require take Cloudflare rules arrays verbatim, so rule\n" +
			"criteria this CLI does not model are preserved.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validatePolicyCreate(cmd, &f); err != nil {
				return err
			}
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would create access policy "+f.Name)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateAccessPolicy(cmd.Context(), ref.ID, body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, reusablePolicyHeaders(), reusablePolicyRow)
		},
	}
	addPolicyFlags(rt, cmd, &f)
	return cmd
}

func newAccessPolicyUpdate(rt *app.Runtime) *cobra.Command {
	var f policyFlagValues
	cmd := &cobra.Command{
		Use:   "update POLICY_ID",
		Short: "Update a reusable Access policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if len(body) == 0 {
				return errors.Usage("nothing to update; pass at least one policy flag or --settings")
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would update access policy "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateAccessPolicy(cmd.Context(), ref.ID, args[0], body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, reusablePolicyHeaders(), reusablePolicyRow)
		},
	}
	addPolicyFlags(rt, cmd, &f)
	return cmd
}

func newAccessPolicyDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete POLICY_ID",
		Short: "Delete a reusable Access policy",
		Long: "Delete a reusable Access policy. Destructive: prompts for confirmation\n" +
			"unless --yes is given; --dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetAccessPolicy(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would delete access policy "+existing.Item.Name)
			}
			if err := rt.Confirm("Delete access policy " + existing.Item.Name + "?"); err != nil {
				return err
			}
			if err := client.DeleteAccessPolicy(cmd.Context(), ref.ID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted access policy %s", args[0])
			return nil
		},
	}
	return cmd
}

// newAccessAppPolicyGroup builds `zero-trust access app policy ...`:
// policies scoped to a single application.
func newAccessAppPolicyGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Application-scoped Access policies",
		Long:  "Access policies of one application (/accounts/{account_id}/access/apps/{app_id}/policies).",
	}
	cmd.AddCommand(newAccessAppPolicyList(rt))
	cmd.AddCommand(newAccessAppPolicyGet(rt))
	cmd.AddCommand(newAccessAppPolicyCreate(rt))
	cmd.AddCommand(newAccessAppPolicyUpdate(rt))
	cmd.AddCommand(newAccessAppPolicyDelete(rt))
	return cmd
}

func newAccessAppPolicyList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list APP_ID",
		Short: "List an application's policies",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListAccessApplicationPolicies(cmd.Context(), ref.ID, args[0], rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, accessPolicyHeaders(), accessPolicyRow)
		},
	}
}

func newAccessAppPolicyGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get APP_ID POLICY_ID",
		Short: "Show one application policy",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetAccessApplicationPolicy(cmd.Context(), ref.ID, args[0], args[1])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, accessPolicyHeaders(), accessPolicyRow)
		},
	}
}

func newAccessAppPolicyCreate(rt *app.Runtime) *cobra.Command {
	var f policyFlagValues
	cmd := &cobra.Command{
		Use:   "create APP_ID --name NAME --decision DECISION --include @rules.json",
		Short: "Create an application policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validatePolicyCreate(cmd, &f); err != nil {
				return err
			}
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would create access policy "+f.Name+" on application "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateAccessApplicationPolicy(cmd.Context(), ref.ID, args[0], body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, accessPolicyHeaders(), accessPolicyRow)
		},
	}
	addPolicyFlags(rt, cmd, &f)
	return cmd
}

func newAccessAppPolicyUpdate(rt *app.Runtime) *cobra.Command {
	var f policyFlagValues
	cmd := &cobra.Command{
		Use:   "update APP_ID POLICY_ID",
		Short: "Update an application policy",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if len(body) == 0 {
				return errors.Usage("nothing to update; pass at least one policy flag or --settings")
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would update access policy "+args[1]+" on application "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateAccessApplicationPolicy(cmd.Context(), ref.ID, args[0], args[1], body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, accessPolicyHeaders(), accessPolicyRow)
		},
	}
	addPolicyFlags(rt, cmd, &f)
	return cmd
}

func newAccessAppPolicyDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete APP_ID POLICY_ID",
		Short: "Delete an application policy",
		Long: "Delete one application policy. Destructive: prompts for confirmation\n" +
			"unless --yes is given; --dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetAccessApplicationPolicy(cmd.Context(), ref.ID, args[0], args[1])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would delete access policy "+existing.Item.Name+" from application "+args[0])
			}
			if err := rt.Confirm("Delete access policy " + existing.Item.Name + "?"); err != nil {
				return err
			}
			if err := client.DeleteAccessApplicationPolicy(cmd.Context(), ref.ID, args[0], args[1]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted access policy %s", args[1])
			return nil
		},
	}
	return cmd
}
