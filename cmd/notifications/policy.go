package notifications

import (
	"strconv"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func policyRow(p cloudflare.AlertingPolicy) []string {
	return []string{p.ID, p.Name, p.AlertType, strconv.FormatBool(p.Enabled), p.AlertInterval}
}

func policyHeaders() []string {
	return []string{"ID", "NAME", "ALERT TYPE", "ENABLED", "INTERVAL"}
}

type policyFlagValues struct {
	rt            *app.Runtime
	Name          string
	AlertType     string
	Description   string
	AlertInterval string
	Mechanisms    string
	Filters       string
	Settings      string
	Enabled       bool
}

func addPolicyFlags(rt *app.Runtime, cmd *cobra.Command, f *policyFlagValues) {
	f.rt = rt
	cmd.Flags().StringVar(&f.Name, "name", "", "policy name (required on create)")
	cmd.Flags().StringVar(&f.AlertType, "alert-type", "", "alert type (for example http_alert_origin_error) (required on create)")
	cmd.Flags().StringVar(&f.Description, "description", "", "description")
	cmd.Flags().StringVar(&f.AlertInterval, "alert-interval", "", "minimum time between notifications")
	cmd.Flags().BoolVar(&f.Enabled, "enabled", false, "enable the policy (required on create; use --enabled=false to disable)")
	cmd.Flags().StringVar(&f.Mechanisms, "mechanisms", "", "delivery mechanisms object (email, pagerduty, webhooks) as JSON (required on create), inline or @file")
	cmd.Flags().StringVar(&f.Filters, "filters", "", "policy filters object as JSON, inline or @file")
	cmd.Flags().StringVar(&f.Settings, "settings", "", "additional policy fields as a JSON object, inline or @file")
}

func (f *policyFlagValues) overrides(cmd *cobra.Command) (map[string]any, error) {
	body := map[string]any{}
	changed := func(name string) bool { return cmd.Flags().Changed(name) }
	if changed("name") {
		body["name"] = f.Name
	}
	if changed("alert-type") {
		body["alert_type"] = f.AlertType
	}
	if changed("description") {
		body["description"] = f.Description
	}
	if changed("alert-interval") {
		body["alert_interval"] = f.AlertInterval
	}
	if changed("enabled") {
		body["enabled"] = f.Enabled
	}
	for _, item := range []struct {
		flag  string
		value string
		key   string
	}{
		{"mechanisms", f.Mechanisms, "mechanisms"},
		{"filters", f.Filters, "filters"},
	} {
		if !changed(item.flag) {
			continue
		}
		obj, err := cmdutil.ParseSecretCarryingObject(f.rt, item.flag, item.value)
		if err != nil {
			return nil, err
		}
		body[item.key] = obj
	}
	if changed("settings") {
		extra, err := cmdutil.ParseSecretCarryingSettings(f.rt, "settings", f.Settings)
		if err != nil {
			return nil, err
		}
		for k, v := range extra {
			body[k] = v
		}
	}
	return body, nil
}

func newPolicyGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Notification policies",
		Long:  "Notification policies (/accounts/{account_id}/alerting/v3/policies).",
	}
	cmd.AddCommand(newPolicyList(rt))
	cmd.AddCommand(newPolicyGet(rt))
	cmd.AddCommand(newPolicyCreate(rt))
	cmd.AddCommand(newPolicyUpdate(rt))
	cmd.AddCommand(newPolicyDelete(rt))
	return cmd
}

func newPolicyList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List notification policies",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListAlertingPolicies(cmd.Context(), ref.ID, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, policyHeaders(), policyRow)
		},
	}
}

func newPolicyGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get POLICY_ID",
		Short: "Show one notification policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetAlertingPolicy(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, policyHeaders(), policyRow)
		},
	}
}

func newPolicyCreate(rt *app.Runtime) *cobra.Command {
	var f policyFlagValues
	cmd := &cobra.Command{
		Use:   "create --name NAME --alert-type TYPE --enabled --mechanisms @mechanisms.json",
		Short: "Create a notification policy",
		Long: "Create a notification policy.\n\n" +
			"Example:\n" +
			"  flareadm notifications policy create --name \"origin errors\" \\\n" +
			"    --alert-type http_alert_origin_error --enabled \\\n" +
			"    --mechanisms '{\"email\":[{\"id\":\"<destination-id>\"}]}'",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.Name == "" {
				return errors.Usage("--name is required")
			}
			if f.AlertType == "" {
				return errors.Usage("--alert-type is required")
			}
			if !cmd.Flags().Changed("enabled") {
				return errors.Usage("--enabled (or --enabled=false) is required")
			}
			if !cmd.Flags().Changed("mechanisms") {
				return errors.Usage("--mechanisms is required (JSON object)")
			}
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would create notification policy "+f.Name+" for alert type "+f.AlertType)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateAlertingPolicy(cmd.Context(), ref.ID, body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, policyHeaders(), policyRow)
		},
	}
	addPolicyFlags(rt, cmd, &f)
	return cmd
}

func newPolicyUpdate(rt *app.Runtime) *cobra.Command {
	var f policyFlagValues
	cmd := &cobra.Command{
		Use:   "update POLICY_ID",
		Short: "Update a notification policy",
		Long: "Update a policy. Provided fields are merged into the current policy and the\n" +
			"result is PUT, so fields this CLI does not model are preserved.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if len(body) == 0 {
				return errors.Usage("nothing to update; pass at least one policy flag or --settings")
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would update notification policy "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateAlertingPolicy(cmd.Context(), ref.ID, args[0], body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, policyHeaders(), policyRow)
		},
	}
	addPolicyFlags(rt, cmd, &f)
	return cmd
}

func newPolicyDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete POLICY_ID",
		Short: "Delete a notification policy",
		Long: "Delete a policy. Destructive: prompts for confirmation unless --yes is given;\n" +
			"--dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetAlertingPolicy(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would delete notification policy "+existing.Item.Name)
			}
			if err := rt.Confirm("Delete notification policy " + existing.Item.Name + "?"); err != nil {
				return err
			}
			if err := client.DeleteAlertingPolicy(cmd.Context(), ref.ID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted notification policy %s", args[0])
			return nil
		},
	}
	return cmd
}
