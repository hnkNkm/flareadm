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

func gatewayRuleRow(r cloudflare.GatewayRule) []string {
	return []string{r.ID, r.Name, r.Action, strconv.FormatBool(r.Enabled), strconv.FormatInt(r.Precedence, 10), r.Traffic}
}

func gatewayRuleHeaders() []string {
	return []string{"ID", "NAME", "ACTION", "ENABLED", "PRECEDENCE", "TRAFFIC"}
}

// ruleFlagValues collects the shared Gateway rule flags.
type ruleFlagValues struct {
	rt                 *app.Runtime
	Name               string
	Action             string
	Description        string
	Traffic            string
	Identity           string
	DevicePosture      string
	Filters            string
	RuleSettings       string
	Schedule           string
	Settings           string
	ExpiresAt          string
	ExpirationDuration int64
	Precedence         int64
	Enabled            bool
}

func addRuleFlags(rt *app.Runtime, cmd *cobra.Command, f *ruleFlagValues) {
	f.rt = rt
	cmd.Flags().StringVar(&f.Name, "name", "", "rule name (required on create)")
	cmd.Flags().StringVar(&f.Action, "action", "", "rule action: "+strings.Join(cloudflare.GatewayRuleActionValues, ", "))
	_ = cmd.RegisterFlagCompletionFunc("action", cmdutil.EnumsOf(cloudflare.GatewayRuleActionValues))
	cmd.Flags().StringVar(&f.Description, "description", "", "rule description")
	cmd.Flags().StringVar(&f.Traffic, "traffic", "", "traffic expression (for example any(net 192.0.2.0/24))")
	cmd.Flags().StringVar(&f.Identity, "identity", "", "identity expression (for example any(identity.email matches \"@example.com\"))")
	cmd.Flags().StringVar(&f.DevicePosture, "device-posture", "", "device posture rule ids, comma-separated or an expression")
	cmd.Flags().BoolVar(&f.Enabled, "enabled", false, "enable the rule (use --enabled=false to disable)")
	cmd.Flags().Int64Var(&f.Precedence, "precedence", 0, "evaluation precedence")
	cmd.Flags().StringVar(&f.Filters, "filters", "", "filter definitions as a JSON array, inline or @file")
	cmd.Flags().StringVar(&f.RuleSettings, "rule-settings", "", "rule settings object as JSON, inline or @file")
	cmd.Flags().StringVar(&f.Schedule, "schedule", "", "schedule object as JSON, inline or @file")
	cmd.Flags().StringVar(&f.ExpiresAt, "expires-at", "", "RFC3339 time when the rule stops applying")
	cmd.Flags().Int64Var(&f.ExpirationDuration, "expiration-duration", 0, "default active duration in minutes (requires --expires-at)")
	cmd.Flags().StringVar(&f.Settings, "settings", "", "additional rule fields as a JSON object, inline or @file")
}

func (f *ruleFlagValues) overrides(cmd *cobra.Command) (map[string]any, error) {
	body := map[string]any{}
	changed := func(name string) bool { return cmd.Flags().Changed(name) }
	if changed("name") {
		body["name"] = f.Name
	}
	if changed("action") {
		if !contains(cloudflare.GatewayRuleActionValues, f.Action) {
			return nil, errors.Usage("invalid --action %q (supported: %s)", f.Action, strings.Join(cloudflare.GatewayRuleActionValues, ", "))
		}
		body["action"] = f.Action
	}
	if changed("description") {
		body["description"] = f.Description
	}
	if changed("traffic") {
		body["traffic"] = f.Traffic
	}
	if changed("identity") {
		body["identity"] = f.Identity
	}
	if changed("device-posture") {
		body["device_posture"] = f.DevicePosture
	}
	if changed("enabled") {
		body["enabled"] = f.Enabled
	}
	if changed("precedence") {
		body["precedence"] = f.Precedence
	}
	for _, item := range []struct {
		flag  string
		value string
		key   string
	}{
		{"filters", f.Filters, "filters"},
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
	for _, item := range []struct {
		flag  string
		value string
		key   string
	}{
		{"rule-settings", f.RuleSettings, "rule_settings"},
		{"schedule", f.Schedule, "schedule"},
	} {
		if !changed(item.flag) {
			continue
		}
		obj, err := parseSecretCarryingObject(f.rt, item.flag, item.value)
		if err != nil {
			return nil, err
		}
		body[item.key] = obj
	}
	if changed("expires-at") || changed("expiration-duration") {
		if !changed("expires-at") {
			return nil, errors.Usage("--expires-at is required when --expiration-duration is set")
		}
		expiration := map[string]any{"expires_at": f.ExpiresAt}
		if changed("expiration-duration") {
			expiration["duration"] = f.ExpirationDuration
		}
		body["expiration"] = expiration
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

func newGatewayGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gateway",
		Short: "Zero Trust Gateway (rules, lists, locations)",
	}
	cmd.AddCommand(newGatewayRuleGroup(rt))
	cmd.AddCommand(newGatewayListGroup(rt))
	cmd.AddCommand(newGatewayLocationGroup(rt))
	return cmd
}

func newGatewayRuleGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rule",
		Short: "Gateway policies (rules)",
		Long:  "Gateway policies (/accounts/{account_id}/gateway/rules), also known as Gateway rules.",
	}
	cmd.AddCommand(newGatewayRuleList(rt))
	cmd.AddCommand(newGatewayRuleGet(rt))
	cmd.AddCommand(newGatewayRuleCreate(rt))
	cmd.AddCommand(newGatewayRuleUpdate(rt))
	cmd.AddCommand(newGatewayRuleDelete(rt))
	return cmd
}

func newGatewayRuleList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List Gateway rules",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListGatewayRules(cmd.Context(), ref.ID, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, gatewayRuleHeaders(), gatewayRuleRow)
		},
	}
}

func newGatewayRuleGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get RULE_ID",
		Short: "Show one Gateway rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetGatewayRule(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, gatewayRuleHeaders(), gatewayRuleRow)
		},
	}
}

func newGatewayRuleCreate(rt *app.Runtime) *cobra.Command {
	var f ruleFlagValues
	cmd := &cobra.Command{
		Use:   "create --name NAME --action ACTION",
		Short: "Create a Gateway rule",
		Long: "Create a Gateway policy.\n\n" +
			"Example:\n" +
			"  flareadm zero-trust gateway rule create --name \"block malware\" \\\n" +
			"    --action block --traffic 'any(dns.security_category[*] in {\"malware\"})'",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.Name == "" {
				return errors.Usage("--name is required")
			}
			if f.Action == "" {
				return errors.Usage("--action is required")
			}
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would create Gateway rule "+f.Name)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateGatewayRule(cmd.Context(), ref.ID, body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, gatewayRuleHeaders(), gatewayRuleRow)
		},
	}
	addRuleFlags(rt, cmd, &f)
	return cmd
}

func newGatewayRuleUpdate(rt *app.Runtime) *cobra.Command {
	var f ruleFlagValues
	cmd := &cobra.Command{
		Use:   "update RULE_ID",
		Short: "Update a Gateway rule",
		Long: "Update a Gateway policy. Provided fields are merged into the current rule and\n" +
			"the result is PUT, so fields this CLI does not model are preserved.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if len(body) == 0 {
				return errors.Usage("nothing to update; pass at least one rule flag or --settings")
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would update Gateway rule "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateGatewayRule(cmd.Context(), ref.ID, args[0], body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, gatewayRuleHeaders(), gatewayRuleRow)
		},
	}
	addRuleFlags(rt, cmd, &f)
	return cmd
}

func newGatewayRuleDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete RULE_ID",
		Short: "Delete a Gateway rule",
		Long: "Delete a Gateway policy. Destructive: prompts for confirmation unless --yes\n" +
			"is given; --dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetGatewayRule(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would delete Gateway rule "+existing.Item.Name)
			}
			if err := rt.Confirm("Delete Gateway rule " + existing.Item.Name + "?"); err != nil {
				return err
			}
			if err := client.DeleteGatewayRule(cmd.Context(), ref.ID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted Gateway rule %s", args[0])
			return nil
		},
	}
	return cmd
}
