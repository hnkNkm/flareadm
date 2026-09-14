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

func devicePostureRow(r cloudflare.DevicePostureRule) []string {
	return []string{r.ID, r.Name, r.Type, strconv.FormatBool(r.Enabled), r.Schedule}
}

func devicePostureHeaders() []string {
	return []string{"ID", "NAME", "TYPE", "ENABLED", "SCHEDULE"}
}

type postureFlagValues struct {
	rt          *app.Runtime
	Name        string
	Type        string
	Description string
	Expiration  string
	Schedule    string
	Input       string
	Match       string
	Settings    string
}

func addPostureFlags(rt *app.Runtime, cmd *cobra.Command, f *postureFlagValues) {
	f.rt = rt
	cmd.Flags().StringVar(&f.Name, "name", "", "rule name (required on create)")
	cmd.Flags().StringVar(&f.Type, "type", "", "posture check type (required on create): "+strings.Join(cloudflare.DevicePostureTypeValues, ", "))
	_ = cmd.RegisterFlagCompletionFunc("type", cmdutil.EnumsOf(cloudflare.DevicePostureTypeValues))
	cmd.Flags().StringVar(&f.Description, "description", "", "rule description")
	cmd.Flags().StringVar(&f.Expiration, "expiration", "", "how long a device check stays valid (for example 24h)")
	cmd.Flags().StringVar(&f.Schedule, "schedule", "", "check schedule")
	cmd.Flags().StringVar(&f.Input, "input", "", "check input object as JSON, inline or @file")
	cmd.Flags().StringVar(&f.Match, "match", "", "match rules as a JSON array, inline or @file")
	cmd.Flags().StringVar(&f.Settings, "settings", "", "additional posture fields as a JSON object, inline or @file")
}

func (f *postureFlagValues) overrides(cmd *cobra.Command) (map[string]any, error) {
	body := map[string]any{}
	changed := func(name string) bool { return cmd.Flags().Changed(name) }
	if changed("name") {
		body["name"] = f.Name
	}
	if changed("type") {
		if !contains(cloudflare.DevicePostureTypeValues, f.Type) {
			return nil, errors.Usage("invalid --type %q (supported: %s)", f.Type, strings.Join(cloudflare.DevicePostureTypeValues, ", "))
		}
		body["type"] = f.Type
	}
	if changed("description") {
		body["description"] = f.Description
	}
	if changed("expiration") {
		body["expiration"] = f.Expiration
	}
	if changed("schedule") {
		body["schedule"] = f.Schedule
	}
	if changed("input") {
		obj, err := parseSecretCarryingObject(f.rt, "input", f.Input)
		if err != nil {
			return nil, err
		}
		body["input"] = obj
	}
	if changed("match") {
		arr, err := parseJSONArrayList("match", f.Match)
		if err != nil {
			return nil, err
		}
		body["match"] = arr
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

func newDevicePostureGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "posture",
		Short: "Device posture rules",
		Long:  "Device posture rules (/accounts/{account_id}/devices/posture).",
	}
	cmd.AddCommand(newDevicePostureList(rt))
	cmd.AddCommand(newDevicePostureGet(rt))
	cmd.AddCommand(newDevicePostureCreate(rt))
	cmd.AddCommand(newDevicePostureUpdate(rt))
	cmd.AddCommand(newDevicePostureDelete(rt))
	return cmd
}

func newDevicePostureList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List device posture rules",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListDevicePostureRules(cmd.Context(), ref.ID, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, devicePostureHeaders(), devicePostureRow)
		},
	}
}

func newDevicePostureGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get RULE_ID",
		Short: "Show one device posture rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetDevicePostureRule(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, devicePostureHeaders(), devicePostureRow)
		},
	}
}

func newDevicePostureCreate(rt *app.Runtime) *cobra.Command {
	var f postureFlagValues
	cmd := &cobra.Command{
		Use:   "create --name NAME --type TYPE",
		Short: "Create a device posture rule",
		Long: "Create a device posture rule.\n\n" +
			"Example:\n" +
			"  flareadm zero-trust device posture create --name \"disk encrypted\" \\\n" +
			"    --type disk_encryption --input '{\"requireAll\":true}'",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.Name == "" {
				return errors.Usage("--name is required")
			}
			if f.Type == "" {
				return errors.Usage("--type is required")
			}
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would create device posture rule "+f.Name)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateDevicePostureRule(cmd.Context(), ref.ID, body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, devicePostureHeaders(), devicePostureRow)
		},
	}
	addPostureFlags(rt, cmd, &f)
	return cmd
}

func newDevicePostureUpdate(rt *app.Runtime) *cobra.Command {
	var f postureFlagValues
	cmd := &cobra.Command{
		Use:   "update RULE_ID",
		Short: "Update a device posture rule",
		Long: "Update a device posture rule. Provided fields are merged into the current rule\n" +
			"and the result is PUT, so fields this CLI does not model are preserved.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if len(body) == 0 {
				return errors.Usage("nothing to update; pass at least one posture flag or --settings")
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would update device posture rule "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateDevicePostureRule(cmd.Context(), ref.ID, args[0], body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, devicePostureHeaders(), devicePostureRow)
		},
	}
	addPostureFlags(rt, cmd, &f)
	return cmd
}

func newDevicePostureDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete RULE_ID",
		Short: "Delete a device posture rule",
		Long: "Delete a device posture rule. Destructive: prompts for confirmation unless\n" +
			"--yes is given; --dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetDevicePostureRule(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would delete device posture rule "+existing.Item.Name)
			}
			if err := rt.Confirm("Delete device posture rule " + existing.Item.Name + "?"); err != nil {
				return err
			}
			if err := client.DeleteDevicePostureRule(cmd.Context(), ref.ID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted device posture rule %s", args[0])
			return nil
		},
	}
	return cmd
}
