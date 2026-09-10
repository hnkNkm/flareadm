// Package healthcheck implements `flareadm healthcheck ...`: zone-scoped
// Cloudflare health checks and their previews.
package healthcheck

import (
	"encoding/json"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

// New builds the healthcheck command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "healthcheck",
		Short: "Cloudflare health checks",
		Long:  "Zone-scoped Cloudflare health checks (/zones/{zone_id}/healthchecks). The zone comes from --zone or the profile default.",
	}
	cmd.AddCommand(newList(rt))
	cmd.AddCommand(newGet(rt))
	cmd.AddCommand(newCreate(rt))
	cmd.AddCommand(newUpdate(rt))
	cmd.AddCommand(newDelete(rt))
	cmd.AddCommand(newPreviewGroup(rt))
	return cmd
}

func row(h cloudflare.Healthcheck) []string {
	return []string{h.ID, h.Name, h.Address, h.Type, h.Status, strconv.FormatBool(h.Suspended)}
}

func headers() []string {
	return []string{"ID", "NAME", "ADDRESS", "TYPE", "STATUS", "SUSPENDED"}
}

type flagValues struct {
	rt                 *app.Runtime
	Name               string
	Address            string
	Type               string
	Description        string
	CheckRegions       string
	HTTPConfig         string
	TCPConfig          string
	Settings           string
	Interval           int64
	Retries            int64
	Timeout            int64
	ConsecutiveFails   int64
	ConsecutiveSuccess int64
	Suspended          bool
}

func addFlags(rt *app.Runtime, cmd *cobra.Command, f *flagValues) {
	f.rt = rt
	cmd.Flags().StringVar(&f.Name, "name", "", "health check name (required on create)")
	cmd.Flags().StringVar(&f.Address, "address", "", "hostname or IP to check (required on create)")
	cmd.Flags().StringVar(&f.Type, "type", "", "check type (HTTP, HTTPS, TCP) (required on create)")
	cmd.Flags().StringVar(&f.Description, "description", "", "description")
	cmd.Flags().StringVar(&f.CheckRegions, "check-regions", "", "comma-separated regions to probe from")
	cmd.Flags().Int64Var(&f.Interval, "interval", 0, "seconds between checks")
	cmd.Flags().Int64Var(&f.Retries, "retries", 0, "retries before marking an origin unhealthy")
	cmd.Flags().Int64Var(&f.Timeout, "timeout", 0, "seconds before a check attempt times out")
	cmd.Flags().Int64Var(&f.ConsecutiveFails, "consecutive-fails", 0, "failed attempts before marking unhealthy")
	cmd.Flags().Int64Var(&f.ConsecutiveSuccess, "consecutive-successes", 0, "successful attempts before marking healthy")
	cmd.Flags().BoolVar(&f.Suspended, "suspended", false, "suspend the health check")
	cmd.Flags().StringVar(&f.HTTPConfig, "http-config", "", "HTTP configuration object as JSON, inline or @file (header values are treated as credentials)")
	cmd.Flags().StringVar(&f.TCPConfig, "tcp-config", "", "TCP configuration object as JSON, inline or @file")
	cmd.Flags().StringVar(&f.Settings, "settings", "", "additional fields as a JSON object, inline or @file")
}

func (f *flagValues) overrides(cmd *cobra.Command) (map[string]any, error) {
	body := map[string]any{}
	changed := func(name string) bool { return cmd.Flags().Changed(name) }
	if changed("name") {
		body["name"] = f.Name
	}
	if changed("address") {
		body["address"] = f.Address
	}
	if changed("type") {
		body["type"] = f.Type
	}
	if changed("description") {
		body["description"] = f.Description
	}
	if changed("check-regions") {
		body["check_regions"] = cmdutil.SplitList(f.CheckRegions)
	}
	if changed("interval") {
		body["interval"] = f.Interval
	}
	if changed("retries") {
		body["retries"] = f.Retries
	}
	if changed("timeout") {
		body["timeout"] = f.Timeout
	}
	if changed("consecutive-fails") {
		body["consecutive_fails"] = f.ConsecutiveFails
	}
	if changed("consecutive-successes") {
		body["consecutive_successes"] = f.ConsecutiveSuccess
	}
	if changed("suspended") {
		body["suspended"] = f.Suspended
	}
	if changed("http-config") {
		obj, err := cmdutil.ParseSecretCarryingObject(f.rt, "http-config", f.HTTPConfig)
		if err != nil {
			return nil, err
		}
		cmdutil.ProtectHeaderValues(f.rt, rawToAny(obj))
		body["http_config"] = obj
	}
	if changed("tcp-config") {
		obj, err := cmdutil.ParseSecretCarryingObject(f.rt, "tcp-config", f.TCPConfig)
		if err != nil {
			return nil, err
		}
		body["tcp_config"] = obj
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

// rawToAny decodes a raw JSON value for credential scanning.
func rawToAny(raw json.RawMessage) any {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	return v
}

func newList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List health checks",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListHealthchecks(cmd.Context(), zoneID, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, headers(), row)
		},
	}
}

func newGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get HEALTHCHECK_ID",
		Short: "Show one health check",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetHealthcheck(cmd.Context(), zoneID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, headers(), row)
		},
	}
}

func newCreate(rt *app.Runtime) *cobra.Command {
	var f flagValues
	cmd := &cobra.Command{
		Use:   "create --name NAME --address HOST --type TYPE",
		Short: "Create a health check",
		Long: "Create a zone health check.\n\n" +
			"Example:\n" +
			"  flareadm healthcheck create --zone example.com --name web --address \\\n" +
			"    example.com --type HTTPS --http-config '{\"path\":\"/health\"}'\n\n" +
			"--http-config values under header are registered as protected secrets.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.Name == "" {
				return errors.Usage("--name is required")
			}
			if f.Address == "" {
				return errors.Usage("--address is required")
			}
			if f.Type == "" {
				return errors.Usage("--type is required")
			}
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would create health check "+f.Name+" for "+f.Address)
			}
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateHealthcheck(cmd.Context(), zoneID, body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, headers(), row)
		},
	}
	addFlags(rt, cmd, &f)
	return cmd
}

func newUpdate(rt *app.Runtime) *cobra.Command {
	var f flagValues
	cmd := &cobra.Command{
		Use:   "update HEALTHCHECK_ID",
		Short: "Update a health check",
		Long: "Update a health check. Provided fields are merged into the current check and\n" +
			"the result is PUT, so fields this CLI does not model are preserved.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if len(body) == 0 {
				return errors.Usage("nothing to update; pass at least one health check flag or --settings")
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would update health check "+args[0])
			}
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateHealthcheck(cmd.Context(), zoneID, args[0], body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, headers(), row)
		},
	}
	addFlags(rt, cmd, &f)
	return cmd
}

func newDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete HEALTHCHECK_ID",
		Short: "Delete a health check",
		Long: "Delete a health check. Destructive: prompts for confirmation unless --yes is\n" +
			"given; --dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetHealthcheck(cmd.Context(), zoneID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would delete health check "+existing.Item.Name)
			}
			if err := rt.Confirm("Delete health check " + existing.Item.Name + "?"); err != nil {
				return err
			}
			if err := client.DeleteHealthcheck(cmd.Context(), zoneID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted health check %s", args[0])
			return nil
		},
	}
	return cmd
}

func newPreviewGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "preview",
		Short: "Health check previews",
		Long:  "Health check previews (/zones/{zone_id}/healthchecks/preview): transient checks used to validate settings before creating one.",
	}
	cmd.AddCommand(newPreviewCreate(rt))
	cmd.AddCommand(newPreviewGet(rt))
	cmd.AddCommand(newPreviewDelete(rt))
	return cmd
}

func newPreviewCreate(rt *app.Runtime) *cobra.Command {
	var f flagValues
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a health check preview",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if len(body) == 0 {
				return errors.Usage("nothing to preview; pass at least one health check flag or --settings")
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would create a health check preview")
			}
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateHealthcheckPreview(cmd.Context(), zoneID, body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, headers(), row)
		},
	}
	addFlags(rt, cmd, &f)
	return cmd
}

func newPreviewGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get PREVIEW_ID",
		Short: "Show one health check preview",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetHealthcheckPreview(cmd.Context(), zoneID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, headers(), row)
		},
	}
}

func newPreviewDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete PREVIEW_ID",
		Short: "Delete a health check preview",
		Long: "Delete a preview. Destructive: prompts for confirmation unless --yes is given;\n" +
			"--dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would delete health check preview "+args[0])
			}
			if err := rt.Confirm("Delete health check preview " + args[0] + "?"); err != nil {
				return err
			}
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			if err := client.DeleteHealthcheckPreview(cmd.Context(), zoneID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted health check preview %s", args[0])
			return nil
		},
	}
	return cmd
}
