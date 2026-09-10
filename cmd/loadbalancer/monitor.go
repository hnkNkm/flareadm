package loadbalancer

import (
	"encoding/json"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

type monitorFlagValues struct {
	rt              *app.Runtime
	Type            string
	Description     string
	Method          string
	Path            string
	ExpectedBody    string
	ExpectedCodes   string
	ProbeZone       string
	Header          string
	Settings        string
	Port            int64
	Timeout         int64
	Retries         int64
	Interval        int64
	ConsecutiveUp   int64
	ConsecutiveDown int64
	FollowRedirects bool
	AllowInsecure   bool
}

func addMonitorFlags(rt *app.Runtime, cmd *cobra.Command, f *monitorFlagValues) {
	f.rt = rt
	cmd.Flags().StringVar(&f.Type, "type", "", "probe type: http, https, tcp, udp_icmp, icmp_ping, smtp (required on create)")
	cmd.Flags().StringVar(&f.Description, "description", "", "description")
	cmd.Flags().StringVar(&f.Method, "method", "", "HTTP method to probe with")
	cmd.Flags().StringVar(&f.Path, "path", "", "HTTP path to probe")
	cmd.Flags().Int64Var(&f.Port, "port", 0, "port to probe")
	cmd.Flags().Int64Var(&f.Timeout, "timeout", 0, "seconds before a probe times out")
	cmd.Flags().Int64Var(&f.Retries, "retries", 0, "retries before marking unhealthy")
	cmd.Flags().Int64Var(&f.Interval, "interval", 0, "seconds between probes")
	cmd.Flags().Int64Var(&f.ConsecutiveUp, "consecutive-up", 0, "successful probes before marking healthy")
	cmd.Flags().Int64Var(&f.ConsecutiveDown, "consecutive-down", 0, "failed probes before marking unhealthy")
	cmd.Flags().BoolVar(&f.FollowRedirects, "follow-redirects", false, "follow HTTP redirects")
	cmd.Flags().BoolVar(&f.AllowInsecure, "allow-insecure", false, "accept insecure TLS certificates")
	cmd.Flags().StringVar(&f.ExpectedBody, "expected-body", "", "substring expected in the response body")
	cmd.Flags().StringVar(&f.ExpectedCodes, "expected-codes", "", "expected HTTP status codes (for example 2xx)")
	cmd.Flags().StringVar(&f.ProbeZone, "probe-zone", "", "zone to probe from")
	cmd.Flags().StringVar(&f.Header, "header", "", "probe request headers as a JSON object, inline or @file (values are treated as credentials)")
	cmd.Flags().StringVar(&f.Settings, "settings", "", "additional monitor fields as a JSON object, inline or @file")
}

func (f *monitorFlagValues) overrides(cmd *cobra.Command) (map[string]any, error) {
	body := map[string]any{}
	changed := func(name string) bool { return cmd.Flags().Changed(name) }
	if changed("type") {
		if !contains(cloudflare.LoadBalancerMonitorTypeValues, f.Type) {
			return nil, errors.Usage("invalid --type %q (supported: %s)", f.Type, joinList(cloudflare.LoadBalancerMonitorTypeValues))
		}
		body["type"] = f.Type
	}
	if changed("description") {
		body["description"] = f.Description
	}
	if changed("method") {
		body["method"] = f.Method
	}
	if changed("path") {
		body["path"] = f.Path
	}
	if changed("port") {
		body["port"] = f.Port
	}
	if changed("timeout") {
		body["timeout"] = f.Timeout
	}
	if changed("retries") {
		body["retries"] = f.Retries
	}
	if changed("interval") {
		body["interval"] = f.Interval
	}
	if changed("consecutive-up") {
		body["consecutive_up"] = f.ConsecutiveUp
	}
	if changed("consecutive-down") {
		body["consecutive_down"] = f.ConsecutiveDown
	}
	if changed("follow-redirects") {
		body["follow_redirects"] = f.FollowRedirects
	}
	if changed("allow-insecure") {
		body["allow_insecure"] = f.AllowInsecure
	}
	if changed("expected-body") {
		body["expected_body"] = f.ExpectedBody
	}
	if changed("expected-codes") {
		body["expected_codes"] = f.ExpectedCodes
	}
	if changed("probe-zone") {
		body["probe_zone"] = f.ProbeZone
	}
	if changed("header") {
		obj, err := cmdutil.ParseSecretCarryingObject(f.rt, "header", f.Header)
		if err != nil {
			return nil, err
		}
		cmdutil.ProtectHeaderMap(f.rt, decodeRaw(obj))
		body["header"] = obj
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

// monitorLabel prefers the monitor's type, falling back to its id.
func monitorLabel(m cloudflare.LoadBalancerMonitor, id string) string {
	if m.Type != "" {
		return m.Type + " monitor " + id
	}
	return id
}

// decodeRaw decodes a raw JSON value for credential scanning.
func decodeRaw(raw json.RawMessage) any {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	return v
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func newMonitorGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Monitors",
		Long:  "Origin monitors (/accounts/{account_id}/load_balancers/monitors). Monitors are account-scoped.",
	}
	cmd.AddCommand(newMonitorList(rt))
	cmd.AddCommand(newMonitorGet(rt))
	cmd.AddCommand(newMonitorCreate(rt))
	cmd.AddCommand(newMonitorUpdate(rt))
	cmd.AddCommand(newMonitorDelete(rt))
	return cmd
}

func newMonitorList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List monitors",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListLoadBalancerMonitors(cmd.Context(), ref.ID, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, monitorHeaders(), monitorRow)
		},
	}
}

func newMonitorGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get MONITOR_ID",
		Short: "Show one monitor",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetLoadBalancerMonitor(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, monitorHeaders(), monitorRow)
		},
	}
}

func newMonitorCreate(rt *app.Runtime) *cobra.Command {
	var f monitorFlagValues
	cmd := &cobra.Command{
		Use:   "create --type TYPE",
		Short: "Create a monitor",
		Long: "Create a monitor.\n\n" +
			"Example:\n" +
			"  flareadm load-balancer monitor create --type https --path /health \\\n" +
			"    --expected-codes 200 --interval 60\n\n" +
			"--header values are registered as protected secrets.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.Type == "" {
				return errors.Usage("--type is required")
			}
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would create monitor of type "+f.Type)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateLoadBalancerMonitor(cmd.Context(), ref.ID, body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, monitorHeaders(), monitorRow)
		},
	}
	addMonitorFlags(rt, cmd, &f)
	return cmd
}

func newMonitorUpdate(rt *app.Runtime) *cobra.Command {
	var f monitorFlagValues
	cmd := &cobra.Command{
		Use:   "update MONITOR_ID",
		Short: "Update a monitor",
		Long:  "Partially update a monitor: only the provided fields change.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if len(body) == 0 {
				return errors.Usage("nothing to update; pass at least one monitor flag or --settings")
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would update monitor "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateLoadBalancerMonitor(cmd.Context(), ref.ID, args[0], body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, monitorHeaders(), monitorRow)
		},
	}
	addMonitorFlags(rt, cmd, &f)
	return cmd
}

func newMonitorDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete MONITOR_ID",
		Short: "Delete a monitor",
		Long: "Delete a monitor. Destructive: prompts for confirmation unless --yes is given;\n" +
			"--dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetLoadBalancerMonitor(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would delete monitor "+monitorLabel(existing.Item, args[0]))
			}
			if err := rt.Confirm("Delete monitor " + monitorLabel(existing.Item, args[0]) + "?"); err != nil {
				return err
			}
			if err := client.DeleteLoadBalancerMonitor(cmd.Context(), ref.ID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted monitor %s", args[0])
			return nil
		},
	}
	return cmd
}
