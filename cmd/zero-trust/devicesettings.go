package zerotrust

import (
	"sort"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
)

type settingsFlagValues struct {
	rt                     *app.Runtime
	DisableForTime         float64
	SignalFingerprint      string
	SignalInterval         string
	SignalURL              string
	Settings               string
	GatewayProxyEnabled    bool
	GatewayUDPProxyEnabled bool
	RootCertInstallation   bool
	UseZTVirtualIP         bool
	EmergencySignalEnabled bool
}

func addSettingsFlags(rt *app.Runtime, cmd *cobra.Command, f *settingsFlagValues) {
	f.rt = rt
	cmd.Flags().BoolVar(&f.GatewayProxyEnabled, "gateway-proxy-enabled", false, "route traffic through the Gateway proxy")
	cmd.Flags().BoolVar(&f.GatewayUDPProxyEnabled, "gateway-udp-proxy-enabled", false, "route UDP traffic through the Gateway proxy")
	cmd.Flags().BoolVar(&f.RootCertInstallation, "root-certificate-installation-enabled", false, "install the Cloudflare root certificate on devices")
	cmd.Flags().BoolVar(&f.UseZTVirtualIP, "use-zt-virtual-ip", false, "use the Zero Trust virtual IP range")
	cmd.Flags().BoolVar(&f.EmergencySignalEnabled, "external-emergency-signal-enabled", false, "enable the external emergency signal")
	cmd.Flags().StringVar(&f.SignalFingerprint, "external-emergency-signal-fingerprint", "", "public key fingerprint for the emergency signal")
	cmd.Flags().StringVar(&f.SignalInterval, "external-emergency-signal-interval", "", "emergency signal polling interval (for example 5m)")
	cmd.Flags().StringVar(&f.SignalURL, "external-emergency-signal-url", "", "external emergency signal URL (must be https)")
	cmd.Flags().Float64Var(&f.DisableForTime, "disable-for-time", 0, "minutes the user can disable the client for (0 keeps the API default)")
	cmd.Flags().StringVar(&f.Settings, "settings", "", "additional device settings as a JSON object, inline or @file")
}

func (f *settingsFlagValues) overrides(cmd *cobra.Command) (map[string]any, error) {
	body := map[string]any{}
	changed := func(name string) bool { return cmd.Flags().Changed(name) }
	if changed("gateway-proxy-enabled") {
		body["gateway_proxy_enabled"] = f.GatewayProxyEnabled
	}
	if changed("gateway-udp-proxy-enabled") {
		body["gateway_udp_proxy_enabled"] = f.GatewayUDPProxyEnabled
	}
	if changed("root-certificate-installation-enabled") {
		body["root_certificate_installation_enabled"] = f.RootCertInstallation
	}
	if changed("use-zt-virtual-ip") {
		body["use_zt_virtual_ip"] = f.UseZTVirtualIP
	}
	if changed("external-emergency-signal-enabled") {
		body["external_emergency_signal_enabled"] = f.EmergencySignalEnabled
	}
	if changed("external-emergency-signal-fingerprint") {
		body["external_emergency_signal_fingerprint"] = f.SignalFingerprint
	}
	if changed("external-emergency-signal-interval") {
		body["external_emergency_signal_interval"] = f.SignalInterval
	}
	if changed("external-emergency-signal-url") {
		body["external_emergency_signal_url"] = f.SignalURL
	}
	if changed("disable-for-time") {
		body["disable_for_time"] = f.DisableForTime
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

func newDeviceSettingsGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "settings",
		Short: "Account device settings",
		Long:  "Account device settings (/accounts/{account_id}/devices/settings). Unmapped fields\nare preserved by the read-modify-PUT update.",
	}
	cmd.AddCommand(newDeviceSettingsGet(rt))
	cmd.AddCommand(newDeviceSettingsUpdate(rt))
	return cmd
}

// renderDeviceSettings prints the settings as a two-column table (sorted keys)
// so fields this CLI does not model are visible rather than silently dropped.
func renderDeviceSettings(rt *app.Runtime, settings map[string]any) error {
	if rt.Raw() {
		return nil
	}
	if rt.Format() != output.Table {
		return rt.Printer().Emit(settings)
	}
	keys := make([]string, 0, len(settings))
	for k := range settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rows := make([][]string, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, []string{k, scalarString(settings[k])})
	}
	return rt.Printer().PrintTable([]string{"SETTING", "VALUE"}, rows)
}

func newDeviceSettingsGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Show the account device settings",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetDeviceSettings(cmd.Context(), ref.ID)
			if err != nil {
				return err
			}
			if rt.Raw() {
				return rt.Printer().Raw(res.RawBody)
			}
			return renderDeviceSettings(rt, res.Item)
		},
	}
}

func newDeviceSettingsUpdate(rt *app.Runtime) *cobra.Command {
	var f settingsFlagValues
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update the account device settings",
		Long: "Update device settings. Provided fields are merged into the current settings and\n" +
			"the result is PUT, so fields this CLI does not model are preserved.\n\n" +
			"--settings accepts a JSON object (inline or @file) for fields without a\n" +
			"dedicated flag; it wins over flags for the same key.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if len(body) == 0 {
				return errors.Usage("nothing to update; pass at least one settings flag or --settings")
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would update account device settings")
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateDeviceSettings(cmd.Context(), ref.ID, body)
			if err != nil {
				return err
			}
			if rt.Raw() {
				return rt.Printer().Raw(res.RawBody)
			}
			return renderDeviceSettings(rt, res.Item)
		},
	}
	addSettingsFlags(rt, cmd, &f)
	return cmd
}
