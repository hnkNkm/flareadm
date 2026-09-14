package ssl

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

func settingRow(s cloudflare.SSLSetting) []string {
	return []string{s.ID, s.Value, yesNo(s.Editable)}
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// settingFlags maps CLI flags to Cloudflare zone setting ids.
var settingFlags = []struct {
	flag    string
	setting string
}{
	{"mode", "ssl"},
	{"min-tls-version", "min_tls_version"},
	{"opportunistic-encryption", "opportunistic_encryption"},
	{"tls-1-3", "tls_1_3"},
	{"always-use-https", "always_use_https"},
	{"automatic-https-rewrites", "automatic_https_rewrites"},
}

func newSettingGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setting",
		Short: "Zone SSL/TLS settings",
	}
	cmd.AddCommand(newSettingGet(rt))
	cmd.AddCommand(newSettingUpdate(rt))
	return cmd
}

// newSettingGet reads one or all SSL/TLS settings of a zone.
func newSettingGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get [NAME]",
		Short: "Show zone SSL/TLS settings",
		Long: "Show the SSL/TLS zone settings. NAME restricts the output to one setting:\n" +
			"always_use_https, automatic_https_rewrites, min_tls_version,\n" +
			"opportunistic_encryption, ssl, tls_1_3.",
		Args: cobra.MaximumNArgs(1),
		// The positional is a zone setting name, never a zone.
		ValidArgsFunction: cmdutil.EnumsOf(cloudflare.SSLSettingsIDs),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			name := ""
			if len(args) == 1 {
				name = args[0]
			}
			res, err := client.ListSSLSettings(cmd.Context(), zoneID, name)
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, []string{"NAME", "VALUE", "EDITABLE"}, settingRow)
		},
	}
}

// newSettingUpdate patches the provided settings.
func newSettingUpdate(rt *app.Runtime) *cobra.Command {
	values := map[string]*string{}
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update zone SSL/TLS settings",
		Long: "Update one or more SSL/TLS zone settings. Every provided flag is patched as\n" +
			"its own setting; omitted settings are left unchanged.\n\n" +
			"Values:\n" +
			"  --mode                     off | flexible | full | strict\n" +
			"  --min-tls-version          1.0 | 1.1 | 1.2 | 1.3\n" +
			"  --tls-1-3                  on | off\n" +
			"  --always-use-https         on | off\n" +
			"  --automatic-https-rewrites on | off\n" +
			"  --opportunistic-encryption on | off",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			updates := map[string]string{}
			for _, sf := range settingFlags {
				v, ok := values[sf.setting]
				if !ok || !cmd.Flags().Changed(sf.flag) {
					continue
				}
				allowed := cloudflare.SSLSettingsAllowed[sf.setting]
				if !contains(allowed, *v) {
					return errors.Usage("invalid value %q for --%s (supported: %s)", *v, sf.flag, strings.Join(allowed, ", "))
				}
				updates[sf.setting] = *v
			}
			if len(updates) == 0 {
				return errors.Usage("nothing to update; pass at least one of --mode, --min-tls-version, --tls-1-3, --always-use-https, --automatic-https-rewrites, --opportunistic-encryption")
			}
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				lines := make([]string, 0, len(updates))
				for id, v := range updates {
					lines = append(lines, fmt.Sprintf("Would set %s = %s", id, v))
				}
				if rt.Format() == output.Table {
					for _, l := range lines {
						_, _ = fmt.Fprintln(rt.Out, l)
					}
					return nil
				}
				return rt.Printer().Emit(map[string]string{"preview": strings.Join(lines, "; ")})
			}
			res, err := client.UpdateSSLSettings(cmd.Context(), zoneID, updates)
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, []string{"NAME", "VALUE", "EDITABLE"}, settingRow)
		},
	}
	for _, sf := range settingFlags {
		v := new(string)
		values[sf.setting] = v
		cmd.Flags().StringVar(v, sf.flag, "", fmt.Sprintf("value for the %s setting", sf.setting))
		_ = cmd.RegisterFlagCompletionFunc(sf.flag, cmdutil.EnumsOf(cloudflare.SSLSettingsAllowed[sf.setting]))
	}
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
