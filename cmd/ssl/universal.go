package ssl

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/output"
)

func universalRow(u cloudflare.UniversalSSL) []string {
	return []string{yesNo(u.Enabled)}
}

func newUniversalGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "universal",
		Short: "Universal SSL",
	}
	cmd.AddCommand(newUniversalGet(rt))
	cmd.AddCommand(newUniversalSet(rt, "enable", true))
	cmd.AddCommand(newUniversalSet(rt, "disable", false))
	return cmd
}

func newUniversalGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Show the Universal SSL setting of a zone",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetUniversalSSL(cmd.Context(), zoneID)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"ENABLED"}, universalRow)
		},
	}
}

func newUniversalSet(rt *app.Runtime, verb string, enabled bool) *cobra.Command {
	state := "enable"
	if !enabled {
		state = "disable"
	}
	return &cobra.Command{
		Use:   verb,
		Short: state + " Universal SSL for a zone",
		Long: state + " Universal SSL for a zone.\n\n" +
			"Disabling Universal SSL removes the currently active Universal SSL\n" +
			"certificates from the edge; visitors may lose HTTPS access unless a\n" +
			"custom or advanced certificate is active.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				line := fmt.Sprintf("Would %s Universal SSL for zone %s", state, zoneID)
				if rt.Format() == output.Table {
					_, _ = fmt.Fprintln(rt.Out, line)
					return nil
				}
				return rt.Printer().Emit(map[string]string{"preview": line})
			}
			res, err := client.SetUniversalSSL(cmd.Context(), zoneID, enabled)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"ENABLED"}, universalRow)
		},
	}
}
