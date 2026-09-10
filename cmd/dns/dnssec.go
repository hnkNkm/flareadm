package dns

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
)

func dnssecRow(d cloudflare.DNSSEC) []string {
	return []string{d.Status, d.Algorithm, d.KeyType}
}

// newDNSSECGroup builds `dns dnssec`.
func newDNSSECGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dnssec",
		Short: "DNSSEC settings for a zone",
	}
	cmd.AddCommand(
		newDNSSECGet(rt),
		newDNSSECSet(rt, "enable", cloudflare.DNSSECStatusActive),
		newDNSSECSet(rt, "disable", cloudflare.DNSSECStatusDisabled),
	)
	return cmd
}

func newDNSSECGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Show the DNSSEC status of a zone",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetDNSSEC(cmd.Context(), zoneID)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"STATUS", "ALGORITHM", "KEY TYPE"}, dnssecRow)
		},
	}
}

func newDNSSECSet(rt *app.Runtime, verb, status string) *cobra.Command {
	return &cobra.Command{
		Use:   verb,
		Short: "DNSSEC status: " + status,
		Long:  "Set the zone DNSSEC status to " + status + ".",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.SetDNSSECStatus(cmd.Context(), zoneID, status)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"STATUS", "ALGORITHM", "KEY TYPE"}, dnssecRow)
		},
	}
}
