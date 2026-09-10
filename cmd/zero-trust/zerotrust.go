// Package zerotrust implements `flareadm zero-trust ...`: Cloudflare Tunnel
// administration and Zero Trust account settings.
package zerotrust

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
)

// New builds the zero-trust command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "zero-trust",
		Short: "Zero Trust administration",
		Long:  "Zero Trust administration (Cloudflare Tunnel and account organization settings). Account scope is resolved through the standard account resolution.",
	}
	cmd.AddCommand(newAccessGroup(rt))
	cmd.AddCommand(newDeviceGroup(rt))
	cmd.AddCommand(newGatewayGroup(rt))
	cmd.AddCommand(newTunnelGroup(rt))
	cmd.AddCommand(newRouteGroup(rt))
	cmd.AddCommand(newOrganizationGroup(rt))
	return cmd
}
