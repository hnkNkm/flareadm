// Package ssl implements `flareadm ssl ...`: zone SSL/TLS settings,
// Universal SSL and certificate packs.
package ssl

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
)

// New builds the ssl command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssl",
		Short: "Zone SSL/TLS administration",
	}
	cmd.AddCommand(newSettingGroup(rt))
	cmd.AddCommand(newUniversalGroup(rt))
	cmd.AddCommand(newCertificatePackGroup(rt))
	return cmd
}
