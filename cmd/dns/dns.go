// Package dns implements `flareadm dns record ...` and
// `flareadm dns dnssec ...`.
package dns

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
)

// New builds the dns command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dns",
		Short: "DNS administration",
	}
	cmd.AddCommand(newRecordGroup(rt))
	cmd.AddCommand(newDNSSECGroup(rt))
	return cmd
}
