// Package d1 implements `flareadm d1 ...`: D1 database administration.
package d1

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
)

// New builds the d1 command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "d1",
		Short: "D1 database administration",
		Long:  "D1 database administration. Account scope is resolved through the standard account resolution (--account-id, profile account_id, FLAREADM_ACCOUNT_ID or the single accessible account).",
	}
	cmd.AddCommand(newDatabaseGroup(rt))
	return cmd
}
