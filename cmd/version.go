package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/version"
)

// versionCmd prints the FlareADM version. Local-only: no configuration file
// and no network access.
func versionCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the FlareADM version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, _ = fmt.Fprintln(rt.Out, version.String())
			return nil
		},
	}
}
