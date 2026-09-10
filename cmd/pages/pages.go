// Package pages implements `flareadm pages ...`: remote administration of
// Cloudflare Pages projects, their deployments and custom domains.
package pages

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
)

// New builds the pages command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pages",
		Short: "Cloudflare Pages administration",
		Long:  "Cloudflare Pages administration (projects, deployments and project domains). Account scope is resolved through the standard account resolution.",
	}
	cmd.AddCommand(newProjectGroup(rt))
	return cmd
}

func dateOnly(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}
