// Package auth implements `flareadm auth verify`.
package auth

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
)

// New builds the auth command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Authentication helpers",
	}
	cmd.AddCommand(newVerify(rt))
	return cmd
}

func newVerify(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Verify the resolved API token",
		Long: "Verify the API token resolved for the active profile by calling\n" +
			"GET /user/tokens/verify. The token itself is never printed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := rt.CloudClient()
			if err != nil {
				return err
			}
			res, err := client.VerifyToken(cmd.Context())
			if err != nil {
				return err
			}
			row := func(v cloudflare.Verification) []string {
				return []string{v.ID, v.Status}
			}
			return app.RenderGet(rt, res, []string{"ID", "STATUS"}, row)
		},
	}
}
