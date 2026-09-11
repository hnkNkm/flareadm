// Package auth implements `flareadm auth verify|login|logout|status`.
package auth

import (
	"strings"

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
	cmd.AddCommand(newLogin(rt))
	cmd.AddCommand(newLogout(rt))
	cmd.AddCommand(newStatus(rt))
	return cmd
}

func newVerify(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Verify the resolved credential",
		Long: "Verify the credential resolved for the active profile.\n\n" +
			"An API token is checked with GET /user/tokens/verify, which reports the\n" +
			"token object's status. An OAuth credential is checked with GET /user,\n" +
			"because an OAuth access token has no token object to verify\n" +
			"(docs/oauth.md §5 Q4). The credential itself is never printed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := rt.CloudClient()
			if err != nil {
				return err
			}
			if rt.IsOAuthCredential() {
				res, err := client.UserDetails(cmd.Context())
				if err != nil {
					return err
				}
				row := func(u cloudflare.UserDetails) []string {
					return []string{u.ID, u.Email, identityName(u)}
				}
				return app.RenderGet(rt, res, []string{"USER ID", "EMAIL", "NAME"}, row)
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

// identityName renders a display name, falling back to the username.
func identityName(u cloudflare.UserDetails) string {
	name := strings.TrimSpace(u.FirstName + " " + u.LastName)
	if name != "" {
		return name
	}
	return u.Username
}
