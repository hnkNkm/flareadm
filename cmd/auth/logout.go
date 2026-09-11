package auth

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/oauth"
)

func newLogout(rt *app.Runtime) *cobra.Command {
	var localOnly bool
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Revoke the stored OAuth credential and delete it",
		Long: "Log out: revoke the stored refresh token at the Cloudflare revocation\n" +
			"endpoint, then delete the local credential.\n\n" +
			"If revocation fails with a network error the credential is kept so the\n" +
			"logout can be retried (exit 8). If the endpoint rejects the token the\n" +
			"credential is deleted anyway and the rejection is reported on stderr\n" +
			"(exit 3). --local skips the network call entirely.\n\n" +
			"API tokens are not affected: they are managed by the caller's environment,\n" +
			"not by FlareADM.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			profileName := rt.ActiveProfileName()
			store := rt.OAuthStore()
			cred, ok, err := store.Load(profileName)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New(errors.CodeAuth,
					"no OAuth credential is stored for profile %q; nothing to log out", profileName)
			}
			rt.ProtectSecret(cred.AccessToken)
			rt.ProtectSecret(cred.RefreshToken)

			if rt.DryRunFlag {
				if localOnly || cred.RefreshToken == "" {
					return cmdutil.PreviewLine(rt, "Would delete the OAuth credential for profile "+profileName)
				}
				return cmdutil.PreviewLine(rt, "Would revoke the OAuth credential for profile "+profileName+" and delete it")
			}
			if err := rt.Confirm(fmt.Sprintf("Log out profile %q and delete %s?", profileName, store.Path(profileName))); err != nil {
				return err
			}

			var revokeErr error
			if !localOnly && cred.RefreshToken != "" {
				clientID := cred.ClientID
				if clientID == "" {
					if prof, err := rt.ActiveProfilePtr(); err == nil && prof != nil {
						clientID = prof.OAuthClientID
					}
				}
				revokeErr = oauth.Revoke(cmd.Context(), oauth.RevokeOptions{
					Credential: cred,
					ClientID:   clientID,
					Endpoints:  oauth.EndpointsFromEnv(rt.Getenv),
					Protect:    rt.ProtectSecret,
				})
				// A network failure leaves the credential in place so the user can
				// retry; deleting locally would strand a live token on the server
				// (docs/oauth.md §9).
				if revokeErr != nil && errors.CodeOf(revokeErr) == errors.CodeNetwork {
					return revokeErr
				}
			}
			if err := store.Delete(profileName); err != nil {
				return err
			}
			if revokeErr != nil {
				return errors.New(errors.CodeAuth,
					"%s; the local credential for profile %q was deleted anyway", revokeErr, profileName)
			}
			if localOnly || cred.RefreshToken == "" {
				_, _ = fmt.Fprintf(rt.Out, "Deleted the OAuth credential for profile %q (the refresh token was not revoked)\n", profileName)
				return nil
			}
			_, _ = fmt.Fprintf(rt.Out, "Logged out profile %q and deleted its OAuth credential\n", profileName)
			return nil
		},
	}
	cmd.Flags().BoolVar(&localOnly, "local", false, "delete the local credential without revoking the refresh token")
	return cmd
}
