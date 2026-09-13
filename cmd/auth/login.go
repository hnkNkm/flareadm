package auth

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/auth"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/oauth"
)

func newLogin(rt *app.Runtime) *cobra.Command {
	var clientIDFlag, scopesFlag, callbackHost string
	var allScopes, readOnly, noBrowser bool
	var callbackPort int
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in with OAuth (Authorization Code + PKCE)",
		Long: "Log in with OAuth so no API token has to be pasted into the environment.\n\n" +
			"The flow is Authorization Code with PKCE (S256) and a loopback callback. The\n" +
			"redirect URI it uses must be registered on your OAuth client:\n\n" +
			"  " + oauth.RedirectURI(oauth.DefaultCallbackHost, oauth.DefaultCallbackPort) + "\n\n" +
			"Provide the client id with --client-id or the profile key oauth_client_id.\n" +
			"Scopes default to the read-only set; --scopes picks an explicit set and\n" +
			"--all-scopes requests the full catalog. List the scope ids with\n" +
			"`flareadm auth scopes` - they are the values to register in the `scopes`\n" +
			"array of the OAuth client.\n\n" +
			"In CI use an API token instead (FLAREADM_API_TOKEN): login requires a\n" +
			"terminal, and with --no-browser it prints the authorize URL once and waits\n" +
			"for the callback until --timeout expires.\n\n" +
			"Tokens are stored owner-only under the OAuth credential directory and are\n" +
			"never printed, logged or included in error text.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			profileName := rt.ActiveProfileName()
			prof, err := rt.ActiveProfilePtr()
			if err != nil {
				return err
			}

			// Environment credentials keep absolute precedence (docs/oauth.md §6.1, §8).
			if cred, ok := auth.Resolve(prof); ok {
				return errors.Usage(
					"already authenticated with an API token from %s; unset it to log in via OAuth, or keep using it",
					cred.Source)
			}

			clientID := clientIDFlag
			if clientID == "" && prof != nil {
				clientID = prof.OAuthClientID
			}
			if clientID == "" {
				return errors.Usage("--client-id is required (or set oauth_client_id in profile %q)", profileName)
			}

			scopes, err := selectScopes(scopesFlag, allScopes, readOnly)
			if err != nil {
				return err
			}
			if callbackPort < 0 || callbackPort > 65535 {
				return errors.Usage("--callback-port must be between 0 and 65535 (got %d)", callbackPort)
			}
			redirectURI := oauth.RedirectURI(callbackHost, callbackPort)
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would start an OAuth login for profile "+profileName+
					" with "+describeScopes(scopes)+" (redirect "+redirectURI+")")
			}
			if !noBrowser && !rt.StdinTTY() {
				return errors.Usage(
					"login requires an interactive terminal; use --no-browser to print the URL and complete the login elsewhere, or set FLAREADM_API_TOKEN for CI")
			}

			cred, err := oauth.Login(cmd.Context(), oauth.LoginOptions{
				ClientID:     clientID,
				Scopes:       scopes,
				CallbackHost: callbackHost,
				CallbackPort: callbackPort,
				OpenBrowser:  !noBrowser,
				Timeout:      timeout,
				Endpoints:    oauth.EndpointsFromEnv(rt.Getenv),
				Out:          rt.Out,
				ErrOut:       rt.Err,
				Protect:      rt.ProtectSecret,
			})
			if err != nil {
				return err
			}
			store := rt.OAuthStore()
			if err := store.Save(profileName, cred); err != nil {
				return err
			}
			rt.ProtectSecret(cred.AccessToken)
			rt.ProtectSecret(cred.RefreshToken)
			rt.Logger().Infof("stored OAuth credential at %s", store.Path(profileName))
			_, _ = fmt.Fprintf(rt.Out, "Logged in with OAuth for profile %q (%s); credential stored at %s\n",
				profileName, cred.Describe(), store.Path(profileName))
			return nil
		},
	}
	cmd.Flags().StringVar(&clientIDFlag, "client-id", "", "OAuth client id (falls back to the profile oauth_client_id)")
	cmd.Flags().StringVar(&scopesFlag, "scopes", "",
		"comma-separated OAuth scope ids to request (list them with `flareadm auth scopes`)")
	cmd.Flags().BoolVar(&allScopes, "all-scopes", false, "request every scope in the catalog")
	cmd.Flags().BoolVar(&readOnly, "read-only", false, "request only read scopes (the default)")
	cmd.Flags().StringVar(&callbackHost, "callback-host", oauth.DefaultCallbackHost, "host the loopback callback listens on")
	cmd.Flags().IntVar(&callbackPort, "callback-port", oauth.DefaultCallbackPort, "port the loopback callback listens on")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "print the authorize URL instead of opening a browser")
	cmd.Flags().DurationVar(&timeout, "timeout", oauth.DefaultLoginTimeout, "how long to wait for the OAuth callback")
	return cmd
}
