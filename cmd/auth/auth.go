// Package auth implements `flareadm auth verify|login|logout|status`.
package auth

import (
	"context"
	stderrors "errors"
	"net/http"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/resolver"
)

// New builds the auth command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Authentication helpers",
	}
	cmd.AddCommand(newVerify(rt))
	cmd.AddCommand(newScopes(rt))
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
			"token object's status. Account-owned API tokens cannot be verified there\n" +
			"(that endpoint answers HTTP 401 for them), so a rejected user-scoped check\n" +
			"falls back to GET /accounts/{account_id}/tokens/verify; the output then\n" +
			"names the check that produced the result, so a 401 can never read as an\n" +
			"expired credential. An OAuth credential is checked with GET /user, because\n" +
			"an OAuth access token has no token object to verify (docs/oauth.md §5 Q4).\n" +
			"The credential itself is never printed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := rt.CloudClient()
			if err != nil {
				return err
			}
			if rt.IsOAuthCredential() {
				// Identity is authorized by the `user-details.read` API permission
				// the client is registered with, not by an OIDC `openid` scope:
				// Cloudflare rejects `openid`/`offline` in an authorize request for
				// this client type (see oauth.RequiredScopes), and the CLI does not
				// request them.
				res, err := client.UserDetails(cmd.Context())
				if err != nil {
					if forbiddenByScope(err) {
						return errors.New(errors.CodePermission,
							"the OAuth client is not allowed to read the user identity: GET /user needs the "+
								"user-details.read permission on the client (%s). Add user-details.read to the "+
								"client's registered scopes and run 'flareadm auth login' again. "+
								"`flareadm auth scopes` lists the ids this CLI requests",
							err.Error())
					}
					return err
				}
				row := func(u cloudflare.UserDetails) []string {
					return []string{u.ID, u.Email, identityName(u)}
				}
				return app.RenderGet(rt, res, []string{"USER ID", "EMAIL", "NAME"}, row)
			}
			res, err := client.VerifyToken(cmd.Context())
			if err == nil {
				row := func(v cloudflare.Verification) []string {
					return []string{v.ID, v.Status}
				}
				return app.RenderGet(rt, res, []string{"ID", "STATUS"}, row)
			}
			if !userVerifyRejected(err) {
				return err
			}
			// An account-owned token is rejected by the user-scoped endpoint. Try
			// the account-scoped check when an account can be resolved; when it
			// cannot, report the original failure rather than guessing.
			ref, resolveErr := resolveVerifyAccount(cmd.Context(), rt)
			if resolveErr != nil {
				return err
			}
			acctRes, acctErr := client.VerifyAccountToken(cmd.Context(), ref.ID)
			if acctErr != nil {
				return errors.New(errors.CodeAuth,
					"the credential could not be verified. GET /user/tokens/verify: %s. GET /accounts/%s/tokens/verify: %s. "+
						"It may be an account-owned token for a different account; select one with --account-id or a profile account_id",
					err.Error(), ref.ID, acctErr.Error())
			}
			accountRow := func(v accountVerification) []string {
				return []string{v.ID, v.Status, v.ExpiresOn, v.Scope}
			}
			item := accountVerification{
				ID:        acctRes.Item.ID,
				Status:    acctRes.Item.Status,
				ExpiresOn: acctRes.Item.ExpiresOn,
				Scope:     "account-owned token",
			}
			wrapped := &cloudflare.GetResult[accountVerification]{Item: item, RawBody: acctRes.RawBody}
			return app.RenderGet(rt, wrapped, []string{"ID", "STATUS", "EXPIRES", "SCOPE"}, accountRow)
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

// forbiddenByScope reports whether err is an HTTP 403: for the OAuth identity
// call that means the client is missing the user-details.read permission, which
// is actionable, unlike a plain permission failure from another endpoint.
func forbiddenByScope(err error) bool {
	var exit *errors.ExitError
	if !stderrors.As(err, &exit) {
		return false
	}
	return exit.StatusCode == http.StatusForbidden
}

// accountVerification is the account-scoped verification result plus the marker
// that names which check produced it. The marker exists so a 401 from the
// user-scoped endpoint can never be mistaken for an expired credential.
//
// The fields are spelled out instead of embedding cloudflare.Verification: the
// YAML encoder nests embedded structs under the type name, which would make the
// yaml output disagree with the json one.
type accountVerification struct {
	ID        string `json:"id" yaml:"id"`
	Status    string `json:"status" yaml:"status"`
	ExpiresOn string `json:"expires_on,omitempty" yaml:"expires_on,omitempty"`
	Scope     string `json:"scope" yaml:"scope"`
}

// userVerifyRejected reports whether the user-scoped verification failed in the
// way that means "this endpoint does not know the credential": HTTP 401 or 403.
// Every other failure (transport error, 5xx, malformed body) is returned to the
// caller unchanged, because it carries no information about the token's owner.
func userVerifyRejected(err error) bool {
	var exit *errors.ExitError
	if !stderrors.As(err, &exit) {
		return false
	}
	return exit.StatusCode == http.StatusUnauthorized || exit.StatusCode == http.StatusForbidden
}

// resolveVerifyAccount resolves the account for the fallback check. It reports an
// error when no account can be resolved (no accounts, several accounts, or a
// failed lookup), in which case the caller keeps the original user-scoped error.
func resolveVerifyAccount(ctx context.Context, rt *app.Runtime) (resolver.AccountRef, error) {
	client, err := rt.CloudClient()
	if err != nil {
		return resolver.AccountRef{}, err
	}
	prof, err := rt.ActiveProfilePtr()
	if err != nil {
		return resolver.AccountRef{}, err
	}
	ref, err := resolver.Account(ctx, client, rt.AccountIDFlag, prof, rt.Getenv)
	if err != nil {
		return resolver.AccountRef{}, err
	}
	if logger := rt.Logger(); logger != nil {
		logger.Debugf("verifying account-owned token against GET /accounts/%s/tokens/verify (%s)", ref.ID, ref.Source)
	}
	return ref, nil
}
