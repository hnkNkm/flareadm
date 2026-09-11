package auth

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/auth"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
)

func newStatus(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show which credential wins for the active profile",
		Long: "Show the credential source that commands will use, without calling the API\n" +
			"and without ever printing token material.\n\n" +
			"Environment credentials win over stored OAuth credentials, so a profile with\n" +
			"both reports the environment variable (docs/oauth.md §8).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			profileName := rt.ActiveProfileName()
			prof, err := rt.ActiveProfilePtr()
			if err != nil {
				return err
			}
			store := rt.OAuthStore()

			fields := []struct{ name, value string }{
				{"PROFILE", profileName},
			}
			switch cred, ok := auth.Resolve(prof); {
			case ok:
				fields = append(fields,
					struct{ name, value string }{"SOURCE", cred.Source},
					struct{ name, value string }{"KIND", "api token (environment)"},
					struct{ name, value string }{"STORE", "(not used)"},
				)
			default:
				stored, ok, err := store.Load(profileName)
				if err != nil {
					return err
				}
				if !ok {
					return errors.New(errors.CodeAuth,
						"no credential found for profile %q; run 'flareadm auth login' or set FLAREADM_API_TOKEN", profileName)
				}
				rt.ProtectSecret(stored.AccessToken)
				rt.ProtectSecret(stored.RefreshToken)
				expiry := "(unknown)"
				if !stored.ExpiresAt.IsZero() {
					expiry = stored.ExpiresAt.UTC().Format(time.RFC3339)
					if stored.Expired(time.Now()) {
						expiry += " (expired; will refresh on next use)"
					}
				}
				refresh := "no"
				if stored.RefreshToken != "" {
					refresh = "yes"
				}
				identity := "(unavailable)"
				if client, err := rt.CloudClient(); err == nil {
					if res, err := client.UserDetails(cmd.Context()); err == nil && res != nil {
						identity = res.Item.Email
						if identity == "" {
							identity = res.Item.ID
						}
					}
				}
				fields = append(fields,
					struct{ name, value string }{"SOURCE", "oauth:" + profileName},
					struct{ name, value string }{"KIND", "oauth (stored, " + stored.TokenType + ")"},
					struct{ name, value string }{"CLIENT ID", stored.ClientID},
					struct{ name, value string }{"SCOPES", describeScopes(stored.Scopes)},
					struct{ name, value string }{"EXPIRES", expiry},
					struct{ name, value string }{"REFRESH TOKEN", refresh},
					struct{ name, value string }{"STORE", store.Path(profileName)},
					struct{ name, value string }{"USER", identity},
				)
			}

			if rt.Raw() {
				return nil
			}
			if rt.Format() != output.Table {
				payload := map[string]string{}
				for _, f := range fields {
					payload[f.name] = f.value
				}
				return rt.Printer().Emit(payload)
			}
			rows := make([][]string, 0, len(fields))
			for _, f := range fields {
				rows = append(rows, []string{f.name, f.value})
			}
			return rt.Printer().PrintTable([]string{"FIELD", "VALUE"}, rows)
		},
	}
}
