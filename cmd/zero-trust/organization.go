package zerotrust

import (
	"encoding/json"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func newOrganizationGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "organization",
		Short: "Zero Trust account organization",
		Long:  "Read and update the account-level Zero Trust organization (name, login domain, session and MFA policy fields).",
	}
	cmd.AddCommand(newOrganizationGet(rt))
	cmd.AddCommand(newOrganizationUpdate(rt))
	return cmd
}

func newOrganizationGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Show the Zero Trust organization",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetZeroTrustOrganization(cmd.Context(), ref.ID)
			if err != nil {
				return err
			}
			row := func(o cloudflare.ZeroTrustOrganization) []string {
				return []string{o.Name, o.AuthDomain, o.SessionDuration, strconv.FormatBool(o.IsUIReadOnly), strconv.FormatBool(o.MFARequiredForAllApps)}
			}
			return app.RenderGet(rt, res, []string{"NAME", "AUTH DOMAIN", "SESSION DURATION", "UI READ ONLY", "MFA REQUIRED"}, row)
		},
	}
}

func newOrganizationUpdate(rt *app.Runtime) *cobra.Command {
	var nameFlag, authDomainFlag, sessionFlag, toggleReasonFlag string
	var uiReadOnlyFlag, allowWARPFlag, autoRedirectFlag, denyUnmatchedFlag, mfaFlag bool
	var settingsFlag string
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update the Zero Trust organization",
		Long: "Update account-level Zero Trust organization settings. Provided fields are\n" +
			"merged into the current organization and the result is PUT, so fields this\n" +
			"CLI does not model are preserved.\n\n" +
			"--settings accepts a JSON object (inline or @file) for fields without a\n" +
			"dedicated flag; it wins over flags for the same key.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			overrides := map[string]any{}
			if cmd.Flags().Changed("name") {
				overrides["name"] = nameFlag
			}
			if cmd.Flags().Changed("auth-domain") {
				overrides["auth_domain"] = authDomainFlag
			}
			if cmd.Flags().Changed("session-duration") {
				overrides["session_duration"] = sessionFlag
			}
			if cmd.Flags().Changed("is-ui-read-only") {
				overrides["is_ui_read_only"] = uiReadOnlyFlag
			}
			if cmd.Flags().Changed("ui-read-only-toggle-reason") {
				overrides["ui_read_only_toggle_reason"] = toggleReasonFlag
			}
			if cmd.Flags().Changed("allow-authenticate-via-warp") {
				overrides["allow_authenticate_via_warp"] = allowWARPFlag
			}
			if cmd.Flags().Changed("auto-redirect-to-identity") {
				overrides["auto_redirect_to_identity"] = autoRedirectFlag
			}
			if cmd.Flags().Changed("deny-unmatched-requests") {
				overrides["deny_unmatched_requests"] = denyUnmatchedFlag
			}
			if cmd.Flags().Changed("mfa-required-for-all-apps") {
				overrides["mfa_required_for_all_apps"] = mfaFlag
			}
			if cmd.Flags().Changed("settings") {
				parsed, err := cmdutil.ParseJSONObject("settings", settingsFlag)
				if err != nil {
					return err
				}
				var extra map[string]any
				if err := json.Unmarshal(parsed, &extra); err != nil {
					return errors.Usage("--settings must be a JSON object")
				}
				for k, v := range extra {
					overrides[k] = v
				}
			}
			if len(overrides) == 0 {
				return errors.Usage("nothing to update; pass at least one organization flag or --settings")
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would update the Zero Trust organization")
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateZeroTrustOrganization(cmd.Context(), ref.ID, overrides)
			if err != nil {
				return err
			}
			row := func(o cloudflare.ZeroTrustOrganization) []string {
				return []string{o.Name, o.AuthDomain, o.SessionDuration, strconv.FormatBool(o.IsUIReadOnly), strconv.FormatBool(o.MFARequiredForAllApps)}
			}
			return app.RenderGet(rt, res, []string{"NAME", "AUTH DOMAIN", "SESSION DURATION", "UI READ ONLY", "MFA REQUIRED"}, row)
		},
	}
	cmd.Flags().StringVar(&nameFlag, "name", "", "organization name")
	cmd.Flags().StringVar(&authDomainFlag, "auth-domain", "", "login auth domain")
	cmd.Flags().StringVar(&sessionFlag, "session-duration", "", "session duration (for example 24h)")
	cmd.Flags().BoolVar(&uiReadOnlyFlag, "is-ui-read-only", false, "lock the Zero Trust dashboard (use --is-ui-read-only=false to unlock)")
	cmd.Flags().StringVar(&toggleReasonFlag, "ui-read-only-toggle-reason", "", "reason recorded when toggling UI read-only")
	cmd.Flags().BoolVar(&allowWARPFlag, "allow-authenticate-via-warp", false, "allow authentication via WARP")
	cmd.Flags().BoolVar(&autoRedirectFlag, "auto-redirect-to-identity", false, "auto-redirect to the identity provider")
	cmd.Flags().BoolVar(&denyUnmatchedFlag, "deny-unmatched-requests", false, "deny requests that match no Access policy")
	cmd.Flags().BoolVar(&mfaFlag, "mfa-required-for-all-apps", false, "require MFA for all Access applications")
	cmd.Flags().StringVar(&settingsFlag, "settings", "", "additional organization fields as a JSON object, inline or @file")
	return cmd
}
