package zerotrust

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func serviceTokenRow(t cloudflare.AccessServiceToken) []string {
	return []string{t.ID, t.Name, t.ClientID, t.Duration, dateOnly(t.ExpiresAt)}
}

func serviceTokenHeaders() []string {
	return []string{"ID", "NAME", "CLIENT ID", "DURATION", "EXPIRES"}
}

// serviceTokenSecretRow includes the client secret: it is used only by the
// commands whose explicit purpose is to reveal it (create, rotate).
func serviceTokenSecretRow(t cloudflare.AccessServiceToken) []string {
	return append(serviceTokenRow(t), t.ClientSecret)
}

func serviceTokenSecretHeaders() []string {
	return append(serviceTokenHeaders(), "CLIENT SECRET")
}

type tokenFlagValues struct {
	Name                string
	Duration            string
	ClientSecretVersion int64
	PrevSecretExpiresAt string
	Enabled             bool
	Settings            string
}

func newAccessServiceTokenGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service-token",
		Short: "Access service tokens",
		Long:  "Access service tokens (/accounts/{account_id}/access/service_tokens).\n\nThe client secret is a credential: it is returned only by create and rotate\n(and only there is it printed), is registered as a protected secret, and never\nappears in diagnostics, error text or --dry-run previews.",
	}
	cmd.AddCommand(newAccessServiceTokenList(rt))
	cmd.AddCommand(newAccessServiceTokenGet(rt))
	cmd.AddCommand(newAccessServiceTokenCreate(rt))
	cmd.AddCommand(newAccessServiceTokenUpdate(rt))
	cmd.AddCommand(newAccessServiceTokenDelete(rt))
	cmd.AddCommand(newAccessServiceTokenRotate(rt))
	return cmd
}

func newAccessServiceTokenList(rt *app.Runtime) *cobra.Command {
	var f cloudflare.AccessServiceTokenQuery
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List service tokens",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListAccessServiceTokens(cmd.Context(), ref.ID, f, rt.Policy())
			if err != nil {
				return err
			}
			for i := range res.Items {
				res.Items[i].ClientSecret = ""
			}
			return app.RenderList(rt, res, serviceTokenHeaders(), serviceTokenRow)
		},
	}
	cmd.Flags().StringVar(&f.Name, "name", "", "only tokens with this exact name")
	cmd.Flags().StringVar(&f.Search, "search", "", "search tokens by name")
	return cmd
}

func newAccessServiceTokenGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get TOKEN_ID",
		Short: "Show one service token",
		Long:  "Show service token metadata. The client secret is not returned by the API here; use rotate to issue a new one.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetAccessServiceToken(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			res.Item.ClientSecret = ""
			return app.RenderGet(rt, res, serviceTokenHeaders(), serviceTokenRow)
		},
	}
}

func newAccessServiceTokenCreate(rt *app.Runtime) *cobra.Command {
	var f tokenFlagValues
	cmd := &cobra.Command{
		Use:   "create --name NAME",
		Short: "Create a service token",
		Long: "Create a service token. The response carries the client secret; it is\n" +
			"printed once here (stdout only), registered as a protected secret and is not\n" +
			"retrievable afterwards.\n\n" +
			"Example:\n" +
			"  flareadm zero-trust access service-token create --name ci --duration 8760h",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.Name == "" {
				return errors.Usage("--name is required")
			}
			body := map[string]any{"name": f.Name}
			addTokenOverrides(cmd, &f, body)
			if rt.DryRunFlag {
				return previewLine(rt, "Would create service token "+f.Name)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateAccessServiceToken(cmd.Context(), ref.ID, body)
			if err != nil {
				return err
			}
			rt.ProtectSecret(res.Item.ClientSecret)
			return app.RenderGet(rt, res, serviceTokenSecretHeaders(), serviceTokenSecretRow)
		},
	}
	addTokenFlagSet(cmd, &f)
	return cmd
}

func newAccessServiceTokenUpdate(rt *app.Runtime) *cobra.Command {
	var f tokenFlagValues
	cmd := &cobra.Command{
		Use:   "update TOKEN_ID",
		Short: "Update a service token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]any{}
			addTokenOverrides(cmd, &f, body)
			if len(body) == 0 {
				return errors.Usage("nothing to update; pass at least one of --name, --duration, --enabled, --client-secret-version, --previous-client-secret-expires-at")
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would update service token "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateAccessServiceToken(cmd.Context(), ref.ID, args[0], body)
			if err != nil {
				return err
			}
			res.Item.ClientSecret = ""
			return app.RenderGet(rt, res, serviceTokenHeaders(), serviceTokenRow)
		},
	}
	addTokenFlagSet(cmd, &f)
	return cmd
}

func newAccessServiceTokenDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete TOKEN_ID",
		Short: "Delete a service token",
		Long: "Delete a service token. Destructive and irreversible: existing clients lose\n" +
			"access. Prompts for confirmation unless --yes is given; --dry-run previews\n" +
			"the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetAccessServiceToken(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would delete service token "+existing.Item.Name)
			}
			if err := rt.Confirm("Delete service token " + existing.Item.Name + "?"); err != nil {
				return err
			}
			if err := client.DeleteAccessServiceToken(cmd.Context(), ref.ID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted service token %s", args[0])
			return nil
		},
	}
	return cmd
}

func newAccessServiceTokenRotate(rt *app.Runtime) *cobra.Command {
	var prevExpires string
	cmd := &cobra.Command{
		Use:   "rotate TOKEN_ID",
		Short: "Rotate a service token client secret",
		Long: "Rotate the client secret. The new secret is printed once here (stdout only),\n" +
			"registered as a protected secret and is not retrievable afterwards. The old\n" +
			"secret keeps working until --previous-secret-expires-at unless the API default\n" +
			"applies.\n\n" +
			"Rotating is not destructive but it is a credential change: it is never\n" +
			"previewed with the new value, and --dry-run only reports the intent.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]any{}
			if cmd.Flags().Changed("previous-secret-expires-at") {
				body["previous_client_secret_expires_at"] = prevExpires
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would rotate service token "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.RotateAccessServiceToken(cmd.Context(), ref.ID, args[0], body)
			if err != nil {
				return err
			}
			rt.ProtectSecret(res.Item.ClientSecret)
			return app.RenderGet(rt, res, serviceTokenSecretHeaders(), serviceTokenSecretRow)
		},
	}
	cmd.Flags().StringVar(&prevExpires, "previous-secret-expires-at", "", "RFC3339 time until which the previous client secret keeps working")
	return cmd
}

func addTokenFlagSet(cmd *cobra.Command, f *tokenFlagValues) {
	cmd.Flags().StringVar(&f.Name, "name", "", "service token name")
	cmd.Flags().StringVar(&f.Duration, "duration", "", "token lifetime (for example 8760h)")
	cmd.Flags().BoolVar(&f.Enabled, "enabled", false, "enable or disable the token (use --enabled=false to disable)")
	cmd.Flags().Int64Var(&f.ClientSecretVersion, "client-secret-version", 0, "client secret version")
	cmd.Flags().StringVar(&f.PrevSecretExpiresAt, "previous-client-secret-expires-at", "", "RFC3339 time until which the previous client secret keeps working")
}

func addTokenOverrides(cmd *cobra.Command, f *tokenFlagValues, body map[string]any) {
	changed := func(name string) bool { return cmd.Flags().Changed(name) }
	if changed("name") {
		body["name"] = f.Name
	}
	if changed("duration") {
		body["duration"] = f.Duration
	}
	if changed("enabled") {
		body["enabled"] = f.Enabled
	}
	if changed("client-secret-version") {
		body["client_secret_version"] = f.ClientSecretVersion
	}
	if changed("previous-client-secret-expires-at") {
		body["previous_client_secret_expires_at"] = f.PrevSecretExpiresAt
	}
}
