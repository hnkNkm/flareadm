package zerotrust

import (
	"strconv"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func identityProviderRow(p cloudflare.IdentityProvider) []string {
	return []string{p.ID, p.Name, p.Type, strconv.FormatBool(p.ReadOnly)}
}

func identityProviderHeaders() []string {
	return []string{"ID", "NAME", "TYPE", "READ ONLY"}
}

type idpFlagValues struct {
	rt                 *app.Runtime
	Name               string
	Type               string
	Config             string
	SCIMConfig         string
	SAMLCertificateSet string
	Settings           string
}

func addIDPFlags(rt *app.Runtime, cmd *cobra.Command, f *idpFlagValues) {
	f.rt = rt
	cmd.Flags().StringVar(&f.Name, "name", "", "identity provider name (required on create)")
	cmd.Flags().StringVar(&f.Type, "type", "", "identity provider type (for example onetimepin, okta, saml, google)")
	cmd.Flags().StringVar(&f.Config, "config", "", "provider configuration object (required on create); @file-only because it carries provider credentials")
	cmd.Flags().StringVar(&f.SCIMConfig, "scim-config", "", "SCIM configuration object, inline or @file")
	cmd.Flags().StringVar(&f.SAMLCertificateSet, "saml-certificate-set-id", "", "SAML certificate set id")
	cmd.Flags().StringVar(&f.Settings, "settings", "", "additional identity provider fields as a JSON object, inline or @file")
}

func (f *idpFlagValues) overrides(cmd *cobra.Command) (map[string]any, error) {
	body := map[string]any{}
	changed := func(name string) bool { return cmd.Flags().Changed(name) }
	if changed("name") {
		body["name"] = f.Name
	}
	if changed("type") {
		body["type"] = f.Type
	}
	if changed("config") {
		text, err := fileOnly("config", f.Config)
		if err != nil {
			return nil, err
		}
		cfg, err := parseSecretCarryingObject(f.rt, "config", text)
		if err != nil {
			return nil, err
		}
		body["config"] = cfg
	}
	if changed("scim-config") {
		scim, err := parseSecretCarryingObject(f.rt, "scim-config", f.SCIMConfig)
		if err != nil {
			return nil, err
		}
		body["scim_config"] = scim
	}
	if changed("saml-certificate-set-id") {
		body["saml_certificate_set_id"] = f.SAMLCertificateSet
	}
	if changed("settings") {
		extra, err := parseSecretCarryingSettings(f.rt, "settings", f.Settings)
		if err != nil {
			return nil, err
		}
		for k, v := range extra {
			body[k] = v
		}
	}
	return body, nil
}

func newAccessIDPGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "identity-provider",
		Short: "Access identity providers",
		Long:  "Access identity providers (/accounts/{account_id}/access/identity_providers).",
	}
	cmd.AddCommand(newAccessIDPList(rt))
	cmd.AddCommand(newAccessIDPGet(rt))
	cmd.AddCommand(newAccessIDPCreate(rt))
	cmd.AddCommand(newAccessIDPUpdate(rt))
	cmd.AddCommand(newAccessIDPDelete(rt))
	return cmd
}

func newAccessIDPList(rt *app.Runtime) *cobra.Command {
	var scimEnabled string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List identity providers",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListIdentityProviders(cmd.Context(), ref.ID, scimEnabled, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, identityProviderHeaders(), identityProviderRow)
		},
	}
	cmd.Flags().StringVar(&scimEnabled, "scim-enabled", "", "filter by SCIM state (true, false, default)")
	return cmd
}

func newAccessIDPGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get IDENTITY_PROVIDER_ID",
		Short: "Show one identity provider",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetIdentityProvider(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, identityProviderHeaders(), identityProviderRow)
		},
	}
}

func newAccessIDPCreate(rt *app.Runtime) *cobra.Command {
	var f idpFlagValues
	cmd := &cobra.Command{
		Use:   "create --name NAME --type TYPE --config @config.json",
		Short: "Create an identity provider",
		Long: "Create an identity provider.\n\n" +
			"Example:\n" +
			"  flareadm zero-trust access identity-provider create --name okta \\\n" +
			"    --type okta --config @okta.json\n\n" +
			"--config is @file-only because provider configurations carry credentials\n" +
			"(client secrets, signing keys); it is sent verbatim.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.Name == "" {
				return errors.Usage("--name is required")
			}
			if f.Type == "" {
				return errors.Usage("--type is required")
			}
			if !cmd.Flags().Changed("config") {
				return errors.Usage("--config is required (@file JSON object)")
			}
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would create identity provider "+f.Name)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateIdentityProvider(cmd.Context(), ref.ID, body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, identityProviderHeaders(), identityProviderRow)
		},
	}
	addIDPFlags(rt, cmd, &f)
	return cmd
}

func newAccessIDPUpdate(rt *app.Runtime) *cobra.Command {
	var f idpFlagValues
	cmd := &cobra.Command{
		Use:   "update IDENTITY_PROVIDER_ID",
		Short: "Update an identity provider",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if len(body) == 0 {
				return errors.Usage("nothing to update; pass at least one identity provider flag or --settings")
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would update identity provider "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateIdentityProvider(cmd.Context(), ref.ID, args[0], body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, identityProviderHeaders(), identityProviderRow)
		},
	}
	addIDPFlags(rt, cmd, &f)
	return cmd
}

func newAccessIDPDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete IDENTITY_PROVIDER_ID",
		Short: "Delete an identity provider",
		Long: "Delete an identity provider. Destructive: prompts for confirmation unless\n" +
			"--yes is given; --dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetIdentityProvider(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would delete identity provider "+existing.Item.Name)
			}
			if err := rt.Confirm("Delete identity provider " + existing.Item.Name + "?"); err != nil {
				return err
			}
			if err := client.DeleteIdentityProvider(cmd.Context(), ref.ID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted identity provider %s", args[0])
			return nil
		},
	}
	return cmd
}
