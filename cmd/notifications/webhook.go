package notifications

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func webhookRow(w cloudflare.AlertingWebhook) []string {
	return []string{w.ID, w.Name, w.URL, dateOnly(w.LastSuccess), dateOnly(w.LastFailure)}
}

func webhookHeaders() []string {
	return []string{"ID", "NAME", "URL", "LAST SUCCESS", "LAST FAILURE"}
}

type webhookFlagValues struct {
	rt       *app.Runtime
	Name     string
	URL      string
	Secret   string
	Settings string
}

func addWebhookFlags(rt *app.Runtime, cmd *cobra.Command, f *webhookFlagValues) {
	f.rt = rt
	cmd.Flags().StringVar(&f.Name, "name", "", "destination name (required on create)")
	cmd.Flags().StringVar(&f.URL, "url", "", "webhook URL (required on create); it may embed a token, so it is treated as a credential")
	cmd.Flags().StringVar(&f.Secret, "secret", "", "signing secret as @file only")
	cmd.Flags().StringVar(&f.Settings, "settings", "", "additional destination fields as a JSON object, inline or @file")
}

func (f *webhookFlagValues) overrides(cmd *cobra.Command) (map[string]any, error) {
	body := map[string]any{}
	changed := func(name string) bool { return cmd.Flags().Changed(name) }
	if changed("name") {
		body["name"] = f.Name
	}
	if changed("url") {
		if f.URL == "" {
			return nil, errors.Usage("--url must not be empty")
		}
		f.rt.ProtectSecret(f.URL)
		cmdutil.ProtectURLCredentials(f.rt, f.URL)
		body["url"] = f.URL
	}
	if changed("secret") {
		secret, err := cmdutil.FileOnly("secret", f.Secret)
		if err != nil {
			return nil, err
		}
		f.rt.ProtectSecret(secret)
		body["secret"] = secret
	}
	if changed("settings") {
		extra, err := cmdutil.ParseSecretCarryingSettings(f.rt, "settings", f.Settings)
		if err != nil {
			return nil, err
		}
		for k, v := range extra {
			body[k] = v
		}
	}
	return body, nil
}

func newWebhookGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "webhook",
		Short: "Webhook destinations",
		Long:  "Webhook notification destinations (/accounts/{account_id}/alerting/v3/destinations/webhooks).\n\nThe URL often embeds a token and --secret is a signing secret: both are\nregistered as protected secrets and never appear in diagnostics, error text or\n--dry-run previews (explicit reads still show the URL the API returns).",
	}
	cmd.AddCommand(newWebhookList(rt))
	cmd.AddCommand(newWebhookGet(rt))
	cmd.AddCommand(newWebhookCreate(rt))
	cmd.AddCommand(newWebhookUpdate(rt))
	cmd.AddCommand(newWebhookDelete(rt))
	return cmd
}

func newWebhookList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List webhook destinations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListAlertingWebhooks(cmd.Context(), ref.ID, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, webhookHeaders(), webhookRow)
		},
	}
}

func newWebhookGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get WEBHOOK_ID",
		Short: "Show one webhook destination",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetAlertingWebhook(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, webhookHeaders(), webhookRow)
		},
	}
}

func newWebhookCreate(rt *app.Runtime) *cobra.Command {
	var f webhookFlagValues
	cmd := &cobra.Command{
		Use:   "create --name NAME --url URL",
		Short: "Create a webhook destination",
		Long: "Create a webhook destination.\n\n" +
			"Example:\n" +
			"  flareadm notifications webhook create --name slack --url https://hooks.example.com/...\n\n" +
			"Previews never show the URL: it can embed a token.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.Name == "" {
				return errors.Usage("--name is required")
			}
			if !cmd.Flags().Changed("url") {
				return errors.Usage("--url is required")
			}
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would create webhook destination "+f.Name+" (url hidden)")
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateAlertingWebhook(cmd.Context(), ref.ID, body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, webhookHeaders(), webhookRow)
		},
	}
	addWebhookFlags(rt, cmd, &f)
	return cmd
}

func newWebhookUpdate(rt *app.Runtime) *cobra.Command {
	var f webhookFlagValues
	cmd := &cobra.Command{
		Use:   "update WEBHOOK_ID",
		Short: "Update a webhook destination",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if len(body) == 0 {
				return errors.Usage("nothing to update; pass at least one of --name, --url, --secret, --settings")
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would update webhook destination "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateAlertingWebhook(cmd.Context(), ref.ID, args[0], body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, webhookHeaders(), webhookRow)
		},
	}
	addWebhookFlags(rt, cmd, &f)
	return cmd
}

func newWebhookDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete WEBHOOK_ID",
		Short: "Delete a webhook destination",
		Long: "Delete a destination. Destructive: prompts for confirmation unless --yes is\n" +
			"given; --dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetAlertingWebhook(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would delete webhook destination "+existing.Item.Name)
			}
			if err := rt.Confirm("Delete webhook destination " + existing.Item.Name + "?"); err != nil {
				return err
			}
			if err := client.DeleteAlertingWebhook(cmd.Context(), ref.ID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted webhook destination %s", args[0])
			return nil
		},
	}
	return cmd
}
