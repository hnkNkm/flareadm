package workers

import (
	"strconv"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func accountSettingsRow(s cloudflare.WorkerAccountSettings) []string {
	return []string{s.DefaultUsageModel, strconv.FormatBool(s.GreenCompute)}
}

func accountSettingsHeaders() []string {
	return []string{"DEFAULT USAGE MODEL", "GREEN COMPUTE"}
}

func newAccountSettingsGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "account-settings",
		Short: "Account-level Workers defaults",
		Long:  "Account-level Workers defaults (/accounts/{account_id}/workers/account-settings).",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "get",
		Short: "Show account Workers defaults",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetWorkerAccountSettings(cmd.Context(), ref.ID)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, accountSettingsHeaders(), accountSettingsRow)
		},
	})
	cmd.AddCommand(newAccountSettingsUpdate(rt))
	return cmd
}

func newAccountSettingsUpdate(rt *app.Runtime) *cobra.Command {
	var modelFlag, settingsFlag string
	var greenCompute bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update account Workers defaults",
		Long: "Update account defaults. Provided fields are merged into the current settings,\n" +
			"so fields this CLI does not model are preserved.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]any{}
			if cmd.Flags().Changed("default-usage-model") {
				body["default_usage_model"] = modelFlag
			}
			if cmd.Flags().Changed("green-compute") {
				body["green_compute"] = greenCompute
			}
			if cmd.Flags().Changed("settings") {
				extra, err := cmdutil.ParseSecretCarryingSettings(rt, "settings", settingsFlag)
				if err != nil {
					return err
				}
				for k, v := range extra {
					body[k] = v
				}
			}
			if len(body) == 0 {
				return errors.Usage("nothing to update; pass at least one of --default-usage-model, --green-compute, --settings")
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would update account Workers settings")
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateWorkerAccountSettings(cmd.Context(), ref.ID, body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, accountSettingsHeaders(), accountSettingsRow)
		},
	}
	cmd.Flags().StringVar(&modelFlag, "default-usage-model", "", "default usage model (standard, bundled, unbound)")
	cmd.Flags().BoolVar(&greenCompute, "green-compute", false, "schedule deployments in low-carbon regions by default")
	cmd.Flags().StringVar(&settingsFlag, "settings", "", "additional settings as a JSON object, inline or @file")
	return cmd
}
