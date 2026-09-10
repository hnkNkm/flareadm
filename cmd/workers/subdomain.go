package workers

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func subdomainRow(s cloudflare.WorkerSubdomain) []string {
	return []string{s.Subdomain}
}

func newSubdomainGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "subdomain",
		Short: "Account workers.dev subdomain",
		Long:  "Account-level workers.dev subdomain (/accounts/{account_id}/workers/subdomain).",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "get",
		Short: "Show the account workers.dev subdomain",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetWorkerSubdomain(cmd.Context(), ref.ID)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"SUBDOMAIN"}, subdomainRow)
		},
	})
	cmd.AddCommand(newSubdomainUpdate(rt))
	cmd.AddCommand(newSubdomainDelete(rt))
	return cmd
}

func newSubdomainUpdate(rt *app.Runtime) *cobra.Command {
	var nameFlag string
	cmd := &cobra.Command{
		Use:   "update --name NAME",
		Short: "Set the account workers.dev subdomain",
		Long:  "Register or rename the account's workers.dev subdomain.\n\nExample:\n  flareadm workers subdomain update --name acme",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if nameFlag == "" {
				return errors.Usage("--name is required")
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would set the workers.dev subdomain to "+nameFlag)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateWorkerSubdomain(cmd.Context(), ref.ID, nameFlag)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"SUBDOMAIN"}, subdomainRow)
		},
	}
	cmd.Flags().StringVar(&nameFlag, "name", "", "workers.dev subdomain name (required)")
	return cmd
}

func newSubdomainDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Remove the account workers.dev subdomain",
		Long: "Remove the account's workers.dev subdomain. Destructive: every workers.dev\n" +
			"route of the account stops resolving. Prompts for confirmation unless --yes is\n" +
			"given; --dry-run previews the change without confirming.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetWorkerSubdomain(cmd.Context(), ref.ID)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would remove the workers.dev subdomain "+existing.Item.Subdomain)
			}
			question := "Remove the account workers.dev subdomain?"
			if existing.Item.Subdomain != "" {
				question = "Remove the workers.dev subdomain " + existing.Item.Subdomain + "?"
			}
			if err := rt.Confirm(question); err != nil {
				return err
			}
			if err := client.DeleteWorkerSubdomain(cmd.Context(), ref.ID); err != nil {
				return err
			}
			rt.Logger().Infof("removed the workers.dev subdomain")
			return nil
		},
	}
	return cmd
}
