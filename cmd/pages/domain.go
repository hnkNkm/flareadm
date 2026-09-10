package pages

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func domainRow(d cloudflare.PagesProjectDomain) []string {
	return []string{d.Name, d.Status, d.CertificateAuthority, dateOnly(d.CreatedOn)}
}

func domainHeaders() []string {
	return []string{"NAME", "STATUS", "CERTIFICATE AUTHORITY", "CREATED"}
}

func newProjectDomainGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "domain",
		Short: "Pages project domains",
		Long:  "Custom domains of a Pages project (/accounts/{account_id}/pages/projects/{project}/domains).",
	}
	cmd.AddCommand(newProjectDomainList(rt))
	cmd.AddCommand(newProjectDomainGet(rt))
	cmd.AddCommand(newProjectDomainCreate(rt))
	cmd.AddCommand(newProjectDomainUpdate(rt))
	cmd.AddCommand(newProjectDomainDelete(rt))
	return cmd
}

func newProjectDomainList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list PROJECT",
		Short: "List a project's domains",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListPagesProjectDomains(cmd.Context(), ref.ID, args[0], rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, domainHeaders(), domainRow)
		},
	}
}

func newProjectDomainGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get PROJECT DOMAIN_NAME",
		Short: "Show one project domain",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetPagesProjectDomain(cmd.Context(), ref.ID, args[0], args[1])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, domainHeaders(), domainRow)
		},
	}
}

func newProjectDomainCreate(rt *app.Runtime) *cobra.Command {
	var nameFlag string
	cmd := &cobra.Command{
		Use:   "create PROJECT --name DOMAIN",
		Short: "Attach a custom domain",
		Long:  "Attach a custom domain to a Pages project.\n\nExample:\n  flareadm pages project domain create docs --name docs.example.com",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if nameFlag == "" {
				return errors.Usage("--name is required")
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would attach domain "+nameFlag+" to Pages project "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreatePagesProjectDomain(cmd.Context(), ref.ID, args[0], nameFlag)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, domainHeaders(), domainRow)
		},
	}
	cmd.Flags().StringVar(&nameFlag, "name", "", "domain name (required)")
	return cmd
}

func newProjectDomainUpdate(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update PROJECT DOMAIN_NAME",
		Short: "Re-run domain validation",
		Long: "Re-run validation and certificate provisioning for a project domain. The\n" +
			"endpoint exposes no updatable fields, so this command takes no flags and the\n" +
			"reported status reflects the new attempt.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.RevalidatePagesProjectDomain(cmd.Context(), ref.ID, args[0], args[1])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, domainHeaders(), domainRow)
		},
	}
	return cmd
}

func newProjectDomainDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete PROJECT DOMAIN_NAME",
		Short: "Detach a custom domain",
		Long: "Detach a custom domain from a Pages project. Destructive: prompts for\n" +
			"confirmation unless --yes is given; --dry-run previews the change without\n" +
			"confirming.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would detach domain "+args[1]+" from Pages project "+args[0])
			}
			if err := rt.Confirm("Detach domain " + args[1] + " from Pages project " + args[0] + "?"); err != nil {
				return err
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			if err := client.DeletePagesProjectDomain(cmd.Context(), ref.ID, args[0], args[1]); err != nil {
				return err
			}
			rt.Logger().Infof("detached domain %s", args[1])
			return nil
		},
	}
	return cmd
}
