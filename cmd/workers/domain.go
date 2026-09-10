package workers

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func domainRow(d cloudflare.WorkerDomain) []string {
	return []string{d.ID, d.Hostname, d.Service, d.Environment, d.ZoneName}
}

func domainHeaders() []string {
	return []string{"ID", "HOSTNAME", "SERVICE", "ENVIRONMENT", "ZONE"}
}

func newDomainGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "domain",
		Short: "Workers custom domains",
		Long:  "Account-scoped custom domains attached to Workers (/accounts/{account_id}/workers/domains).",
	}
	cmd.AddCommand(newDomainList(rt))
	cmd.AddCommand(newDomainGet(rt))
	cmd.AddCommand(newDomainCreate(rt))
	cmd.AddCommand(newDomainDelete(rt))
	return cmd
}

func newDomainList(rt *app.Runtime) *cobra.Command {
	var f cloudflare.WorkerDomainQuery
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List Workers custom domains",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListWorkerDomains(cmd.Context(), ref.ID, f, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, domainHeaders(), domainRow)
		},
	}
	cmd.Flags().StringVar(&f.Hostname, "hostname", "", "only domains with this hostname")
	cmd.Flags().StringVar(&f.Service, "service", "", "only domains attached to this script")
	cmd.Flags().StringVar(&f.Environment, "environment", "", "only domains in this environment (production, preview)")
	cmd.Flags().StringVar(&f.ZoneName, "zone-name", "", "only domains in this zone name")
	return cmd
}

func newDomainGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get DOMAIN_ID",
		Short: "Show one Workers custom domain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetWorkerDomain(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, domainHeaders(), domainRow)
		},
	}
}

func newDomainCreate(rt *app.Runtime) *cobra.Command {
	var hostnameFlag, serviceFlag, environmentFlag, zoneIDFlag, zoneNameFlag string
	cmd := &cobra.Command{
		Use:   "create --hostname HOSTNAME --service SCRIPT",
		Short: "Attach a custom domain to a Worker",
		Long: "Attach (or re-attach) a custom domain. The API operation is idempotent.\n\n" +
			"Example:\n" +
			"  flareadm workers domain create --hostname api.example.com --service api \\\n" +
			"    --zone-name example.com --environment production",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if hostnameFlag == "" {
				return errors.Usage("--hostname is required")
			}
			if serviceFlag == "" {
				return errors.Usage("--service is required")
			}
			body := map[string]any{"hostname": hostnameFlag, "service": serviceFlag}
			if environmentFlag != "" {
				body["environment"] = environmentFlag
			}
			if zoneIDFlag != "" {
				body["zone_id"] = zoneIDFlag
			}
			if zoneNameFlag != "" {
				body["zone_name"] = zoneNameFlag
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would attach domain "+hostnameFlag+" to script "+serviceFlag)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.AttachWorkerDomain(cmd.Context(), ref.ID, body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, domainHeaders(), domainRow)
		},
	}
	cmd.Flags().StringVar(&hostnameFlag, "hostname", "", "hostname to attach (required)")
	cmd.Flags().StringVar(&serviceFlag, "service", "", "script that serves the hostname (required)")
	cmd.Flags().StringVar(&environmentFlag, "environment", "", "environment (production, preview)")
	cmd.Flags().StringVar(&zoneIDFlag, "zone-id", "", "zone id of the hostname")
	cmd.Flags().StringVar(&zoneNameFlag, "zone-name", "", "zone name of the hostname")
	return cmd
}

func newDomainDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete DOMAIN_ID",
		Short: "Detach a custom domain",
		Long: "Detach a custom domain from its Worker. Destructive: prompts for confirmation\n" +
			"unless --yes is given; --dry-run previews the change without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetWorkerDomain(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would detach domain "+existing.Item.Hostname)
			}
			if err := rt.Confirm("Detach domain " + existing.Item.Hostname + "?"); err != nil {
				return err
			}
			if err := client.DeleteWorkerDomain(cmd.Context(), ref.ID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("detached domain %s", args[0])
			return nil
		},
	}
	return cmd
}
