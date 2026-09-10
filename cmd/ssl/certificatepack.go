package ssl

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

// packDeployValues are the deploy environments accepted by the API.
var packDeployValues = []string{"staging", "production"}

func packRow(p cloudflare.CertificatePack) []string {
	hosts := strings.Join(p.Hosts, ",")
	return []string{p.ID, p.Type, p.Status, hosts, p.PrimaryCertificate}
}

func newCertificatePackGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "certificate-pack",
		Short: "Zone SSL certificate packs",
	}
	cmd.AddCommand(newCertificatePackList(rt))
	cmd.AddCommand(newCertificatePackGet(rt))
	return cmd
}

func newCertificatePackList(rt *app.Runtime) *cobra.Command {
	var statusFlag, deployFlag string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List certificate packs of a zone",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if deployFlag != "" && !contains(packDeployValues, deployFlag) {
				return errors.Usage("invalid --deploy %q (supported: %s)", deployFlag, strings.Join(packDeployValues, ", "))
			}
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			q := cloudflare.CertificatePackQuery{Status: statusFlag, Deploy: deployFlag}
			res, err := client.ListCertificatePacks(cmd.Context(), zoneID, q, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, []string{"ID", "TYPE", "STATUS", "HOSTS", "PRIMARY"}, packRow)
		},
	}
	cmd.Flags().StringVar(&statusFlag, "status", "", "only packs with this status")
	cmd.Flags().StringVar(&deployFlag, "deploy", "", "only packs in this environment (staging, production)")
	return cmd
}

func newCertificatePackGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get PACK_ID",
		Short: "Show one certificate pack",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetCertificatePack(cmd.Context(), zoneID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"ID", "TYPE", "STATUS", "HOSTS", "PRIMARY"}, packRow)
		},
	}
}
