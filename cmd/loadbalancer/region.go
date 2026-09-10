package loadbalancer

import (
	"encoding/json"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/output"
)

func regionRows(raw json.RawMessage) []string {
	return []string{cmdutil.CompactJSON(raw)}
}

func newRegionGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "region",
		Short: "Load balancing regions",
		Long:  "Load balancing regions (/accounts/{account_id}/load_balancers/regions). The API returns untyped objects, so regions are rendered as JSON.",
	}
	cmd.AddCommand(newRegionList(rt))
	cmd.AddCommand(newRegionGet(rt))
	return cmd
}

func newRegionList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List regions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListLoadBalancerRegions(cmd.Context(), ref.ID, rt.Policy())
			if err != nil {
				return err
			}
			if rt.Raw() {
				return rt.Printer().Raw(res.RawBody)
			}
			if rt.Format() != output.Table {
				return rt.Printer().Emit(res.Items)
			}
			rows := make([][]string, 0, len(res.Items))
			for _, item := range res.Items {
				rows = append(rows, regionRows(item))
			}
			return rt.Printer().PrintTable([]string{"REGION"}, rows)
		},
	}
}

func newRegionGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get REGION_ID",
		Short: "Show one region",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetLoadBalancerRegion(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.Raw() {
				return rt.Printer().Raw(res.RawBody)
			}
			if rt.Format() != output.Table {
				return rt.Printer().Emit(res.Item)
			}
			return rt.Printer().PrintTable([]string{"REGION"}, [][]string{regionRows(res.Item)})
		},
	}
}
