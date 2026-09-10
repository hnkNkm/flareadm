package zerotrust

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func routeRow(r cloudflare.TunnelRoute) []string {
	return []string{r.ID, r.Network, r.TunnelID, r.Comment, r.VirtualNetworkID, dateOnly(r.CreatedAt)}
}

func routeHeaders() []string {
	return []string{"ID", "NETWORK", "TUNNEL ID", "COMMENT", "VIRTUAL NETWORK", "CREATED"}
}

func newRouteGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "route",
		Short: "Private network routes (tunnel routes)",
		Long: "Zero Trust private network routes. These live under the accounts teamnet API\n" +
			"(/accounts/{account_id}/teamnet/routes), not under the tunnel API.",
	}
	cmd.AddCommand(newRouteList(rt))
	cmd.AddCommand(newRouteGet(rt))
	cmd.AddCommand(newRouteCreate(rt))
	cmd.AddCommand(newRouteUpdate(rt))
	cmd.AddCommand(newRouteDelete(rt))
	return cmd
}

func newRouteList(rt *app.Runtime) *cobra.Command {
	var networkFlag, tunnelFlag, commentFlag string
	var deletedFlag bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List private network routes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			q := cloudflare.TunnelRouteQuery{
				NetworkSubset: networkFlag, TunnelID: tunnelFlag,
				Comment: commentFlag, IsDeleted: deletedFlag,
			}
			res, err := client.ListTunnelRoutes(cmd.Context(), ref.ID, q, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, routeHeaders(), routeRow)
		},
	}
	cmd.Flags().StringVar(&networkFlag, "network-subset", "", "only routes inside this CIDR subset")
	cmd.Flags().StringVar(&tunnelFlag, "tunnel-id", "", "only routes attached to this tunnel")
	cmd.Flags().StringVar(&commentFlag, "comment", "", "only routes with this comment")
	cmd.Flags().BoolVar(&deletedFlag, "deleted", false, "include deleted routes")
	return cmd
}

func newRouteGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get ROUTE_ID",
		Short: "Show one route",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetTunnelRoute(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, routeHeaders(), routeRow)
		},
	}
}

func newRouteCreate(rt *app.Runtime) *cobra.Command {
	var networkFlag, tunnelFlag, commentFlag, vnetFlag string
	cmd := &cobra.Command{
		Use:   "create --network CIDR --tunnel-id TUNNEL_ID",
		Short: "Create a private network route",
		Long: "Create a private network route.\n\n" +
			"Example:\n" +
			"  flareadm zero-trust route create --network 10.0.0.0/8 --tunnel-id <tunnel> --comment \"office\"",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if networkFlag == "" {
				return errors.Usage("--network is required")
			}
			if tunnelFlag == "" {
				return errors.Usage("--tunnel-id is required")
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would create route "+networkFlag+" via tunnel "+tunnelFlag)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateTunnelRoute(cmd.Context(), ref.ID, cloudflare.TunnelRouteWrite{
				Network: networkFlag, TunnelID: tunnelFlag, Comment: commentFlag, VirtualNetworkID: vnetFlag,
			})
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, routeHeaders(), routeRow)
		},
	}
	cmd.Flags().StringVar(&networkFlag, "network", "", "route CIDR (required)")
	cmd.Flags().StringVar(&tunnelFlag, "tunnel-id", "", "tunnel that serves the route (required)")
	cmd.Flags().StringVar(&commentFlag, "comment", "", "route comment")
	cmd.Flags().StringVar(&vnetFlag, "virtual-network-id", "", "virtual network id")
	return cmd
}

func newRouteUpdate(rt *app.Runtime) *cobra.Command {
	var networkFlag, tunnelFlag, commentFlag, vnetFlag string
	cmd := &cobra.Command{
		Use:   "update ROUTE_ID",
		Short: "Update a private network route",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			up := cloudflare.TunnelRouteEdit{}
			changed := false
			if cmd.Flags().Changed("network") {
				up.Network = &networkFlag
				changed = true
			}
			if cmd.Flags().Changed("tunnel-id") {
				up.TunnelID = &tunnelFlag
				changed = true
			}
			if cmd.Flags().Changed("comment") {
				up.Comment = &commentFlag
				changed = true
			}
			if cmd.Flags().Changed("virtual-network-id") {
				up.VirtualNetworkID = &vnetFlag
				changed = true
			}
			if !changed {
				return errors.Usage("nothing to update; pass at least one of --network, --tunnel-id, --comment, --virtual-network-id")
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would update route "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateTunnelRoute(cmd.Context(), ref.ID, args[0], up)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, routeHeaders(), routeRow)
		},
	}
	cmd.Flags().StringVar(&networkFlag, "network", "", "new route CIDR")
	cmd.Flags().StringVar(&tunnelFlag, "tunnel-id", "", "new serving tunnel")
	cmd.Flags().StringVar(&commentFlag, "comment", "", "new comment")
	cmd.Flags().StringVar(&vnetFlag, "virtual-network-id", "", "new virtual network id")
	return cmd
}

func newRouteDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete ROUTE_ID",
		Short: "Delete a private network route",
		Long: "Delete a route. Destructive: prompts for confirmation unless --yes is\n" +
			"given; --dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetTunnelRoute(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would delete route "+existing.Item.Network+" ("+existing.Item.ID+")")
			}
			if err := rt.Confirm("Delete route " + existing.Item.Network + "?"); err != nil {
				return err
			}
			if err := client.DeleteTunnelRoute(cmd.Context(), ref.ID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted route %s", args[0])
			return nil
		},
	}
	return cmd
}
