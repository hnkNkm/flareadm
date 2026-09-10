package workers

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func routeRow(r cloudflare.WorkerRoute) []string {
	return []string{r.ID, r.Pattern, r.Script}
}

func routeHeaders() []string {
	return []string{"ID", "PATTERN", "SCRIPT"}
}

func newRouteGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "route",
		Short: "Workers routes",
		Long:  "Zone-scoped Workers routes (/zones/{zone_id}/workers/routes). The zone comes from --zone or the profile default; every other resource in this group is account-scoped.",
	}
	cmd.AddCommand(newRouteList(rt))
	cmd.AddCommand(newRouteGet(rt))
	cmd.AddCommand(newRouteCreate(rt))
	cmd.AddCommand(newRouteUpdate(rt))
	cmd.AddCommand(newRouteDelete(rt))
	return cmd
}

func newRouteList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List Workers routes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListWorkerRoutes(cmd.Context(), zoneID, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, routeHeaders(), routeRow)
		},
	}
}

func newRouteGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get ROUTE_ID",
		Short: "Show one Workers route",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetWorkerRoute(cmd.Context(), zoneID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, routeHeaders(), routeRow)
		},
	}
}

func newRouteCreate(rt *app.Runtime) *cobra.Command {
	var patternFlag, scriptFlag string
	cmd := &cobra.Command{
		Use:   "create --pattern PATTERN --script SCRIPT",
		Short: "Create a Workers route",
		Long: "Create a route in a zone.\n\n" +
			"Example:\n" +
			"  flareadm workers route create --zone example.com \\\n" +
			"    --pattern 'example.com/api/*' --script api",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if patternFlag == "" {
				return errors.Usage("--pattern is required")
			}
			if scriptFlag == "" {
				return errors.Usage("--script is required")
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would create route "+patternFlag+" -> "+scriptFlag)
			}
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateWorkerRoute(cmd.Context(), zoneID, map[string]any{
				"pattern": patternFlag, "script": scriptFlag,
			})
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, routeHeaders(), routeRow)
		},
	}
	cmd.Flags().StringVar(&patternFlag, "pattern", "", "route pattern (required)")
	cmd.Flags().StringVar(&scriptFlag, "script", "", "script that serves the route (required)")
	return cmd
}

func newRouteUpdate(rt *app.Runtime) *cobra.Command {
	var patternFlag, scriptFlag string
	cmd := &cobra.Command{
		Use:   "update ROUTE_ID",
		Short: "Update a Workers route",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]any{}
			if cmd.Flags().Changed("pattern") {
				body["pattern"] = patternFlag
			}
			if cmd.Flags().Changed("script") {
				body["script"] = scriptFlag
			}
			if len(body) == 0 {
				return errors.Usage("nothing to update; pass at least one of --pattern, --script")
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would update route "+args[0])
			}
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateWorkerRoute(cmd.Context(), zoneID, args[0], body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, routeHeaders(), routeRow)
		},
	}
	cmd.Flags().StringVar(&patternFlag, "pattern", "", "new route pattern")
	cmd.Flags().StringVar(&scriptFlag, "script", "", "new script")
	return cmd
}

func newRouteDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete ROUTE_ID",
		Short: "Delete a Workers route",
		Long: "Delete a route. Destructive: prompts for confirmation unless --yes is given;\n" +
			"--dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, zoneID, err := rt.ResolveZone(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetWorkerRoute(cmd.Context(), zoneID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would delete route "+existing.Item.Pattern)
			}
			if err := rt.Confirm("Delete Workers route " + existing.Item.Pattern + "?"); err != nil {
				return err
			}
			if err := client.DeleteWorkerRoute(cmd.Context(), zoneID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted route %s", args[0])
			return nil
		},
	}
	return cmd
}
