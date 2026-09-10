package loadbalancer

import (
	"encoding/json"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/errors"
)

type poolFlagValues struct {
	rt                *app.Runtime
	Name              string
	Description       string
	Origins           string
	Monitor           string
	NotificationEmail string
	CheckRegions      string
	LoadShedding      string
	OriginSteering    string
	Settings          string
	MinimumOrigins    int64
	Enabled           bool
}

func addPoolFlags(rt *app.Runtime, cmd *cobra.Command, f *poolFlagValues) {
	f.rt = rt
	cmd.Flags().StringVar(&f.Name, "name", "", "pool name (required on create)")
	cmd.Flags().StringVar(&f.Description, "description", "", "description")
	cmd.Flags().StringVar(&f.Origins, "origins", "", "origins array as JSON, inline or @file (required on create)")
	cmd.Flags().StringVar(&f.Monitor, "monitor", "", "monitor id used to probe the origins")
	cmd.Flags().Int64Var(&f.MinimumOrigins, "minimum-origins", 0, "minimum number of healthy origins")
	cmd.Flags().StringVar(&f.NotificationEmail, "notification-email", "", "email notified about pool state changes")
	cmd.Flags().StringVar(&f.CheckRegions, "check-regions", "", "comma-separated regions to probe from")
	cmd.Flags().BoolVar(&f.Enabled, "enabled", false, "enable the pool (use --enabled=false to disable)")
	cmd.Flags().StringVar(&f.LoadShedding, "load-shedding", "", "load shedding object as JSON, inline or @file")
	cmd.Flags().StringVar(&f.OriginSteering, "origin-steering", "", "origin steering object as JSON, inline or @file")
	cmd.Flags().StringVar(&f.Settings, "settings", "", "additional pool fields as a JSON object, inline or @file")
}

func (f *poolFlagValues) overrides(cmd *cobra.Command) (map[string]any, error) {
	body := map[string]any{}
	changed := func(name string) bool { return cmd.Flags().Changed(name) }
	if changed("name") {
		body["name"] = f.Name
	}
	if changed("description") {
		body["description"] = f.Description
	}
	if changed("origins") {
		arr, err := cmdutil.ParseJSONArrayList("origins", f.Origins)
		if err != nil {
			return nil, err
		}
		cmdutil.ProtectHeaderValues(f.rt, decodeRaw(arr))
		body["origins"] = arr
	}
	if changed("monitor") {
		body["monitor"] = f.Monitor
	}
	if changed("minimum-origins") {
		body["minimum_origins"] = f.MinimumOrigins
	}
	if changed("notification-email") {
		body["notification_email"] = f.NotificationEmail
	}
	if changed("check-regions") {
		body["check_regions"] = cmdutil.SplitList(f.CheckRegions)
	}
	if changed("enabled") {
		body["enabled"] = f.Enabled
	}
	for _, item := range []struct {
		flag  string
		value string
		key   string
	}{
		{"load-shedding", f.LoadShedding, "load_shedding"},
		{"origin-steering", f.OriginSteering, "origin_steering"},
	} {
		if !changed(item.flag) {
			continue
		}
		obj, err := cmdutil.ParseSecretCarryingObject(f.rt, item.flag, item.value)
		if err != nil {
			return nil, err
		}
		body[item.key] = obj
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

func newPoolGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pool",
		Short: "Origin pools",
		Long:  "Origin pools (/accounts/{account_id}/load_balancers/pools). Pools are account-scoped.",
	}
	cmd.AddCommand(newPoolList(rt))
	cmd.AddCommand(newPoolGet(rt))
	cmd.AddCommand(newPoolCreate(rt))
	cmd.AddCommand(newPoolUpdate(rt))
	cmd.AddCommand(newPoolDelete(rt))
	cmd.AddCommand(newPoolHealthGroup(rt))
	return cmd
}

func newPoolList(rt *app.Runtime) *cobra.Command {
	var monitorFilter string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List origin pools",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListLoadBalancerPools(cmd.Context(), ref.ID, monitorFilter, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, poolHeaders(), poolRow)
		},
	}
	cmd.Flags().StringVar(&monitorFilter, "monitor", "", "only pools using this monitor id")
	return cmd
}

func newPoolGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get POOL_ID",
		Short: "Show one origin pool",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetLoadBalancerPool(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, poolHeaders(), poolRow)
		},
	}
}

func newPoolCreate(rt *app.Runtime) *cobra.Command {
	var f poolFlagValues
	cmd := &cobra.Command{
		Use:   "create --name NAME --origins @origins.json",
		Short: "Create an origin pool",
		Long: "Create an origin pool.\n\n" +
			"Example:\n" +
			"  flareadm load-balancer pool create --name primary \\\n" +
			"    --origins '[{\"name\":\"a\",\"address\":\"192.0.2.1\"}]'",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.Name == "" {
				return errors.Usage("--name is required")
			}
			if !cmd.Flags().Changed("origins") {
				return errors.Usage("--origins is required (JSON array)")
			}
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would create origin pool "+f.Name)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateLoadBalancerPool(cmd.Context(), ref.ID, body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, poolHeaders(), poolRow)
		},
	}
	addPoolFlags(rt, cmd, &f)
	return cmd
}

func newPoolUpdate(rt *app.Runtime) *cobra.Command {
	var f poolFlagValues
	cmd := &cobra.Command{
		Use:   "update POOL_ID",
		Short: "Update an origin pool",
		Long:  "Partially update a pool: only the provided fields change (--origins replaces the whole origin list).",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if len(body) == 0 {
				return errors.Usage("nothing to update; pass at least one pool flag or --settings")
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would update origin pool "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateLoadBalancerPool(cmd.Context(), ref.ID, args[0], body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, poolHeaders(), poolRow)
		},
	}
	addPoolFlags(rt, cmd, &f)
	return cmd
}

func newPoolDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete POOL_ID",
		Short: "Delete an origin pool",
		Long: "Delete a pool. Destructive: prompts for confirmation unless --yes is given;\n" +
			"--dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetLoadBalancerPool(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would delete origin pool "+existing.Item.Name)
			}
			if err := rt.Confirm("Delete origin pool " + existing.Item.Name + "?"); err != nil {
				return err
			}
			if err := client.DeleteLoadBalancerPool(cmd.Context(), ref.ID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted origin pool %s", args[0])
			return nil
		},
	}
	return cmd
}

func newPoolHealthGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "health",
		Short: "Origin pool health",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "get POOL_ID",
		Short: "Show pool health per point of presence",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetLoadBalancerPoolHealth(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"POOL ID", "POP HEALTH"}, func(raw json.RawMessage) []string {
				var decoded struct {
					PoolID    string          `json:"pool_id"`
					POPHealth json.RawMessage `json:"pop_health"`
				}
				_ = json.Unmarshal(raw, &decoded)
				poolID := decoded.PoolID
				if poolID == "" {
					poolID = args[0]
				}
				return []string{poolID, cmdutil.CompactJSON(decoded.POPHealth)}
			})
		},
	})
	return cmd
}
