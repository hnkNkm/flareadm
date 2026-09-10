// Package loadbalancer implements `flareadm load-balancer ...`: load balancers,
// origin pools, monitors and regions.
package loadbalancer

import (
	"context"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

// New builds the load-balancer command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "load-balancer",
		Short: "Cloudflare Load Balancing",
		Long:  "Cloudflare Load Balancing administration. Load balancers are account-scoped by default and switch to zone scope when --zone is given; pools, monitors and regions are always account-scoped.",
	}
	cmd.AddCommand(newLBList(rt))
	cmd.AddCommand(newLBGet(rt))
	cmd.AddCommand(newLBCreate(rt))
	cmd.AddCommand(newLBUpdate(rt))
	cmd.AddCommand(newLBDelete(rt))
	cmd.AddCommand(newPoolGroup(rt))
	cmd.AddCommand(newMonitorGroup(rt))
	cmd.AddCommand(newRegionGroup(rt))
	return cmd
}

// lbScope resolves the account-or-zone scope: an explicit --zone selects zone
// scope, otherwise account scope is used.
func lbScope(ctx context.Context, rt *app.Runtime) (*cloudflare.Client, string, string, error) {
	if rt.ZoneFlag != "" {
		client, zoneID, err := rt.ResolveZone(ctx)
		if err != nil {
			return nil, "", "", err
		}
		return client, "", zoneID, nil
	}
	client, ref, err := rt.ResolveAccount(ctx)
	if err != nil {
		return nil, "", "", err
	}
	return client, ref.ID, "", nil
}

func lbRow(l cloudflare.LoadBalancer) []string {
	return []string{l.ID, l.Name, strconv.FormatBool(l.Enabled), l.SteeringPolicy, joinList(l.DefaultPools), l.FallbackPool}
}

func joinList(items []string) string {
	out := ""
	for i, item := range items {
		if i > 0 {
			out += ","
		}
		out += item
	}
	return out
}

func lbHeaders() []string {
	return []string{"ID", "NAME", "ENABLED", "STEERING", "DEFAULT POOLS", "FALLBACK POOL"}
}

func poolRow(p cloudflare.LoadBalancerPool) []string {
	return []string{p.ID, p.Name, strconv.FormatBool(p.Enabled), strconv.Itoa(len(p.Origins)), p.Monitor, strconv.FormatInt(p.MinimumOrigins, 10)}
}

func poolHeaders() []string {
	return []string{"ID", "NAME", "ENABLED", "ORIGINS", "MONITOR", "MINIMUM ORIGINS"}
}

func monitorRow(m cloudflare.LoadBalancerMonitor) []string {
	return []string{m.ID, m.Type, m.Method, m.Path, strconv.FormatInt(m.Interval, 10), strconv.FormatInt(m.Timeout, 10)}
}

func monitorHeaders() []string {
	return []string{"ID", "TYPE", "METHOD", "PATH", "INTERVAL", "TIMEOUT"}
}

type lbFlagValues struct {
	rt              *app.Runtime
	Name            string
	Description     string
	DefaultPools    string
	FallbackPool    string
	SteeringPolicy  string
	SessionAffinity string
	RegionPools     string
	CountryPools    string
	PopPools        string
	Rules           string
	Settings        string
	TTL             int64
	Enabled         bool
	Proxied         bool
}

func addLBFlags(rt *app.Runtime, cmd *cobra.Command, f *lbFlagValues) {
	f.rt = rt
	cmd.Flags().StringVar(&f.Name, "name", "", "load balancer name (required on create)")
	cmd.Flags().StringVar(&f.Description, "description", "", "description")
	cmd.Flags().StringVar(&f.DefaultPools, "default-pools", "", "comma-separated pool ids used by default (required on create)")
	cmd.Flags().StringVar(&f.FallbackPool, "fallback-pool", "", "pool id used when no other pool is healthy (required on create)")
	cmd.Flags().StringVar(&f.SteeringPolicy, "steering-policy", "", "steering policy (off, geo, random, dynamic, proximity, least_conn, ...)")
	cmd.Flags().StringVar(&f.SessionAffinity, "session-affinity", "", "session affinity (none, cookie, ip_cookie)")
	cmd.Flags().Int64Var(&f.TTL, "ttl", 0, "DNS TTL in seconds")
	cmd.Flags().BoolVar(&f.Enabled, "enabled", false, "enable the load balancer (use --enabled=false to disable)")
	cmd.Flags().BoolVar(&f.Proxied, "proxied", false, "proxy traffic through Cloudflare")
	cmd.Flags().StringVar(&f.RegionPools, "region-pools", "", "region pools object as JSON, inline or @file")
	cmd.Flags().StringVar(&f.CountryPools, "country-pools", "", "country pools object as JSON, inline or @file")
	cmd.Flags().StringVar(&f.PopPools, "pop-pools", "", "POP pools object as JSON, inline or @file")
	cmd.Flags().StringVar(&f.Rules, "rules", "", "rules array as JSON, inline or @file")
	cmd.Flags().StringVar(&f.Settings, "settings", "", "additional fields as a JSON object, inline or @file")
}

func (f *lbFlagValues) overrides(cmd *cobra.Command) (map[string]any, error) {
	body := map[string]any{}
	changed := func(name string) bool { return cmd.Flags().Changed(name) }
	if changed("name") {
		body["name"] = f.Name
	}
	if changed("description") {
		body["description"] = f.Description
	}
	if changed("default-pools") {
		body["default_pools"] = cmdutil.SplitList(f.DefaultPools)
	}
	if changed("fallback-pool") {
		body["fallback_pool"] = f.FallbackPool
	}
	if changed("steering-policy") {
		body["steering_policy"] = f.SteeringPolicy
	}
	if changed("session-affinity") {
		body["session_affinity"] = f.SessionAffinity
	}
	if changed("ttl") {
		body["ttl"] = f.TTL
	}
	if changed("enabled") {
		body["enabled"] = f.Enabled
	}
	if changed("proxied") {
		body["proxied"] = f.Proxied
	}
	for _, item := range []struct {
		flag  string
		value string
		key   string
		obj   bool
	}{
		{"region-pools", f.RegionPools, "region_pools", true},
		{"country-pools", f.CountryPools, "country_pools", true},
		{"pop-pools", f.PopPools, "pop_pools", true},
		{"rules", f.Rules, "rules", false},
	} {
		if !changed(item.flag) {
			continue
		}
		if item.obj {
			obj, err := cmdutil.ParseSecretCarryingObject(f.rt, item.flag, item.value)
			if err != nil {
				return nil, err
			}
			body[item.key] = obj
			continue
		}
		arr, err := cmdutil.ParseJSONArrayList(item.flag, item.value)
		if err != nil {
			return nil, err
		}
		body[item.key] = arr
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

func newLBList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List load balancers",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, accountID, zoneID, err := lbScope(cmd.Context(), rt)
			if err != nil {
				return err
			}
			res, err := client.ListLoadBalancers(cmd.Context(), accountID, zoneID, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, lbHeaders(), lbRow)
		},
	}
}

func newLBGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get LOAD_BALANCER_ID",
		Short: "Show one load balancer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, accountID, zoneID, err := lbScope(cmd.Context(), rt)
			if err != nil {
				return err
			}
			res, err := client.GetLoadBalancer(cmd.Context(), accountID, zoneID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, lbHeaders(), lbRow)
		},
	}
}

func newLBCreate(rt *app.Runtime) *cobra.Command {
	var f lbFlagValues
	cmd := &cobra.Command{
		Use:   "create --name NAME --default-pools POOL[,POOL] --fallback-pool POOL",
		Short: "Create a load balancer",
		Long: "Create a load balancer.\n\n" +
			"Example:\n" +
			"  flareadm load-balancer create --name www --default-pools <pool-a>,<pool-b> \\\n" +
			"    --fallback-pool <pool-c> --proxied",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.Name == "" {
				return errors.Usage("--name is required")
			}
			if len(cmdutil.SplitList(f.DefaultPools)) == 0 {
				return errors.Usage("--default-pools is required")
			}
			if f.FallbackPool == "" {
				return errors.Usage("--fallback-pool is required")
			}
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would create load balancer "+f.Name)
			}
			client, accountID, zoneID, err := lbScope(cmd.Context(), rt)
			if err != nil {
				return err
			}
			res, err := client.CreateLoadBalancer(cmd.Context(), accountID, zoneID, body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, lbHeaders(), lbRow)
		},
	}
	addLBFlags(rt, cmd, &f)
	return cmd
}

func newLBUpdate(rt *app.Runtime) *cobra.Command {
	var f lbFlagValues
	cmd := &cobra.Command{
		Use:   "update LOAD_BALANCER_ID",
		Short: "Update a load balancer",
		Long:  "Partially update a load balancer: only the provided fields change, so fields this CLI does not model are preserved.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if len(body) == 0 {
				return errors.Usage("nothing to update; pass at least one load balancer flag or --settings")
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would update load balancer "+args[0])
			}
			client, accountID, zoneID, err := lbScope(cmd.Context(), rt)
			if err != nil {
				return err
			}
			res, err := client.UpdateLoadBalancer(cmd.Context(), accountID, zoneID, args[0], body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, lbHeaders(), lbRow)
		},
	}
	addLBFlags(rt, cmd, &f)
	return cmd
}

func newLBDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete LOAD_BALANCER_ID",
		Short: "Delete a load balancer",
		Long: "Delete a load balancer. Destructive: prompts for confirmation unless --yes is\n" +
			"given; --dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, accountID, zoneID, err := lbScope(cmd.Context(), rt)
			if err != nil {
				return err
			}
			existing, err := client.GetLoadBalancer(cmd.Context(), accountID, zoneID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would delete load balancer "+existing.Item.Name)
			}
			if err := rt.Confirm("Delete load balancer " + existing.Item.Name + "?"); err != nil {
				return err
			}
			if err := client.DeleteLoadBalancer(cmd.Context(), accountID, zoneID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted load balancer %s", args[0])
			return nil
		},
	}
	return cmd
}
