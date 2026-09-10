package zerotrust

import (
	"strconv"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func gatewayLocationRow(l cloudflare.GatewayLocation) []string {
	return []string{l.ID, l.Name, strconv.FormatBool(l.ClientDefault), strconv.FormatBool(l.ECSSupport), compactJSON(l.Networks), l.DOHSubdomain}
}

func gatewayLocationHeaders() []string {
	return []string{"ID", "NAME", "CLIENT DEFAULT", "ECS", "NETWORKS", "DOH SUBDOMAIN"}
}

type locationFlagValues struct {
	rt               *app.Runtime
	Name             string
	Networks         string
	Endpoints        string
	MaxTTL           string
	DNSDestinationID string
	Settings         string
	ClientDefault    bool
	ECSSupport       bool
}

func addLocationFlags(rt *app.Runtime, cmd *cobra.Command, f *locationFlagValues) {
	f.rt = rt
	cmd.Flags().StringVar(&f.Name, "name", "", "location name (required on create)")
	cmd.Flags().StringVar(&f.Networks, "networks", "", "comma-separated CIDRs that resolve to this location")
	cmd.Flags().StringVar(&f.Endpoints, "endpoints", "", "endpoints object as JSON (for example {\"doh\":{\"enabled\":true}}), inline or @file")
	cmd.Flags().StringVar(&f.MaxTTL, "max-ttl", "", "max_ttl object as JSON (for example {\"dns_ttl\":30}), inline or @file")
	cmd.Flags().StringVar(&f.DNSDestinationID, "dns-destination-ips-id", "", "DNS destination IPs id")
	cmd.Flags().BoolVar(&f.ClientDefault, "client-default", false, "use this location as the client default")
	cmd.Flags().BoolVar(&f.ECSSupport, "ecs-support", false, "enable EDNS client subnet support")
	cmd.Flags().StringVar(&f.Settings, "settings", "", "additional location fields as a JSON object, inline or @file")
}

func (f *locationFlagValues) overrides(cmd *cobra.Command) (map[string]any, error) {
	body := map[string]any{}
	changed := func(name string) bool { return cmd.Flags().Changed(name) }
	if changed("name") {
		body["name"] = f.Name
	}
	if changed("networks") {
		networks := splitList(f.Networks)
		entries := make([]map[string]string, 0, len(networks))
		for _, cidr := range networks {
			entries = append(entries, map[string]string{"network": cidr})
		}
		body["networks"] = entries
	}
	if changed("client-default") {
		body["client_default"] = f.ClientDefault
	}
	if changed("ecs-support") {
		body["ecs_support"] = f.ECSSupport
	}
	if changed("dns-destination-ips-id") {
		body["dns_destination_ips_id"] = f.DNSDestinationID
	}
	for _, item := range []struct {
		flag  string
		value string
		key   string
	}{
		{"endpoints", f.Endpoints, "endpoints"},
		{"max-ttl", f.MaxTTL, "max_ttl"},
	} {
		if !changed(item.flag) {
			continue
		}
		obj, err := parseSecretCarryingObject(f.rt, item.flag, item.value)
		if err != nil {
			return nil, err
		}
		body[item.key] = obj
	}
	if changed("settings") {
		extra, err := parseSecretCarryingSettings(f.rt, "settings", f.Settings)
		if err != nil {
			return nil, err
		}
		for k, v := range extra {
			body[k] = v
		}
	}
	return body, nil
}

func newGatewayLocationGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "location",
		Short: "Gateway DNS locations",
		Long:  "Gateway DNS locations (/accounts/{account_id}/gateway/locations).",
	}
	cmd.AddCommand(newGatewayLocationList(rt))
	cmd.AddCommand(newGatewayLocationGet(rt))
	cmd.AddCommand(newGatewayLocationCreate(rt))
	cmd.AddCommand(newGatewayLocationUpdate(rt))
	cmd.AddCommand(newGatewayLocationDelete(rt))
	return cmd
}

func newGatewayLocationList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List Gateway locations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListGatewayLocations(cmd.Context(), ref.ID, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, gatewayLocationHeaders(), gatewayLocationRow)
		},
	}
}

func newGatewayLocationGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get LOCATION_ID",
		Short: "Show one Gateway location",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetGatewayLocation(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, gatewayLocationHeaders(), gatewayLocationRow)
		},
	}
}

func newGatewayLocationCreate(rt *app.Runtime) *cobra.Command {
	var f locationFlagValues
	cmd := &cobra.Command{
		Use:   "create --name NAME",
		Short: "Create a Gateway location",
		Long: "Create a Gateway DNS location.\n\n" +
			"Example:\n" +
			"  flareadm zero-trust gateway location create --name office \\\n" +
			"    --networks 192.0.2.0/24 --client-default",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.Name == "" {
				return errors.Usage("--name is required")
			}
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would create Gateway location "+f.Name)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateGatewayLocation(cmd.Context(), ref.ID, body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, gatewayLocationHeaders(), gatewayLocationRow)
		},
	}
	addLocationFlags(rt, cmd, &f)
	return cmd
}

func newGatewayLocationUpdate(rt *app.Runtime) *cobra.Command {
	var f locationFlagValues
	cmd := &cobra.Command{
		Use:   "update LOCATION_ID",
		Short: "Update a Gateway location",
		Long: "Update a Gateway location. Provided fields are merged into the current location\n" +
			"and the result is PUT, so fields this CLI does not model are preserved.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if len(body) == 0 {
				return errors.Usage("nothing to update; pass at least one location flag or --settings")
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would update Gateway location "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateGatewayLocation(cmd.Context(), ref.ID, args[0], body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, gatewayLocationHeaders(), gatewayLocationRow)
		},
	}
	addLocationFlags(rt, cmd, &f)
	return cmd
}

func newGatewayLocationDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete LOCATION_ID",
		Short: "Delete a Gateway location",
		Long: "Delete a Gateway location. Destructive: prompts for confirmation unless --yes\n" +
			"is given; --dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetGatewayLocation(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would delete Gateway location "+existing.Item.Name)
			}
			if err := rt.Confirm("Delete Gateway location " + existing.Item.Name + "?"); err != nil {
				return err
			}
			if err := client.DeleteGatewayLocation(cmd.Context(), ref.ID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted Gateway location %s", args[0])
			return nil
		},
	}
	return cmd
}
