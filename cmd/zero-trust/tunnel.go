package zerotrust

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func tunnelRow(t cloudflare.Tunnel) []string {
	return []string{t.ID, t.Name, t.Status, t.Type, t.ConfigSrc, strconv.Itoa(len(t.Connections)), dateOnly(t.CreatedAt)}
}

func tunnelHeaders() []string {
	return []string{"ID", "NAME", "STATUS", "TYPE", "CONFIG SRC", "CONNECTIONS", "CREATED"}
}

func connectionRow(c cloudflare.TunnelConnection) []string {
	return []string{c.ID, c.Arch, strconv.FormatInt(c.ConfigVersion, 10), strings.Join(c.Features, ","), dateOnly(c.RunAt)}
}

func newTunnelGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tunnel",
		Short: "Cloudflare Tunnels (cloudflared)",
	}
	cmd.AddCommand(newTunnelList(rt))
	cmd.AddCommand(newTunnelGet(rt))
	cmd.AddCommand(newTunnelCreate(rt))
	cmd.AddCommand(newTunnelUpdate(rt))
	cmd.AddCommand(newTunnelDelete(rt))
	cmd.AddCommand(newTunnelToken(rt))
	cmd.AddCommand(newTunnelConnectionGroup(rt))
	cmd.AddCommand(newTunnelConfigurationGroup(rt))
	return cmd
}

func newTunnelList(rt *app.Runtime) *cobra.Command {
	var nameFlag, statusFlag, uuidFlag string
	var deletedFlag bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List tunnels",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			q := cloudflare.TunnelQuery{Name: nameFlag, Status: statusFlag, UUID: uuidFlag, IsDeleted: deletedFlag}
			res, err := client.ListTunnels(cmd.Context(), ref.ID, q, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, tunnelHeaders(), tunnelRow)
		},
	}
	cmd.Flags().StringVar(&nameFlag, "name", "", "only tunnels with this exact name")
	cmd.Flags().StringVar(&statusFlag, "status", "", "only tunnels with this status")
	cmd.Flags().StringVar(&uuidFlag, "uuid", "", "only the tunnel with this UUID")
	cmd.Flags().BoolVar(&deletedFlag, "deleted", false, "include deleted tunnels")
	return cmd
}

func newTunnelGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get TUNNEL_ID",
		Short: "Show one tunnel",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetTunnel(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, tunnelHeaders(), tunnelRow)
		},
	}
}

func newTunnelCreate(rt *app.Runtime) *cobra.Command {
	var nameFlag, configSrcFlag, secretFlag string
	cmd := &cobra.Command{
		Use:   "create --name NAME",
		Short: "Create a tunnel",
		Long: "Create a cloudflared tunnel.\n\n" +
			"Example:\n" +
			"  flareadm zero-trust tunnel create --name edge --config-src cloudflare\n\n" +
			"--tunnel-secret is @file-only: it is a credential and is never printed,\n" +
			"logged or echoed in errors.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if nameFlag == "" {
				return errors.Usage("--name is required")
			}
			if configSrcFlag != "" && !contains(cloudflare.TunnelConfigSrcValues, configSrcFlag) {
				return errors.Usage("invalid --config-src %q (supported: %s)", configSrcFlag, strings.Join(cloudflare.TunnelConfigSrcValues, ", "))
			}
			w := cloudflare.TunnelWrite{Name: &nameFlag}
			if cmd.Flags().Changed("config-src") {
				w.ConfigSrc = &configSrcFlag
			}
			if cmd.Flags().Changed("tunnel-secret") {
				secret, err := fileOnly("tunnel-secret", secretFlag)
				if err != nil {
					return err
				}
				rt.ProtectSecret(secret)
				w.TunnelSecret = &secret
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would create tunnel "+nameFlag)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateTunnel(cmd.Context(), ref.ID, w)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, tunnelHeaders(), tunnelRow)
		},
	}
	cmd.Flags().StringVar(&nameFlag, "name", "", "tunnel name (required)")
	cmd.Flags().StringVar(&configSrcFlag, "config-src", "", "configuration source (local, cloudflare)")
	cmd.Flags().StringVar(&secretFlag, "tunnel-secret", "", "tunnel secret as @file only")
	return cmd
}

func newTunnelUpdate(rt *app.Runtime) *cobra.Command {
	var nameFlag, secretFlag string
	cmd := &cobra.Command{
		Use:   "update TUNNEL_ID",
		Short: "Update a tunnel",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("name") && !cmd.Flags().Changed("tunnel-secret") {
				return errors.Usage("nothing to update; pass at least one of --name, --tunnel-secret")
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would update tunnel "+args[0])
			}
			w := cloudflare.TunnelWrite{}
			if cmd.Flags().Changed("name") {
				if nameFlag == "" {
					return errors.Usage("--name must not be empty")
				}
				w.Name = &nameFlag
			}
			if cmd.Flags().Changed("tunnel-secret") {
				secret, err := fileOnly("tunnel-secret", secretFlag)
				if err != nil {
					return err
				}
				rt.ProtectSecret(secret)
				w.TunnelSecret = &secret
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateTunnel(cmd.Context(), ref.ID, args[0], w)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, tunnelHeaders(), tunnelRow)
		},
	}
	cmd.Flags().StringVar(&nameFlag, "name", "", "new tunnel name")
	cmd.Flags().StringVar(&secretFlag, "tunnel-secret", "", "tunnel secret as @file only")
	return cmd
}

func newTunnelDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete TUNNEL_ID",
		Short: "Delete a tunnel",
		Long: "Delete a tunnel. Destructive: prompts for confirmation unless --yes is\n" +
			"given; --dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetTunnel(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would delete tunnel "+existing.Item.Name)
			}
			if err := rt.Confirm("Delete tunnel " + existing.Item.Name + "?"); err != nil {
				return err
			}
			if err := client.DeleteTunnel(cmd.Context(), ref.ID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted tunnel %s", args[0])
			return nil
		},
	}
	return cmd
}

func newTunnelToken(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "token TUNNEL_ID",
		Short: "Print the tunnel token",
		Long: "Print the tunnel token (a credential used to run cloudflared).\n\n" +
			"The token is written to stdout only and is registered as a secret, so it\n" +
			"never appears in --verbose/--debug diagnostics or error messages. Treat the\n" +
			"output as sensitive: it grants the ability to run the tunnel.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetTunnelToken(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			rt.ProtectSecret(res.Item)
			if rt.Raw() {
				return rt.Printer().Raw(res.RawBody)
			}
			// The token is printed only here, on explicit request.
			_, _ = fmt.Fprintln(rt.Out, res.Item)
			return nil
		},
	}
}

func newTunnelConnectionGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "connection",
		Short: "Tunnel connector connections",
	}
	cmd.AddCommand(newConnectionList(rt))
	cmd.AddCommand(newConnectionGet(rt))
	cmd.AddCommand(newConnectionDelete(rt))
	return cmd
}

func newConnectionList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list TUNNEL_ID",
		Short: "List a tunnel's active connections",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListTunnelConnections(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, []string{"CLIENT ID", "ARCH", "CONFIG VERSION", "FEATURES", "RUN AT"}, connectionRow)
		},
	}
}

func newConnectionGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get TUNNEL_ID CLIENT_ID",
		Short: "Show one connection",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListTunnelConnections(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			for _, c := range res.Items {
				if c.ID == args[1] {
					item := &cloudflare.GetResult[cloudflare.TunnelConnection]{Item: c, RawBody: res.RawBody}
					return app.RenderGet(rt, item, []string{"CLIENT ID", "ARCH", "CONFIG VERSION", "FEATURES", "RUN AT"}, connectionRow)
				}
			}
			return errors.New(errors.CodeNotFound, "connection %q not found on tunnel %s", args[1], args[0])
		},
	}
}

func newConnectionDelete(rt *app.Runtime) *cobra.Command {
	var clientIDFlag string
	cmd := &cobra.Command{
		Use:   "delete TUNNEL_ID --client-id CLIENT_ID",
		Short: "Delete a tunnel connection",
		Long: "Disconnect one cloudflared connector. Destructive: prompts for confirmation\n" +
			"unless --yes is given; --dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if clientIDFlag == "" {
				return errors.Usage("--client-id is required")
			}
			if rt.DryRunFlag {
				return previewLine(rt, fmt.Sprintf("Would delete connection %s from tunnel %s", clientIDFlag, args[0]))
			}
			if err := rt.Confirm(fmt.Sprintf("Delete connection %s from tunnel %s?", clientIDFlag, args[0])); err != nil {
				return err
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			if err := client.DeleteTunnelConnection(cmd.Context(), ref.ID, args[0], clientIDFlag); err != nil {
				return err
			}
			rt.Logger().Infof("deleted connection %s", clientIDFlag)
			return nil
		},
	}
	cmd.Flags().StringVar(&clientIDFlag, "client-id", "", "connection (client) id (required)")
	return cmd
}

func newTunnelConfigurationGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "configuration",
		Short: "Tunnel remote configuration",
	}
	cmd.AddCommand(newConfigurationGet(rt))
	cmd.AddCommand(newConfigurationUpdate(rt))
	return cmd
}

func newConfigurationGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get TUNNEL_ID",
		Short: "Show the tunnel remote configuration",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetTunnelConfiguration(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.Raw() {
				return rt.Printer().Raw(res.RawBody)
			}
			return rt.Printer().Emit(map[string]any{"config": res.Item.Config})
		},
	}
}

func newConfigurationUpdate(rt *app.Runtime) *cobra.Command {
	var configFlag string
	cmd := &cobra.Command{
		Use:   "update TUNNEL_ID --config @config.json",
		Short: "Replace the tunnel remote configuration",
		Long: "Replace the tunnel's remote configuration (ingress and origin settings).\n" +
			"The file content is sent verbatim as the config object, so fields this CLI\n" +
			"does not model are preserved.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("config") {
				return errors.Usage("--config is required (JSON object from @file)")
			}
			text, err := cmdutil.ValueOrFile("config", configFlag)
			if err != nil {
				return err
			}
			config, err := parseJSONObjectText("config", text)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, fmt.Sprintf("Would replace the configuration of tunnel %s (%d bytes)", args[0], len(config)))
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateTunnelConfiguration(cmd.Context(), ref.ID, args[0], config)
			if err != nil {
				return err
			}
			if rt.Raw() {
				return rt.Printer().Raw(res.RawBody)
			}
			return rt.Printer().Emit(map[string]any{"config": res.Item.Config})
		},
	}
	cmd.Flags().StringVar(&configFlag, "config", "", "configuration JSON object, inline or @file")
	return cmd
}
