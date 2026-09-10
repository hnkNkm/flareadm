// Package hyperdrive implements `flareadm hyperdrive ...`: Hyperdrive
// configuration administration.
package hyperdrive

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
)

// New builds the hyperdrive command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hyperdrive",
		Short: "Hyperdrive configuration administration",
		Long:  "Hyperdrive configuration administration. Account scope is resolved through the standard account resolution.",
	}
	cmd.AddCommand(newConfigGroup(rt))
	return cmd
}

// originHostDatabase extracts host and database names for table output.
func originHostDatabase(origin []byte) (string, string) {
	if len(origin) == 0 {
		return "", ""
	}
	var m map[string]any
	if err := jsonUnmarshal(origin, &m); err != nil {
		return "", ""
	}
	host, _ := m["host"].(string)
	db, _ := m["database"].(string)
	return host, db
}

func configRow(c cloudflare.HyperdriveConfig) []string {
	host, db := originHostDatabase(c.Origin)
	return []string{c.ID, c.Name, host, db, fmt.Sprintf("%d", c.OriginConnectionLimit)}
}

func previewLine(rt *app.Runtime, line string) error {
	if rt.Format() == output.Table {
		_, _ = fmt.Fprintln(rt.Out, line)
		return nil
	}
	return rt.Printer().Emit(map[string]string{"preview": rt.Redact(line)})
}

func newConfigGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Hyperdrive configurations",
	}
	cmd.AddCommand(newConfigList(rt))
	cmd.AddCommand(newConfigGet(rt))
	cmd.AddCommand(newConfigCreate(rt))
	cmd.AddCommand(newConfigUpdate(rt))
	cmd.AddCommand(newConfigDelete(rt))
	return cmd
}

func newConfigList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List Hyperdrive configurations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListHyperdriveConfigs(cmd.Context(), ref.ID, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, []string{"ID", "NAME", "HOST", "DATABASE", "CONNECTION LIMIT"}, configRow)
		},
	}
}

func newConfigGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get CONFIG_ID",
		Short: "Show one Hyperdrive configuration",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetHyperdriveConfig(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"ID", "NAME", "HOST", "DATABASE", "CONNECTION LIMIT"}, configRow)
		},
	}
}

// configFlags are the shared create/update flags.
type configFlags struct {
	name    string
	origin  string
	caching string
	limit   int64
}

func addConfigFlags(cmd *cobra.Command, cf *configFlags) {
	cmd.Flags().StringVar(&cf.name, "name", "", "configuration name")
	cmd.Flags().StringVar(&cf.origin, "origin", "", "origin configuration JSON as @file only (carries credentials)")
	cmd.Flags().StringVar(&cf.caching, "caching", "", "caching options as a JSON object, inline or @file")
	cmd.Flags().Int64Var(&cf.limit, "origin-connection-limit", 0, "maximum origin connections")
}

// originFile reads --origin from a file only: the origin object carries
// credentials (password/connection string) which must not appear in process
// arguments.
func originFile(v string) (string, error) {
	if !strings.HasPrefix(v, "@") {
		return "", errors.Usage(
			"--origin accepts only the @file form (for example @origin.json); inline origin values are rejected because they carry credentials and process arguments are observable")
	}
	return cmdutilValueOrFile("origin", v)
}

func (cf *configFlags) write(cmd *cobra.Command, requireName bool) (cloudflare.HyperdriveWrite, error) {
	w := cloudflare.HyperdriveWrite{}
	if cmd.Flags().Changed("name") {
		if cf.name == "" {
			return w, errors.Usage("--name must not be empty")
		}
		w.Name = &cf.name
	} else if requireName {
		return w, errors.Usage("--name is required")
	}
	if cmd.Flags().Changed("origin") {
		text, err := originFile(cf.origin)
		if err != nil {
			return w, err
		}
		parsed, err := parseJSONObjectText("origin", text)
		if err != nil {
			return w, err
		}
		w.Origin = parsed
	} else if requireName {
		return w, errors.Usage("--origin is required (JSON object from @file)")
	}
	if cmd.Flags().Changed("caching") {
		parsed, err := cmdutilParseObjectOrArray("caching", cf.caching, true)
		if err != nil {
			return w, err
		}
		w.Caching = parsed
	}
	if cmd.Flags().Changed("origin-connection-limit") {
		v := cf.limit
		w.OriginConnectionLimit = &v
	}
	return w, nil
}

func newConfigCreate(rt *app.Runtime) *cobra.Command {
	var cf configFlags
	cmd := &cobra.Command{
		Use:   "create --name NAME --origin @origin.json",
		Short: "Create a Hyperdrive configuration",
		Long: "Create a Hyperdrive configuration.\n\n" +
			"Example:\n" +
			"  flareadm hyperdrive config create --name app-db --origin @origin.json \\\n" +
			"    --caching '{\"disabled\":false}' --origin-connection-limit 10\n\n" +
			"--origin is @file-only: it carries database credentials. Its contents are\n" +
			"never printed, logged or echoed in errors.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			w, err := cf.write(cmd, true)
			if err != nil {
				return err
			}
			rt.ProtectSecret(string(w.Origin))
			if rt.DryRunFlag {
				return previewLine(rt, "Would create Hyperdrive configuration "+*w.Name)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateHyperdriveConfig(cmd.Context(), ref.ID, w)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"ID", "NAME", "HOST", "DATABASE", "CONNECTION LIMIT"}, configRow)
		},
	}
	addConfigFlags(cmd, &cf)
	return cmd
}

func newConfigUpdate(rt *app.Runtime) *cobra.Command {
	var cf configFlags
	cmd := &cobra.Command{
		Use:   "update CONFIG_ID",
		Short: "Update a Hyperdrive configuration",
		Long: "Update a Hyperdrive configuration. Omitted fields keep their values.\n" +
			"--origin is @file-only and its contents are never printed or logged.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			w, err := cf.write(cmd, false)
			if err != nil {
				return err
			}
			if w.Name == nil && len(w.Origin) == 0 && len(w.Caching) == 0 && w.OriginConnectionLimit == nil {
				return errors.Usage("nothing to update; pass at least one of --name, --origin, --caching, --origin-connection-limit")
			}
			if len(w.Origin) > 0 {
				rt.ProtectSecret(string(w.Origin))
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would update Hyperdrive configuration "+args[0])
			}
			res, err := client.UpdateHyperdriveConfig(cmd.Context(), ref.ID, args[0], w)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"ID", "NAME", "HOST", "DATABASE", "CONNECTION LIMIT"}, configRow)
		},
	}
	addConfigFlags(cmd, &cf)
	return cmd
}

func newConfigDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete CONFIG_ID",
		Short: "Delete a Hyperdrive configuration",
		Long: "Delete a Hyperdrive configuration. Destructive: prompts for confirmation\n" +
			"unless --yes is given; --dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetHyperdriveConfig(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would delete Hyperdrive configuration "+existing.Item.Name)
			}
			if err := rt.Confirm("Delete Hyperdrive configuration " + existing.Item.Name + "?"); err != nil {
				return err
			}
			if err := client.DeleteHyperdriveConfig(cmd.Context(), ref.ID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted Hyperdrive configuration %s", args[0])
			return nil
		},
	}
	return cmd
}
