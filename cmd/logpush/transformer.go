package logpush

import (
	"encoding/json"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func transformerRow(t cloudflare.LogpushTransformer) []string {
	return []string{strconv.FormatInt(t.ID, 10), t.Name, t.Dataset, strconv.FormatInt(t.AssociatedJobs, 10), t.UpdatedAt}
}

func transformerHeaders() []string {
	return []string{"ID", "NAME", "DATASET", "JOBS", "UPDATED"}
}

func transformerID(arg string) (int64, error) {
	id, err := strconv.ParseInt(arg, 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.Usage("TRANSFORMER_ID must be a positive integer (got %q)", arg)
	}
	return id, nil
}

type transformerFlagValues struct {
	rt          *app.Runtime
	Name        string
	Code        string
	Description string
	Settings    string
}

func addTransformerFlags(rt *app.Runtime, cmd *cobra.Command, f *transformerFlagValues) {
	f.rt = rt
	cmd.Flags().StringVar(&f.Name, "name", "", "transformer name (required on create)")
	cmd.Flags().StringVar(&f.Code, "code", "", "transformer JavaScript code, inline or @file (required on create)")
	cmd.Flags().StringVar(&f.Description, "description", "", "transformer description")
	cmd.Flags().StringVar(&f.Settings, "settings", "", "additional transformer fields as a JSON object, inline or @file")
}

func (f *transformerFlagValues) overrides(cmd *cobra.Command) (map[string]any, error) {
	body := map[string]any{}
	changed := func(name string) bool { return cmd.Flags().Changed(name) }
	if changed("name") {
		body["name"] = f.Name
	}
	if changed("code") {
		code, err := cmdutil.ValueOrFile("code", f.Code)
		if err != nil {
			return nil, err
		}
		body["code"] = code
	}
	if changed("description") {
		body["description"] = f.Description
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

func newTransformerGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "transformer",
		Short: "Logpush field transformers",
		Long:  "Logpush field transformers (/accounts/{account_id}/logpush/transformers). Transformers are account-scoped.",
	}
	cmd.AddCommand(newTransformerList(rt))
	cmd.AddCommand(newTransformerGet(rt))
	cmd.AddCommand(newTransformerCreate(rt))
	cmd.AddCommand(newTransformerUpdate(rt))
	cmd.AddCommand(newTransformerDelete(rt))
	cmd.AddCommand(newTransformerContentGroup(rt))
	cmd.AddCommand(newTransformerVersionGroup(rt))
	return cmd
}

func newTransformerList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List transformers",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListLogpushTransformers(cmd.Context(), ref.ID, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, transformerHeaders(), transformerRow)
		},
	}
}

func newTransformerGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get TRANSFORMER_ID",
		Short: "Show one transformer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := transformerID(args[0])
			if err != nil {
				return err
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetLogpushTransformer(cmd.Context(), ref.ID, id)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, transformerHeaders(), transformerRow)
		},
	}
}

func newTransformerCreate(rt *app.Runtime) *cobra.Command {
	var f transformerFlagValues
	cmd := &cobra.Command{
		Use:   "create --name NAME --code @transform.js",
		Short: "Create a transformer",
		Long: "Create a field transformer.\n\n" +
			"Example:\n" +
			"  flareadm logpush transformer create --name redact --code @transform.js",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.Name == "" {
				return errors.Usage("--name is required")
			}
			if f.Code == "" {
				return errors.Usage("--code is required (JavaScript, inline or @file)")
			}
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would create Logpush transformer "+f.Name)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateLogpushTransformer(cmd.Context(), ref.ID, body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, transformerHeaders(), transformerRow)
		},
	}
	addTransformerFlags(rt, cmd, &f)
	return cmd
}

func newTransformerUpdate(rt *app.Runtime) *cobra.Command {
	var f transformerFlagValues
	cmd := &cobra.Command{
		Use:   "update TRANSFORMER_ID",
		Short: "Update a transformer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := transformerID(args[0])
			if err != nil {
				return err
			}
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if len(body) == 0 {
				return errors.Usage("nothing to update; pass at least one of --name, --code, --description, --settings")
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would update Logpush transformer "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateLogpushTransformer(cmd.Context(), ref.ID, id, body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, transformerHeaders(), transformerRow)
		},
	}
	addTransformerFlags(rt, cmd, &f)
	return cmd
}

func newTransformerDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete TRANSFORMER_ID",
		Short: "Delete a transformer",
		Long: "Delete a transformer. Destructive: prompts for confirmation unless --yes is\n" +
			"given; --dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := transformerID(args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would delete Logpush transformer "+args[0])
			}
			if err := rt.Confirm("Delete Logpush transformer " + args[0] + "?"); err != nil {
				return err
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			if err := client.DeleteLogpushTransformer(cmd.Context(), ref.ID, id); err != nil {
				return err
			}
			rt.Logger().Infof("deleted Logpush transformer %s", args[0])
			return nil
		},
	}
	return cmd
}

func newTransformerContentGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "content",
		Short: "Transformer code",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "get TRANSFORMER_ID",
		Short: "Download the transformer code",
		Long:  "Write the transformer's JavaScript to stdout. The code is written verbatim and is never logged.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := transformerID(args[0])
			if err != nil {
				return err
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			code, raw, err := client.GetLogpushTransformerContent(cmd.Context(), ref.ID, id)
			if err != nil {
				return err
			}
			if rt.Raw() {
				return rt.Printer().Raw(raw)
			}
			_, err = rt.Out.Write([]byte(code))
			return err
		},
	})
	return cmd
}

func newTransformerVersionGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Transformer versions",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "list TRANSFORMER_ID",
		Short: "List the versions of a transformer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := transformerID(args[0])
			if err != nil {
				return err
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListLogpushTransformerVersions(cmd.Context(), ref.ID, id, rt.Policy())
			if err != nil {
				return err
			}
			fromRaw := func(raw json.RawMessage) []string {
				return []string{cmdutil.CompactJSON(raw)}
			}
			return app.RenderList(rt, res, []string{"VERSION"}, fromRaw)
		},
	})
	return cmd
}
