package workers

import (
	"strconv"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func scriptRow(s cloudflare.WorkerScript) []string {
	return []string{s.ID, dateOnly(s.ModifiedOn), s.CompatibilityDate, s.UsageModel, strconv.FormatBool(s.HasModules), joinList(s.Tags)}
}

func scriptHeaders() []string {
	return []string{"ID", "MODIFIED", "COMPAT DATE", "USAGE MODEL", "MODULES", "TAGS"}
}

func dateOnly(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
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

func newScriptGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "script",
		Short: "Workers scripts",
		Long:  "Workers scripts (/accounts/{account_id}/workers/scripts). Uploading a script creates it when it does not exist yet.",
	}
	cmd.AddCommand(newScriptList(rt))
	cmd.AddCommand(newScriptUpdate(rt))
	cmd.AddCommand(newScriptDelete(rt))
	cmd.AddCommand(newScriptContentGroup(rt))
	cmd.AddCommand(newScriptSettingsGroup(rt))
	cmd.AddCommand(newScriptSecretGroup(rt))
	cmd.AddCommand(newScriptVersionGroup(rt))
	cmd.AddCommand(newScriptDeploymentGroup(rt))
	cmd.AddCommand(newScriptScheduleGroup(rt))
	cmd.AddCommand(newScriptSubdomainGroup(rt))
	return cmd
}

func newScriptList(rt *app.Runtime) *cobra.Command {
	var tags string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List Workers scripts",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListWorkerScripts(cmd.Context(), ref.ID, tags, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, scriptHeaders(), scriptRow)
		},
	}
	cmd.Flags().StringVar(&tags, "tags", "", "only scripts tagged with this value")
	return cmd
}

func newScriptUpdate(rt *app.Runtime) *cobra.Command {
	var metadataFlag, bindingsInherit string
	var fileFlags []string
	cmd := &cobra.Command{
		Use:   "update SCRIPT --metadata @metadata.json --file NAME=@module.js",
		Short: "Upload a Workers script (create or replace)",
		Long: "Upload a script. The upload is a multipart body: the metadata object plus one\n" +
			"part per --file, whose names are what metadata.main_module (or body_part for\n" +
			"service-worker syntax) references. The script is created when it does not\n" +
			"exist yet.\n\n" +
			"Example:\n" +
			"  flareadm workers script update hello --file main=@hello.js \\\n" +
			"    --metadata @metadata.json\n\n" +
			"--metadata is @file-only because it carries bindings, including secret_text\n" +
			"values; those values are registered as protected secrets and never appear in\n" +
			"diagnostics, error text or --dry-run previews. Module contents are never\n" +
			"printed either; previews only report the file count and size.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("metadata") {
				return errors.Usage("--metadata is required (JSON object, @file only)")
			}
			metadataText, err := cmdutil.FileOnly("metadata", metadataFlag)
			if err != nil {
				return err
			}
			metadata, err := cmdutil.ParseSecretCarryingObject(rt, "metadata", metadataText)
			if err != nil {
				return err
			}
			files, err := parseWorkerFiles(fileFlags)
			if err != nil {
				return err
			}
			if len(files) == 0 {
				return errors.Usage("at least one --file NAME=@PATH is required")
			}
			if err := validateUploadMetadata(metadata, files); err != nil {
				return err
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would upload script "+args[0]+" ("+fileSummary(files)+")")
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateWorkerScript(cmd.Context(), ref.ID, args[0], metadata, files, bindingsInherit)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, scriptHeaders(), scriptRow)
		},
	}
	cmd.Flags().StringVar(&metadataFlag, "metadata", "", "upload metadata as @file only (bindings, compatibility date, main_module, ...)")
	cmd.Flags().StringArrayVar(&fileFlags, "file", nil, "module to upload as NAME=@PATH (repeatable)")
	cmd.Flags().StringVar(&bindingsInherit, "bindings-inherit", "", "set to strict to fail on unresolvable inherit bindings")
	return cmd
}

func newScriptDelete(rt *app.Runtime) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "delete SCRIPT",
		Short: "Delete a Workers script",
		Long: "Delete a script and its resources. Destructive: prompts for confirmation\n" +
			"unless --yes is given; --dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would delete script "+args[0])
			}
			if err := rt.Confirm("Delete Workers script " + args[0] + "?"); err != nil {
				return err
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			if err := client.DeleteWorkerScript(cmd.Context(), ref.ID, args[0], force); err != nil {
				return err
			}
			rt.Logger().Infof("deleted script %s", args[0])
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "delete even when the script has dependent resources")
	return cmd
}

func newScriptContentGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "content",
		Short: "Deployed script content",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "get SCRIPT",
		Short: "Download the deployed script content",
		Long: "Write the deployed script content to stdout. The body is written verbatim (no\n" +
			"JSON envelope) and is never logged, even with --debug.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			content, err := client.GetWorkerScriptContent(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if _, err := rt.Out.Write(content); err != nil {
				return err
			}
			return nil
		},
	})
	return cmd
}
