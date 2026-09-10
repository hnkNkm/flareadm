package workers

import (
	"strconv"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func versionRow(v cloudflare.WorkerVersion) []string {
	return []string{v.ID, strconv.FormatInt(v.Number, 10)}
}

func versionHeaders() []string {
	return []string{"ID", "NUMBER"}
}

func newScriptVersionGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Script versions",
		Long:  "Script versions (/accounts/{account_id}/workers/scripts/{script}/versions). Versions are immutable: a version can be created and read, then referenced by a deployment.",
	}
	cmd.AddCommand(newScriptVersionList(rt))
	cmd.AddCommand(newScriptVersionGet(rt))
	cmd.AddCommand(newScriptVersionCreate(rt))
	return cmd
}

func newScriptVersionList(rt *app.Runtime) *cobra.Command {
	var deployable bool
	cmd := &cobra.Command{
		Use:   "list SCRIPT",
		Short: "List a script's versions",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListWorkerVersions(cmd.Context(), ref.ID, args[0], deployable, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, versionHeaders(), versionRow)
		},
	}
	cmd.Flags().BoolVar(&deployable, "deployable", false, "only versions that can be deployed")
	return cmd
}

func newScriptVersionGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get SCRIPT VERSION_ID",
		Short: "Show one version",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetWorkerVersion(cmd.Context(), ref.ID, args[0], args[1])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, versionHeaders(), versionRow)
		},
	}
}

func newScriptVersionCreate(rt *app.Runtime) *cobra.Command {
	var metadataFlag, bindingsInherit string
	var fileFlags []string
	cmd := &cobra.Command{
		Use:   "create SCRIPT --metadata @metadata.json --file NAME=@module.js",
		Short: "Upload a new script version",
		Long: "Upload a new immutable version. The multipart body is the same as a script\n" +
			"upload: metadata plus one part per --file, referenced by metadata.main_module\n" +
			"(or body_part).\n\n" +
			"--metadata is @file-only because it carries bindings, including secret_text\n" +
			"values; module contents are never printed.",
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
				return cmdutil.PreviewLine(rt, "Would upload a new version of script "+args[0]+" ("+fileSummary(files)+")")
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateWorkerVersion(cmd.Context(), ref.ID, args[0], metadata, files, bindingsInherit)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, versionHeaders(), versionRow)
		},
	}
	cmd.Flags().StringVar(&metadataFlag, "metadata", "", "version metadata as @file only")
	cmd.Flags().StringArrayVar(&fileFlags, "file", nil, "module to upload as NAME=@PATH (repeatable)")
	cmd.Flags().StringVar(&bindingsInherit, "bindings-inherit", "", "set to strict to fail on unresolvable inherit bindings")
	return cmd
}
