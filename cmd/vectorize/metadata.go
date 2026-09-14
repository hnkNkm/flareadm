package vectorize

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func metadataRow(m cloudflare.VectorizeMetadataIndex) []string {
	return []string{m.PropertyName, m.IndexType}
}

func newMetadataGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "metadata",
		Short: "Vectorize metadata indexes",
	}
	cmd.AddCommand(newMetadataList(rt))
	cmd.AddCommand(newMetadataCreate(rt))
	cmd.AddCommand(newMetadataDelete(rt))
	return cmd
}

func newMetadataList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list INDEX_NAME",
		Short: "List metadata indexes",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListVectorizeMetadataIndexes(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, []string{"PROPERTY", "TYPE"}, metadataRow)
		},
	}
}

func newMetadataCreate(rt *app.Runtime) *cobra.Command {
	var propertyFlag, typeFlag string
	cmd := &cobra.Command{
		Use:   "create INDEX_NAME --property NAME --type string|number|boolean",
		Short: "Create a metadata index",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if propertyFlag == "" {
				return errors.Usage("--property is required")
			}
			if !contains(metadataIndexTypes, typeFlag) {
				return errors.Usage("invalid --type %q (supported: %s)", typeFlag, strings.Join(metadataIndexTypes, ", "))
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would create metadata index "+propertyFlag+" on Vectorize index "+args[0])
			}
			res, err := client.CreateVectorizeMetadataIndex(cmd.Context(), ref.ID, args[0], propertyFlag, typeFlag)
			if err != nil {
				return err
			}
			row := func(m cloudflare.VectorizeMutation) []string { return []string{m.MutationID} }
			return app.RenderGet(rt, res, []string{"MUTATION ID"}, row)
		},
	}
	cmd.Flags().StringVar(&propertyFlag, "property", "", "metadata property name (required)")
	cmd.Flags().StringVar(&typeFlag, "type", "", "metadata index type (string, number, boolean)")
	_ = cmd.RegisterFlagCompletionFunc("type", cmdutil.EnumsOf(metadataIndexTypes))
	return cmd
}

func newMetadataDelete(rt *app.Runtime) *cobra.Command {
	var propertyFlag string
	cmd := &cobra.Command{
		Use:   "delete INDEX_NAME --property NAME",
		Short: "Delete a metadata index",
		Long: "Delete a metadata index. Destructive: prompts for confirmation unless\n" +
			"--yes is given; --dry-run previews the deletion.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if propertyFlag == "" {
				return errors.Usage("--property is required")
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would delete metadata index "+propertyFlag+" on "+args[0])
			}
			if err := rt.Confirm("Delete metadata index " + propertyFlag + " on " + args[0] + "?"); err != nil {
				return err
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.DeleteVectorizeMetadataIndex(cmd.Context(), ref.ID, args[0], propertyFlag)
			if err != nil {
				return err
			}
			row := func(m cloudflare.VectorizeMutation) []string { return []string{m.MutationID} }
			return app.RenderGet(rt, res, []string{"MUTATION ID"}, row)
		},
	}
	cmd.Flags().StringVar(&propertyFlag, "property", "", "metadata property name (required)")
	return cmd
}
