package vectorize

import (
	"strconv"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func indexRow(idx cloudflare.VectorizeIndex) []string {
	dimensions, metric := "", ""
	if idx.Config != nil {
		dimensions = strconv.FormatInt(idx.Config.Dimensions, 10)
		metric = idx.Config.Metric
	}
	return []string{idx.Name, dimensions, metric, idx.Description}
}

func indexHeaders() []string { return []string{"NAME", "DIMENSIONS", "METRIC", "DESCRIPTION"} }

func newIndexGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "index",
		Short: "Vectorize indexes",
	}
	cmd.AddCommand(newIndexList(rt))
	cmd.AddCommand(newIndexGet(rt))
	cmd.AddCommand(newIndexCreate(rt))
	cmd.AddCommand(newIndexDelete(rt))
	cmd.AddCommand(newIndexInfo(rt))
	cmd.AddCommand(newMetadataGroup(rt))
	return cmd
}

func newIndexList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List Vectorize indexes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListVectorizeIndexes(cmd.Context(), ref.ID)
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, indexHeaders(), indexRow)
		},
	}
}

func newIndexGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get INDEX_NAME",
		Short: "Show one Vectorize index",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetVectorizeIndex(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, indexHeaders(), indexRow)
		},
	}
}

func newIndexCreate(rt *app.Runtime) *cobra.Command {
	var nameFlag, descriptionFlag, metricFlag, presetFlag string
	var dimensionsFlag int64
	cmd := &cobra.Command{
		Use:   "create --name NAME (--dimensions N --metric METRIC | --preset PRESET)",
		Short: "Create a Vectorize index",
		Long: "Create a Vectorize index.\n\n" +
			"Examples:\n" +
			"  flareadm vectorize index create --name docs --dimensions 768 --metric cosine\n" +
			"  flareadm vectorize index create --name docs --preset @preset.json\n\n" +
			"Use either --dimensions with --metric (cosine, euclidean, dot-product) or a\n" +
			"single --preset.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if nameFlag == "" {
				return errors.Usage("--name is required")
			}
			if metricFlag != "" && !contains(metricValues, metricFlag) {
				return errors.Usage("invalid --metric %q (supported: cosine, euclidean, dot-product)", metricFlag)
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would create Vectorize index "+nameFlag)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateVectorizeIndex(cmd.Context(), ref.ID, cloudflare.VectorizeIndexWrite{
				Name: nameFlag, Description: descriptionFlag,
				Dimensions: dimensionsFlag, Metric: metricFlag, Preset: presetFlag,
			})
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, indexHeaders(), indexRow)
		},
	}
	cmd.Flags().StringVar(&nameFlag, "name", "", "index name (required)")
	cmd.Flags().Int64Var(&dimensionsFlag, "dimensions", 0, "vector dimensions")
	cmd.Flags().StringVar(&metricFlag, "metric", "", "distance metric (cosine, euclidean, dot-product)")
	cmd.Flags().StringVar(&presetFlag, "preset", "", "index preset name")
	cmd.Flags().StringVar(&descriptionFlag, "description", "", "index description")
	return cmd
}

func newIndexDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete INDEX_NAME",
		Short: "Delete a Vectorize index",
		Long: "Delete a Vectorize index and all of its vectors. Destructive: prompts for\n" +
			"confirmation unless --yes is given; --dry-run previews the deletion.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetVectorizeIndex(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would delete Vectorize index "+existing.Item.Name)
			}
			if err := rt.Confirm("Delete Vectorize index " + existing.Item.Name + "?"); err != nil {
				return err
			}
			if err := client.DeleteVectorizeIndex(cmd.Context(), ref.ID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted Vectorize index %s", args[0])
			return nil
		},
	}
	return cmd
}

func newIndexInfo(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "info INDEX_NAME",
		Short: "Show index statistics",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.VectorizeIndexInfo(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			row := func(i cloudflare.VectorizeInfo) []string {
				return []string{strconv.FormatInt(i.VectorCount, 10), strconv.FormatInt(i.Dimensions, 10), i.ProcessedUpToMutation}
			}
			return app.RenderGet(rt, res, []string{"VECTORS", "DIMENSIONS", "PROCESSED UP TO"}, row)
		},
	}
}
