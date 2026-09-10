package logpush

import (
	"sort"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/output"
)

func newDatasetGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dataset",
		Short: "Logpush datasets",
		Long:  "Logpush dataset discovery. The API exposes no dataset listing endpoint, so datasets are addressed by name (for example http_requests).",
	}
	cmd.AddCommand(newDatasetFieldGroup(rt))
	cmd.AddCommand(newDatasetJobGroup(rt))
	return cmd
}

func newDatasetFieldGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "field",
		Short: "Fields of a Logpush dataset",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "list DATASET",
		Short: "List the fields of a dataset",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, accountID, zoneID, err := scope(cmd.Context(), rt)
			if err != nil {
				return err
			}
			fields, raw, err := client.ListLogpushDatasetFields(cmd.Context(), accountID, zoneID, args[0])
			if err != nil {
				return err
			}
			if rt.Raw() {
				return rt.Printer().Raw(raw)
			}
			if rt.Format() != output.Table {
				return rt.Printer().Emit(fields)
			}
			names := make([]string, 0, len(fields))
			for name := range fields {
				names = append(names, name)
			}
			sort.Strings(names)
			rows := make([][]string, 0, len(names))
			for _, name := range names {
				rows = append(rows, []string{name, fields[name]})
			}
			return rt.Printer().PrintTable([]string{"FIELD", "TYPE"}, rows)
		},
	})
	return cmd
}

func newDatasetJobGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "job",
		Short: "Jobs writing a Logpush dataset",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "list DATASET",
		Short: "List the jobs of a dataset",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, accountID, zoneID, err := scope(cmd.Context(), rt)
			if err != nil {
				return err
			}
			res, err := client.ListLogpushDatasetJobs(cmd.Context(), accountID, zoneID, args[0], rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, datasetJobHeaders(), datasetRow)
		},
	})
	return cmd
}
