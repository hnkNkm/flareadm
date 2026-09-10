// Package analytics implements `flareadm analytics ...`: the REST analytics
// query API (summary, timeseries, top-n).
package analytics

import (
	"encoding/json"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
)

// New builds the analytics command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "analytics",
		Short: "Cloudflare analytics queries",
		Long: "REST analytics queries (/accounts/{account_id}/analytics/query/{dataset}/...).\n\n" +
			"This is the Analytics Query REST API only: the GraphQL analytics datasets are\n" +
			"not reachable from this CLI. The query object is sent verbatim, so the\n" +
			"documented fields (filters, from, groupBy, stats, to, and n/orderBy for top-n)\n" +
			"are passed through unchanged.",
	}
	cmd.AddCommand(newKindGroup(rt, "summary", "Summary values over a single interval", cloudflare.AnalyticsSummary, false))
	cmd.AddCommand(newKindGroup(rt, "timeseries", "Time series over the query range", cloudflare.AnalyticsTimeseries, true))
	cmd.AddCommand(newKindGroup(rt, "top-n", "Top N groups", cloudflare.AnalyticsTopN, false))
	return cmd
}

func newKindGroup(rt *app.Runtime, name, short string, kind cloudflare.AnalyticsQueryKind, withResolution bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:   name,
		Short: short,
	}
	var queryFlag, resolution string
	get := &cobra.Command{
		Use:   "get DATASET",
		Short: short,
		Long: "Run the query for DATASET.\n\n" +
			"Examples:\n" +
			"  flareadm analytics " + name + " get httpRequestsOverviewAdaptiveGroups --query @query.json\n\n" +
			"--query takes the query object (filters, from, groupBy, stats, to) verbatim.\n" +
			"Results are dataset-shaped and are emitted as returned by the API.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("query") {
				return errors.Usage("--query is required (JSON object)")
			}
			query, err := cmdutil.ParseSecretCarryingObject(rt, "query", queryFlag)
			if err != nil {
				return err
			}
			decoded := map[string]any{}
			if err := json.Unmarshal(query, &decoded); err != nil {
				return errors.Usage("--query must be a JSON object")
			}
			if withResolution && decrypted(cmd, "resolution") {
				decoded["resolution"] = resolution
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would run a "+name+" analytics query on dataset "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, _, err := client.AnalyticsQuery(cmd.Context(), ref.ID, args[0], kind, decoded)
			if err != nil {
				return err
			}
			if rt.Raw() {
				return rt.Printer().Raw(res.RawBody)
			}
			if rt.Format() != output.Table {
				return rt.Printer().Emit(res.Item)
			}
			return rt.Printer().PrintTable([]string{"RESULT"}, [][]string{{cmdutil.CompactJSON(res.Item)}})
		},
	}
	get.Flags().StringVar(&queryFlag, "query", "", "query object as JSON, inline or @file (required)")
	if withResolution {
		get.Flags().StringVar(&resolution, "resolution", "", "timeseries resolution (for example 1m, 1h, 1d)")
	}
	cmd.AddCommand(get)
	return cmd
}

func decrypted(cmd *cobra.Command, name string) bool { return cmd.Flags().Changed(name) }
