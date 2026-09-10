// Package logs implements `flareadm logs ...`: the Log Explorer SQL query API.
package logs

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
)

// New builds the logs command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Cloudflare log queries",
		Long:  "Log Explorer SQL queries (/accounts/{account_id}/logs/explorer/query/sql, or the zone-scoped path with --zone). The SQL text is the request body. Raw log retrieval (logpull) is not implemented.",
	}
	cmd.AddCommand(newQuery(rt))
	return cmd
}

func newQuery(rt *app.Runtime) *cobra.Command {
	var sqlFlag string
	cmd := &cobra.Command{
		Use:   "query --sql @query.sql",
		Short: "Run a Log Explorer SQL query",
		Long: "Run a Log Explorer SQL query.\n\n" +
			"Example:\n" +
			"  flareadm logs query --sql 'SELECT count(*) FROM http_requests' --zone example.com\n\n" +
			"The SQL text is sent as the request body (text/plain); rows are returned as\n" +
			"they come from the API.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("sql") {
				return errors.Usage("--sql is required (SQL text, inline or @file)")
			}
			sql, err := cmdutil.ValueOrFile("sql", sqlFlag)
			if err != nil {
				return err
			}
			if sql == "" {
				return errors.Usage("--sql must not be empty")
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would run a Log Explorer SQL query")
			}
			client, accountID, zoneID, err := scope(cmd.Context(), rt)
			if err != nil {
				return err
			}
			res, err := client.LogsExplorerSQL(cmd.Context(), accountID, zoneID, sql)
			if err != nil {
				return err
			}
			if rt.Raw() {
				return rt.Printer().Raw(res.RawBody)
			}
			if rt.Format() != output.Table {
				return rt.Printer().Emit(res.Items)
			}
			rows := make([][]string, 0, len(res.Items))
			for _, item := range res.Items {
				rows = append(rows, []string{cmdutil.CompactJSON(item)})
			}
			return rt.Printer().PrintTable([]string{"ROW"}, rows)
		},
	}
	cmd.Flags().StringVar(&sqlFlag, "sql", "", "SQL query text, inline or @file")
	return cmd
}
