package d1

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
)

const cellLimit = 48

// cell renders one result value for table output.
func cell(v any) string {
	if v == nil {
		return "null"
	}
	switch t := v.(type) {
	case string:
		return truncate(t, cellLimit)
	case bool:
		return fmt.Sprintf("%t", t)
	case float64:
		return formatFloat(t)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return truncate(string(b), cellLimit)
	}
}

func formatFloat(f float64) string {
	if f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%g", f)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// queryRequest parses the shared query flags.
func queryRequest(cmd *cobra.Command, sqlFlag, paramsFlag, batchFlag string) (cloudflare.D1QueryRequest, error) {
	req := cloudflare.D1QueryRequest{}
	if cmd.Flags().Changed("sql") {
		sql, err := cmdutil.ValueOrFile("sql", sqlFlag)
		if err != nil {
			return req, err
		}
		req.SQL = sql
	}
	if cmd.Flags().Changed("params") {
		params, err := cmdutil.ParseJSONObjectOrArray("params", paramsFlag)
		if err != nil {
			return req, err
		}
		req.Params = params
	}
	if cmd.Flags().Changed("batch") {
		batch, err := cmdutil.ParseJSONArray("batch", batchFlag)
		if err != nil {
			return req, err
		}
		req.Batch = batch
	}
	if req.SQL == "" && len(req.Batch) == 0 {
		return req, errors.Usage("--sql is required (or --batch @file)")
	}
	return req, nil
}

func addQueryFlags(cmd *cobra.Command, sqlFlag, paramsFlag, batchFlag *string) {
	cmd.Flags().StringVar(sqlFlag, "sql", "", "SQL statement, inline or @file (required unless --batch)")
	cmd.Flags().StringVar(paramsFlag, "params", "", "statement parameters as a JSON array or object, inline or @file")
	cmd.Flags().StringVar(batchFlag, "batch", "", "batch of statements as a JSON array, inline or @file")
}

// renderStatements renders object-shaped statement results: a row table for
// a single row-returning statement, otherwise a per-statement summary.
func renderStatements(rt *app.Runtime, res *cloudflare.GetResult[[]cloudflare.D1StatementResult]) error {
	if rt.Raw() {
		return rt.Printer().Raw(res.RawBody)
	}
	stmts := res.Item
	if rt.Format() != output.Table {
		return rt.Printer().Emit(stmts)
	}
	if len(stmts) == 1 && len(stmts[0].Results) > 0 {
		headers, rows := rowsTable(stmts[0].Results)
		if err := rt.Printer().PrintTable(headers, rows); err != nil {
			return err
		}
		summary := statementSummary(0, stmts[0])
		if summary != "" {
			_, _ = fmt.Fprintln(rt.Err, summary)
		}
		return nil
	}
	rows := make([][]string, 0, len(stmts))
	for i, s := range stmts {
		rows = append(rows, statementRow(i+1, s))
	}
	return rt.Printer().PrintTable([]string{"#", "SUCCESS", "ROWS", "CHANGES", "DURATION (MS)"}, rows)
}

// renderRawStatements renders positional (raw) statement results.
func renderRawStatements(rt *app.Runtime, res *cloudflare.GetResult[[]cloudflare.D1RawStatementResult]) error {
	if rt.Raw() {
		return rt.Printer().Raw(res.RawBody)
	}
	stmts := res.Item
	if rt.Format() != output.Table {
		return rt.Printer().Emit(stmts)
	}
	if len(stmts) == 1 && len(stmts[0].Results) > 0 {
		width := 0
		for _, row := range stmts[0].Results {
			if len(row) > width {
				width = len(row)
			}
		}
		headers := make([]string, width)
		for i := range headers {
			headers[i] = fmt.Sprintf("C%d", i+1)
		}
		rows := make([][]string, 0, len(stmts[0].Results))
		for _, row := range stmts[0].Results {
			cells := make([]string, width)
			for i := range cells {
				if i < len(row) {
					cells[i] = cell(row[i])
				}
			}
			rows = append(rows, cells)
		}
		return rt.Printer().PrintTable(headers, rows)
	}
	rows := make([][]string, 0, len(stmts))
	for i, s := range stmts {
		rows = append(rows, rawStatementRow(i+1, s))
	}
	return rt.Printer().PrintTable([]string{"#", "SUCCESS", "ROWS", "CHANGES", "DURATION (MS)"}, rows)
}

// rowsTable derives dynamic columns from the union of row keys.
func rowsTable(results []map[string]any) ([]string, [][]string) {
	keySet := map[string]bool{}
	for _, row := range results {
		for k := range row {
			keySet[k] = true
		}
	}
	headers := make([]string, 0, len(keySet))
	for k := range keySet {
		headers = append(headers, k)
	}
	sort.Strings(headers)
	rows := make([][]string, 0, len(results))
	for _, row := range results {
		cells := make([]string, len(headers))
		for i, h := range headers {
			cells[i] = cell(row[h])
		}
		rows = append(rows, cells)
	}
	return headers, rows
}

func statementRow(n int, s cloudflare.D1StatementResult) []string {
	return []string{fmt.Sprintf("%d", n), fmt.Sprintf("%t", s.Success), countRows(s), metaField(s.Meta, func(m *cloudflare.D1Meta) string { return formatFloat(m.Changes) }), metaField(s.Meta, func(m *cloudflare.D1Meta) string { return formatFloat(m.Duration) })}
}

func rawStatementRow(n int, s cloudflare.D1RawStatementResult) []string {
	return []string{fmt.Sprintf("%d", n), fmt.Sprintf("%t", s.Success), fmt.Sprintf("%d", len(s.Results)), metaField(s.Meta, func(m *cloudflare.D1Meta) string { return formatFloat(m.Changes) }), metaField(s.Meta, func(m *cloudflare.D1Meta) string { return formatFloat(m.Duration) })}
}

func countRows(s cloudflare.D1StatementResult) string { return fmt.Sprintf("%d", len(s.Results)) }

func metaField(m *cloudflare.D1Meta, pick func(*cloudflare.D1Meta) string) string {
	if m == nil {
		return ""
	}
	return pick(m)
}

func statementSummary(n int, s cloudflare.D1StatementResult) string {
	if s.Meta == nil {
		return ""
	}
	return fmt.Sprintf("rows: %d, rows read: %s, rows written: %s, duration: %sms",
		len(s.Results), formatFloat(s.Meta.RowsRead), formatFloat(s.Meta.RowsWritten), formatFloat(s.Meta.Duration))
}

func newDatabaseQuery(rt *app.Runtime) *cobra.Command {
	var sqlFlag, paramsFlag, batchFlag string
	cmd := &cobra.Command{
		Use:   "query DATABASE_ID",
		Short: "Run SQL against a D1 database",
		Long: "Run SQL and print the resulting rows.\n\n" +
			"Examples:\n" +
			"  flareadm d1 database query <id> --sql 'SELECT * FROM users LIMIT 5'\n" +
			"  flareadm d1 database query <id> --sql @schema.sql --params '[1, \"a\"]'\n\n" +
			"--params takes a JSON array (positional) or object (named); --batch takes a\n" +
			"JSON array of statement objects. Parameter payloads are never written to\n" +
			"debug logs or error output.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req, err := queryRequest(cmd, sqlFlag, paramsFlag, batchFlag)
			if err != nil {
				return err
			}
			protectQueryPayload(rt, req)
			if rt.DryRunFlag {
				return previewLine(rt, "Would execute SQL against D1 database "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.QueryD1(cmd.Context(), ref.ID, args[0], req)
			if err != nil {
				return err
			}
			return renderStatements(rt, res)
		},
	}
	addQueryFlags(cmd, &sqlFlag, &paramsFlag, &batchFlag)
	return cmd
}

func newDatabaseRaw(rt *app.Runtime) *cobra.Command {
	var sqlFlag, paramsFlag, batchFlag string
	cmd := &cobra.Command{
		Use:   "raw DATABASE_ID",
		Short: "Run SQL and return positional rows",
		Long: "Run SQL and print rows as positional values (no column names), matching\n" +
			"the D1 raw endpoint. Parameter payloads are never written to debug logs or\n" +
			"error output.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req, err := queryRequest(cmd, sqlFlag, paramsFlag, batchFlag)
			if err != nil {
				return err
			}
			protectQueryPayload(rt, req)
			if rt.DryRunFlag {
				return previewLine(rt, "Would execute raw SQL against D1 database "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.RawD1(cmd.Context(), ref.ID, args[0], req)
			if err != nil {
				return err
			}
			return renderRawStatements(rt, res)
		},
	}
	addQueryFlags(cmd, &sqlFlag, &paramsFlag, &batchFlag)
	return cmd
}

// protectQueryPayload registers parameters and batch payloads as secrets so
// they can never surface through diagnostics or API error messages.
func protectQueryPayload(rt *app.Runtime, req cloudflare.D1QueryRequest) {
	if len(req.Params) > 0 {
		rt.ProtectSecret(string(req.Params))
	}
	if len(req.Batch) > 0 {
		rt.ProtectSecret(string(req.Batch))
	}
}
