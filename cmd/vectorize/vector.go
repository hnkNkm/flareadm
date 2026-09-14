package vectorize

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
)

// unparsableBehaviors are the accepted unparsable payload behaviors.
var unparsableBehaviors = []string{"error", "discard"}

// returnMetadataValues are the accepted metadata return modes.
var returnMetadataValues = []string{"none", "indexed", "all"}

func newVectorGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vector",
		Short: "Vector operations",
	}
	cmd.AddCommand(newVectorInsert(rt, "insert"))
	cmd.AddCommand(newVectorInsert(rt, "upsert"))
	cmd.AddCommand(newVectorQuery(rt))
	cmd.AddCommand(newVectorGet(rt))
	cmd.AddCommand(newVectorDelete(rt))
	cmd.AddCommand(newVectorList(rt))
	return cmd
}

func readFileArg(flag, v string) ([]byte, error) {
	if err := requireFile(flag, v); err != nil {
		return nil, err
	}
	text, err := cmdutil.ValueOrFile(flag, v)
	if err != nil {
		return nil, err
	}
	return []byte(text), nil
}

func mutationRow(m cloudflare.VectorizeMutation) []string { return []string{m.MutationID} }

func newVectorInsert(rt *app.Runtime, op string) *cobra.Command {
	var vectorsFlag, unparsableFlag string
	verb := "Insert"
	short := "Insert vectors"
	if op == "upsert" {
		verb = "Upsert"
		short = "Upsert vectors"
	}
	cmd := &cobra.Command{
		Use:   op + " INDEX_NAME --vectors @vectors.ndjson",
		Short: short,
		Long: verb + " vectors with an NDJSON payload (one vector per line).\n\n" +
			"  --vectors is @file-only; the payload is sent verbatim with content type\n" +
			"  application/x-ndjson and is never printed, logged or echoed in errors.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			payload, err := readFileArg("vectors", vectorsFlag)
			if err != nil {
				return err
			}
			if len(payload) == 0 {
				return errors.Usage("--vectors file is empty")
			}
			if unparsableFlag != "" && !contains(unparsableBehaviors, unparsableFlag) {
				return errors.Usage("invalid --unparsable-behavior %q (supported: error, discard)", unparsableFlag)
			}
			rt.ProtectSecret(string(payload))
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			params := cloudflare.VectorizeMutationParams{Payload: payload, UnparsableBehavior: unparsableFlag}
			var res *cloudflare.GetResult[cloudflare.VectorizeMutation]
			if op == "upsert" {
				res, err = client.UpsertVectors(cmd.Context(), ref.ID, args[0], params)
			} else {
				res, err = client.InsertVectors(cmd.Context(), ref.ID, args[0], params)
			}
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"MUTATION ID"}, mutationRow)
		},
	}
	cmd.Flags().StringVar(&vectorsFlag, "vectors", "", "NDJSON vector payload, @file only")
	cmd.Flags().StringVar(&unparsableFlag, "unparsable-behavior", "", "behavior for unparsable vectors (error, discard)")
	_ = cmd.RegisterFlagCompletionFunc("unparsable-behavior", cmdutil.EnumsOf(unparsableBehaviors))
	return cmd
}

func newVectorQuery(rt *app.Runtime) *cobra.Command {
	var vectorFlag, filterFlag, returnMetadataFlag string
	var topKFlag int64
	var returnValuesFlag bool
	cmd := &cobra.Command{
		Use:   "query INDEX_NAME --vector '[0.1, 0.2]'",
		Short: "Query similar vectors",
		Long: "Run a similarity query.\n\n" +
			"  --vector takes a JSON array of numbers, inline or @file; --filter takes a\n" +
			"  metadata filter object, inline or @file. Vector and filter payloads are\n" +
			"  never written to debug logs or error output.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vector, err := cmdutil.ParseJSONObjectOrArray("vector", vectorFlag)
			if err != nil {
				return errors.Usage("--vector must be a JSON array of numbers")
			}
			if strings.TrimSpace(string(vector))[0] != '[' {
				return errors.Usage("--vector must be a JSON array of numbers")
			}
			var numbers []float64
			if err := json.Unmarshal(vector, &numbers); err != nil {
				return errors.Usage("--vector must be a JSON array of numbers")
			}
			rt.ProtectSecret(string(vector))
			var filter json.RawMessage
			if cmd.Flags().Changed("filter") {
				filter, err = cmdutil.ParseJSONObject("filter", filterFlag)
				if err != nil {
					return err
				}
				rt.ProtectSecret(string(filter))
			}
			if returnMetadataFlag != "" && !contains(returnMetadataValues, returnMetadataFlag) {
				return errors.Usage("invalid --return-metadata %q (supported: none, indexed, all)", returnMetadataFlag)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.QueryVectors(cmd.Context(), ref.ID, args[0], cloudflare.VectorizeQueryParams{
				Vector: vector, TopK: topKFlag, ReturnValues: returnValuesFlag,
				ReturnMetadata: returnMetadataFlag, Filter: filter,
			})
			if err != nil {
				return err
			}
			if rt.Raw() {
				return rt.Printer().Raw(res.RawBody)
			}
			if rt.Format() != output.Table {
				return rt.Printer().Emit(res.Item)
			}
			rows := make([][]string, 0, len(res.Item.Matches))
			for _, m := range res.Item.Matches {
				rows = append(rows, []string{m.ID, strconv.FormatFloat(m.Score, 'f', 4, 64), m.Namespace})
			}
			return rt.Printer().PrintTable([]string{"ID", "SCORE", "NAMESPACE"}, rows)
		},
	}
	cmd.Flags().StringVar(&vectorFlag, "vector", "", "query vector as a JSON array, inline or @file (required)")
	cmd.Flags().Int64Var(&topKFlag, "top-k", 0, "number of nearest matches to return")
	cmd.Flags().BoolVar(&returnValuesFlag, "return-values", false, "include vector values in matches")
	cmd.Flags().StringVar(&returnMetadataFlag, "return-metadata", "", "metadata to return (none, indexed, all)")
	_ = cmd.RegisterFlagCompletionFunc("return-metadata", cmdutil.EnumsOf(returnMetadataValues))
	cmd.Flags().StringVar(&filterFlag, "filter", "", "metadata filter object, inline or @file")
	return cmd
}

func newVectorGet(rt *app.Runtime) *cobra.Command {
	var idFlags []string
	cmd := &cobra.Command{
		Use:   "get INDEX_NAME --id ID",
		Short: "Fetch vectors by id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetVectorsByIDs(cmd.Context(), ref.ID, args[0], idFlags)
			if err != nil {
				return err
			}
			return renderVectors(rt, res)
		},
	}
	cmd.Flags().StringArrayVar(&idFlags, "id", nil, "vector id (repeatable)")
	return cmd
}

func newVectorDelete(rt *app.Runtime) *cobra.Command {
	var idFlags []string
	cmd := &cobra.Command{
		Use:   "delete INDEX_NAME --id ID",
		Short: "Delete vectors by id",
		Long: "Delete vectors by id. Destructive: prompts for confirmation unless --yes\n" +
			"is given; --dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(idFlags) == 0 {
				return errors.Usage("pass at least one --id")
			}
			if rt.DryRunFlag {
				return previewLine(rt, fmt.Sprintf("Would delete %d vector(s) from %s", len(idFlags), args[0]))
			}
			if err := rt.Confirm(fmt.Sprintf("Delete %d vector(s) from index %s?", len(idFlags), args[0])); err != nil {
				return err
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.DeleteVectorsByIDs(cmd.Context(), ref.ID, args[0], idFlags)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"MUTATION ID"}, mutationRow)
		},
	}
	cmd.Flags().StringArrayVar(&idFlags, "id", nil, "vector id (repeatable)")
	return cmd
}

func newVectorList(rt *app.Runtime) *cobra.Command {
	var countFlag int64
	var cursorFlag string
	cmd := &cobra.Command{
		Use:   "list INDEX_NAME",
		Short: "List vector ids",
		Long: "List vector ids. The endpoint paginates with a cursor: pass --cursor from a\n" +
			"previous run (the next cursor is reported on stderr when truncated).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListVectors(cmd.Context(), ref.ID, args[0], countFlag, cursorFlag)
			if err != nil {
				return err
			}
			if res.Item.IsTruncated && res.Item.NextCursor != "" {
				_, _ = fmt.Fprintf(rt.Err, "next cursor: %s\n", res.Item.NextCursor)
			}
			return renderVectors(rt, res)
		},
	}
	cmd.Flags().Int64Var(&countFlag, "count", 0, "number of vectors to return")
	cmd.Flags().StringVar(&cursorFlag, "cursor", "", "pagination cursor from a previous run")
	return cmd
}

// renderVectors renders generic vector payloads: ID column in tables, full
// JSON in structured formats.
func renderVectors(rt *app.Runtime, res *cloudflare.GetResult[cloudflare.VectorizeVectorsResult]) error {
	if rt.Raw() {
		return rt.Printer().Raw(res.RawBody)
	}
	if rt.Format() != output.Table {
		return rt.Printer().Emit(res.Item)
	}
	rows := make([][]string, 0, len(res.Item.Vectors))
	for _, raw := range res.Item.Vectors {
		var m struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(raw, &m)
		rows = append(rows, []string{m.ID})
	}
	return rt.Printer().PrintTable([]string{"ID"}, rows)
}
