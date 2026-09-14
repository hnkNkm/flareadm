package d1

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func importRow(i cloudflare.D1ImportResult) []string {
	return []string{i.Status, i.Filename, i.FinalBookmark, formatFloat(i.NumQueries)}
}

func newDatabaseImport(rt *app.Runtime) *cobra.Command {
	var actionFlag, filenameFlag, etagFlag, bookmarkFlag, fileFlag string
	var waitFlag bool
	cmd := &cobra.Command{
		Use:   "import DATABASE_ID",
		Short: "Import into a D1 database",
		Long: "Import SQL into a D1 database.\n\n" +
			"Examples:\n" +
			"  flareadm d1 database import <id> --file @local.sql\n" +
			"  flareadm d1 database import <id> --file @local.sql --wait\n" +
			"  flareadm d1 database import <id> --action init --filename local.sql\n\n" +
			"--file runs the whole protocol (init, upload, ingest) and reports every\n" +
			"step on stderr. --action exposes single protocol steps. If --wait is given\n" +
			"and the ingest succeeded but polling does not finish, the command exits 9\n" +
			"and reports the final bookmark. File bytes are never written to debug logs\n" +
			"or error output.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hasFile := cmd.Flags().Changed("file")
			hasAction := cmd.Flags().Changed("action")
			if hasFile == hasAction {
				return errors.Usage("pass exactly one of --file @local.sql (full protocol) or --action init|ingest|poll (single step)")
			}
			if waitFlag && !hasFile {
				return errors.Usage("--wait requires --file")
			}
			if rt.DryRunFlag {
				if hasFile {
					return previewLine(rt, "Would import "+fileFlag+" into D1 database "+args[0])
				}
				return previewLine(rt, "Would run the D1 import step "+actionFlag+" on database "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			if hasFile {
				return runImportFile(cmd, rt, client, ref.ID, args[0], fileFlag, waitFlag)
			}
			res, err := client.ImportD1Step(cmd.Context(), ref.ID, args[0], cloudflare.D1ImportStepParams{
				Action: actionFlag, Filename: filenameFlag, Etag: etagFlag, CurrentBookmark: bookmarkFlag,
			})
			if err != nil {
				return err
			}
			if rt.Raw() {
				return rt.Printer().Raw(res.RawBody)
			}
			return app.RenderGet(rt, res, []string{"STATUS", "FILENAME", "FINAL BOOKMARK", "QUERIES"}, importRow)
		},
	}
	cmd.Flags().StringVar(&fileFlag, "file", "", "SQL file to import (@path or path)")
	cmd.Flags().StringVar(&actionFlag, "action", "", "single import step (init, ingest, poll)")
	_ = cmd.RegisterFlagCompletionFunc("action", cmdutil.EnumsOf(cloudflare.D1ImportActions))
	cmd.Flags().StringVar(&filenameFlag, "filename", "", "filename reported to the API (defaults to the --file basename)")
	cmd.Flags().StringVar(&etagFlag, "etag", "", "upload etag (ingest step)")
	cmd.Flags().StringVar(&bookmarkFlag, "bookmark", "", "current bookmark for the step")
	cmd.Flags().BoolVar(&waitFlag, "wait", false, "poll until the import completes")
	return cmd
}

// readImportFile resolves --file (plain path or @path).
func readImportFile(v string) (string, []byte, error) {
	path := strings.TrimPrefix(v, "@")
	if path == "" {
		return "", nil, errors.Usage("--file requires a path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, errors.Wrap(errors.CodeInvalid, "reading import file "+path, err)
	}
	if len(data) == 0 {
		return "", nil, errors.Usage("import file %s is empty", path)
	}
	return filepath.Base(path), data, nil
}

// runImportFile performs init -> upload -> ingest [-> poll].
func runImportFile(cmd *cobra.Command, rt *app.Runtime, client *cloudflare.Client, accountID, databaseID, fileArg string, wait bool) error {
	filename, data, err := readImportFile(fileArg)
	if err != nil {
		return err
	}
	rt.ProtectSecret(string(data))

	initRes, err := client.ImportD1Step(cmd.Context(), accountID, databaseID, cloudflare.D1ImportStepParams{
		Action: "init", Filename: filename,
	})
	if err != nil {
		return err
	}
	if initRes.Item.UploadURL == "" {
		return errors.New(errors.CodeUnclassified, "import init did not return an upload URL")
	}
	_, _ = fmt.Fprintf(rt.Err, "import: init ok (filename %s)\n", filename)

	etag, err := cloudflare.UploadD1File(cmd.Context(), initRes.Item.UploadURL, data)
	if err != nil {
		return errors.Wrap(errors.CodeUnclassified, "import: upload failed", err)
	}
	_, _ = fmt.Fprintf(rt.Err, "import: uploaded %d bytes (etag %s)\n", len(data), etag)

	ingestParams := cloudflare.D1ImportStepParams{Action: "ingest", Filename: filename}
	if etag != "" {
		ingestParams.Etag = etag
	}
	ingestRes, err := client.ImportD1Step(cmd.Context(), accountID, databaseID, ingestParams)
	if err != nil {
		return err
	}
	final := ingestRes.Item.FinalBookmark
	_, _ = fmt.Fprintf(rt.Err, "import: ingest ok (final bookmark %s)\n", final)

	if !wait {
		if rt.Raw() {
			return rt.Printer().Raw(ingestRes.RawBody)
		}
		return app.RenderGet(rt, ingestRes, []string{"STATUS", "FILENAME", "FINAL BOOKMARK", "QUERIES"}, importRow)
	}

	pollRes, pollErr := pollImport(cmd, client, accountID, databaseID, filename, final)
	if pollErr != nil {
		if final == "" {
			final = "(unknown)"
		}
		return errors.Wrap(errors.CodePartial,
			fmt.Sprintf("import: ingest succeeded (final bookmark %s) but the wait/poll step did not complete", final), pollErr)
	}
	_, _ = fmt.Fprintf(rt.Err, "import: complete (final bookmark %s)\n", pollRes.Item.FinalBookmark)
	if rt.Raw() {
		return rt.Printer().Raw(pollRes.RawBody)
	}
	return app.RenderGet(rt, pollRes, []string{"STATUS", "FILENAME", "FINAL BOOKMARK", "QUERIES"}, importRow)
}

// pollImport polls the import status until it completes or the attempt
// budget is exhausted.
func pollImport(cmd *cobra.Command, client *cloudflare.Client, accountID, databaseID, filename, bookmark string) (*cloudflare.GetResult[cloudflare.D1ImportResult], error) {
	const maxAttempts = 100
	interval := 3 * time.Second
	var last *cloudflare.GetResult[cloudflare.D1ImportResult]
	for attempt := 0; attempt < maxAttempts; attempt++ {
		res, err := client.ImportD1Step(cmd.Context(), accountID, databaseID, cloudflare.D1ImportStepParams{
			Action: "poll", Filename: filename, CurrentBookmark: bookmark,
		})
		if err != nil {
			return last, err
		}
		last = res
		if res.Item.Error != "" {
			return res, errors.New(errors.CodeUnclassified, "import reported an error: %s", res.Item.Error)
		}
		if importComplete(res.Item.Status) {
			return res, nil
		}
		select {
		case <-cmd.Context().Done():
			return res, cmd.Context().Err()
		case <-time.After(interval):
		}
	}
	return last, errors.New(errors.CodeUnclassified, "import did not complete after %d poll attempts", maxAttempts)
}

func importComplete(status string) bool {
	switch strings.ToLower(status) {
	case "complete", "completed", "success", "succeeded", "done", "finished":
		return true
	}
	return false
}
