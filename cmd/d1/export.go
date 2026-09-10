package d1

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func exportRow(e cloudflare.D1ExportResult) []string {
	name := e.Filename
	if name == "" {
		name = lastPathSegment(e.SignedURL)
	}
	return []string{e.Status, e.AtBookmark, name}
}

func lastPathSegment(u string) string {
	u = strings.TrimSuffix(u, "/")
	if i := strings.LastIndex(u, "/"); i >= 0 {
		return u[i+1:]
	}
	return u
}

func newDatabaseExport(rt *app.Runtime) *cobra.Command {
	var outputFormat, bookmarkFlag, dumpOptionsFlag, downloadFlag string
	cmd := &cobra.Command{
		Use:   "export DATABASE_ID",
		Short: "Export a D1 database",
		Long: "Start a D1 export and print the download location.\n\n" +
			"Examples:\n" +
			"  flareadm d1 database export <id>\n" +
			"  flareadm d1 database export <id> --download dump.sql\n\n" +
			"The API currently accepts only --output-format polling; the response\n" +
			"carries a signed URL for the dump. --download fetches that URL and writes\n" +
			"the dump to a file created with owner-only permissions.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format := outputFormat
			if format == "" {
				format = "polling"
			}
			if format != "polling" {
				return errors.Usage("invalid --output-format %q (supported: polling)", outputFormat)
			}
			var dumpOptions []byte
			if cmd.Flags().Changed("dump-options") {
				parsed, err := cmdutil.ParseJSONObject("dump-options", dumpOptionsFlag)
				if err != nil {
					return err
				}
				dumpOptions = parsed
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ExportD1(cmd.Context(), ref.ID, args[0], cloudflare.D1ExportParams{
				OutputFormat: format, CurrentBookmark: bookmarkFlag, DumpOptions: dumpOptions,
			})
			if err != nil {
				return err
			}
			if downloadFlag != "" {
				if res.Item.SignedURL == "" {
					return errors.New(errors.CodeUnclassified, "export did not return a download URL")
				}
				if err := downloadFile(cmd.Context(), res.Item.SignedURL, downloadFlag); err != nil {
					return err
				}
				_, _ = fmt.Fprintf(rt.Err, "export: downloaded dump to %s\n", downloadFlag)
			}
			if rt.Raw() {
				return rt.Printer().Raw(res.RawBody)
			}
			return app.RenderGet(rt, res, []string{"STATUS", "AT BOOKMARK", "FILE"}, exportRow)
		},
	}
	cmd.Flags().StringVar(&outputFormat, "output-format", "polling", "export format (polling)")
	cmd.Flags().StringVar(&bookmarkFlag, "bookmark", "", "export at this time-travel bookmark")
	cmd.Flags().StringVar(&dumpOptionsFlag, "dump-options", "", "dump options as a JSON object, inline or @file")
	cmd.Flags().StringVar(&downloadFlag, "download", "", "download the dump to this local path")
	return cmd
}

// downloadFile fetches a signed export URL without Cloudflare credentials.
func downloadFile(ctx context.Context, url, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return errors.Wrap(errors.CodeInvalid, "invalid export URL", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.FromTransport(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return errors.FromAPIFailure(resp.StatusCode, 0, "export download failed", http.MethodGet, "export_url")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.Wrap(errors.CodeInvalid, "creating download file "+path, err)
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		return errors.Wrap(errors.CodeUnclassified, "writing download file "+path, err)
	}
	return f.Close()
}
