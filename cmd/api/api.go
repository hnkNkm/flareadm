// Package api implements `flareadm api request <METHOD> <PATH>` — the
// escape hatch for endpoints not yet modeled as first-class commands. It
// reuses authentication, profiles, retry handling, timeouts, logging and
// output handling (docs/architecture.md).
//
// Output contract for the response body:
//
//   - default: pretty-printed JSON when stdout is a terminal and the body
//     is JSON, verbatim bytes otherwise;
//   - --json / --output json: pretty-printed JSON when the body parses as
//     JSON, verbatim bytes otherwise;
//   - --output yaml: JSON body converted to YAML; a non-JSON body is a
//     usage error (exit 2);
//   - --raw / --output text: verbatim bytes.
//
// Non-JSON bodies are never reformatted or truncated.
package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
)

// methods are the supported request methods.
var methods = []string{"GET", "POST", "PUT", "PATCH", "DELETE"}

// New builds the api command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "api",
		Short: "Raw API access",
	}
	cmd.AddCommand(newRequest(rt))
	return cmd
}

func newRequest(rt *app.Runtime) *cobra.Command {
	var bodyFlag string
	cmd := &cobra.Command{
		Use:   "request METHOD PATH",
		Short: "Send an arbitrary Cloudflare API request",
		Long: "Send an arbitrary Cloudflare API request and print the response body.\n\n" +
			"Examples:\n" +
			"  flareadm api request GET /zones\n" +
			"  flareadm api request POST /zones/<zone-id>/purge_cache --body '{\"purge_everything\": true}'\n" +
			"  flareadm api request POST /zones/<zone-id>/dns_records --body @request.json",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			method := strings.ToUpper(args[0])
			if !contains(methods, method) {
				return errors.Usage("unsupported method %q (supported: %s)", args[0], strings.Join(methods, ", "))
			}
			path := args[1]
			if !strings.HasPrefix(path, "/") {
				return errors.Usage("path %q must start with '/' (for example /zones)", path)
			}

			body, err := readBody(bodyFlag)
			if err != nil {
				return err
			}
			contentType := ""
			if bodyFlag != "" && len(body) > 0 {
				contentType = cloudflare.RequestContentType(body)
			}

			client, err := rt.CloudClient()
			if err != nil {
				return err
			}
			resp, err := client.Request(cmd.Context(), method, path, body, contentType)
			if err != nil {
				return err
			}
			return renderResponse(rt, resp)
		},
	}
	cmd.Flags().StringVar(&bodyFlag, "body", "", "request body: inline text or @file to read from a file")
	return cmd
}

// renderResponse writes the raw API response body honoring the output
// flags. Raw bytes are written exactly as received (never reformatted);
// only JSON bodies are ever re-indented or converted.
func renderResponse(rt *app.Runtime, resp []byte) error {
	if rt.Raw() || rt.Format() == output.Text {
		return writeVerbatim(rt, resp)
	}
	switch rt.Format() {
	case output.JSON:
		if !json.Valid(resp) {
			return writeVerbatim(rt, resp)
		}
		return writePrettyJSON(rt, resp)
	case output.YAML:
		return writeYAML(rt, resp)
	default: // table: the default representation for api request
		if !rt.StdoutTTY() || !json.Valid(resp) {
			return writeVerbatim(rt, resp)
		}
		return writePrettyJSON(rt, resp)
	}
}

// writeVerbatim writes the exact response bytes.
func writeVerbatim(rt *app.Runtime, resp []byte) error {
	if len(resp) == 0 {
		return nil
	}
	_, err := rt.Out.Write(resp)
	return err
}

// writePrettyJSON re-indents a JSON body with two-space indentation and a
// trailing newline.
func writePrettyJSON(rt *app.Runtime, resp []byte) error {
	var out bytes.Buffer
	if err := json.Indent(&out, resp, "", "  "); err != nil {
		// json.Valid passed; Indent can only fail on the same syntax.
		return errors.Wrap(errors.CodeUnclassified, "pretty-printing JSON response", err)
	}
	out.WriteByte('\n')
	_, err := rt.Out.Write(out.Bytes())
	return err
}

// writeYAML converts a JSON body to YAML; non-JSON bodies are a usage
// error so machine consumers never receive silently mangled content.
func writeYAML(rt *app.Runtime, resp []byte) error {
	if !json.Valid(resp) {
		return errors.Usage("--output yaml requires a JSON response body (received non-JSON content)")
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(resp))
	if err := dec.Decode(&v); err != nil {
		return errors.Wrap(errors.CodeUnclassified, "decoding JSON response for yaml output", err)
	}
	out, err := yaml.Marshal(v)
	if err != nil {
		return errors.Wrap(errors.CodeUnclassified, "converting response to yaml", err)
	}
	_, err = rt.Out.Write(out)
	return err
}

// readBody resolves the --body flag: "@path" reads the file, anything else
// is used inline.
func readBody(flag string) ([]byte, error) {
	if flag == "" {
		return nil, nil
	}
	if !strings.HasPrefix(flag, "@") {
		return []byte(flag), nil
	}
	path := flag[1:]
	if path == "" {
		return nil, errors.Usage("--body @ requires a file path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(errors.CodeInvalid, fmt.Sprintf("reading body file %s", path), err)
	}
	return data, nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
