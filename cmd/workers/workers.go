// Package workers implements `flareadm workers ...`: remote administration of
// Cloudflare Workers scripts, routes, custom domains and account settings.
package workers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

// New builds the workers command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workers",
		Short: "Cloudflare Workers administration",
		Long:  "Cloudflare Workers administration (scripts, versions, deployments, routes, custom domains, secrets). Account scope is resolved through the standard account resolution; routes are zone-scoped.",
	}
	cmd.AddCommand(newScriptGroup(rt))
	cmd.AddCommand(newRouteGroup(rt))
	cmd.AddCommand(newDomainGroup(rt))
	cmd.AddCommand(newSubdomainGroup(rt))
	cmd.AddCommand(newAccountSettingsGroup(rt))
	return cmd
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// parseWorkerFiles turns repeated --file NAME=@PATH flags into upload parts. The
// part names are what the upload metadata references as main_module/body_part.
func parseWorkerFiles(values []string) ([]cloudflare.WorkerFile, error) {
	files := make([]cloudflare.WorkerFile, 0, len(values))
	for _, v := range values {
		name, path, ok := strings.Cut(v, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, errors.Usage("--file must have the form NAME=@path (got %q)", v)
		}
		path = strings.TrimSpace(path)
		if !strings.HasPrefix(path, "@") || path == "@" {
			return nil, errors.Usage("--file %s accepts only the @file form (for example %s=@module.js)", name, name)
		}
		content, err := os.ReadFile(path[1:])
		if err != nil {
			return nil, errors.Wrap(errors.CodeInvalid, fmt.Sprintf("reading module file %s", path[1:]), err)
		}
		files = append(files, cloudflare.WorkerFile{Name: name, Content: content})
	}
	return files, nil
}

// validateUploadMetadata checks that the metadata object references one of the
// uploaded parts, as the API requires.
func validateUploadMetadata(metadata []byte, files []cloudflare.WorkerFile) error {
	var meta struct {
		MainModule string `json:"main_module"`
		BodyPart   string `json:"body_part"`
	}
	if err := jsonUnmarshal(metadata, &meta); err != nil {
		return errors.Usage("--metadata must be a JSON object")
	}
	names := make([]string, 0, len(files))
	for _, f := range files {
		names = append(names, f.Name)
	}
	ref := meta.MainModule
	if ref == "" {
		ref = meta.BodyPart
	}
	switch {
	case ref == "":
		return errors.Usage("--metadata must reference an uploaded file as main_module or body_part")
	case !contains(names, ref):
		return errors.Usage("--metadata references %q but no --file with that name was given (uploaded: %s)", ref, strings.Join(names, ", "))
	}
	return nil
}

func jsonUnmarshal(data []byte, v any) error {
	var buf bytes.Buffer
	if err := json.Compact(&buf, data); err != nil {
		return err
	}
	return json.Unmarshal(buf.Bytes(), v)
}

// fileSummary describes an upload without exposing its contents.
func fileSummary(files []cloudflare.WorkerFile) string {
	total := 0
	for _, f := range files {
		total += len(f.Content)
	}
	return fmt.Sprintf("%d file(s), %d bytes", len(files), total)
}
