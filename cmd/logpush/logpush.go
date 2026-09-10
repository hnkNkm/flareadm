// Package logpush implements `flareadm logpush ...`: Logpush jobs, dataset
// discovery and field transformers.
package logpush

import (
	"context"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

// New builds the logpush command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logpush",
		Short: "Cloudflare Logpush administration",
		Long:  "Cloudflare Logpush administration (jobs, datasets, field transformers). Jobs are account-scoped by default; passing --zone switches them to zone scope.",
	}
	cmd.AddCommand(newJobGroup(rt))
	cmd.AddCommand(newDatasetGroup(rt))
	cmd.AddCommand(newTransformerGroup(rt))
	return cmd
}

// scope resolves the account-or-zone scope: an explicit --zone selects zone
// scope, otherwise account scope is used.
func scope(ctx context.Context, rt *app.Runtime) (*cloudflare.Client, string, string, error) {
	if rt.ZoneFlag != "" {
		client, zoneID, err := rt.ResolveZone(ctx)
		if err != nil {
			return nil, "", "", err
		}
		return client, "", zoneID, nil
	}
	client, ref, err := rt.ResolveAccount(ctx)
	if err != nil {
		return nil, "", "", err
	}
	return client, ref.ID, "", nil
}

func jobID(arg string) (int64, error) {
	id, err := strconv.ParseInt(arg, 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.Usage("JOB_ID must be a positive integer (got %q)", arg)
	}
	return id, nil
}

func jobRow(j cloudflare.LogpushJob) []string {
	return []string{strconv.FormatInt(j.ID, 10), j.Name, j.Dataset, strconv.FormatBool(j.Enabled), j.Frequency, j.LastError}
}

func jobHeaders() []string {
	return []string{"ID", "NAME", "DATASET", "ENABLED", "FREQUENCY", "LAST ERROR"}
}

func datasetRow(j cloudflare.LogpushJob) []string {
	return []string{strconv.FormatInt(j.ID, 10), j.Name, strconv.FormatBool(j.Enabled), j.Frequency, j.LastError}
}

func datasetJobHeaders() []string {
	return []string{"ID", "NAME", "ENABLED", "FREQUENCY", "LAST ERROR"}
}
