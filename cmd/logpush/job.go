package logpush

import (
	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func renderJobs(rt *app.Runtime, res *cloudflare.ListResult[cloudflare.LogpushJob]) error {
	return app.RenderList(rt, res, jobHeaders(), jobRow)
}

func renderJob(rt *app.Runtime, res *cloudflare.GetResult[cloudflare.LogpushJob]) error {
	return app.RenderGet(rt, res, jobHeaders(), jobRow)
}

type jobFlagValues struct {
	rt                *app.Runtime
	DestinationConf   string
	Dataset           string
	Name              string
	Filter            string
	Frequency         string
	Kind              string
	LogpullOptions    string
	OutputOptions     string
	OwnershipChalleng string
	Settings          string
	MaxUploadBytes    int64
	MaxUploadInterval int64
	MaxUploadRecords  int64
	Enabled           bool
}

func addJobFlags(rt *app.Runtime, cmd *cobra.Command, f *jobFlagValues, create bool) {
	f.rt = rt
	if create {
		cmd.Flags().StringVar(&f.DestinationConf, "destination-conf", "", "destination URL as @file only (it embeds destination credentials)")
		cmd.Flags().StringVar(&f.Dataset, "dataset", "", "dataset to push (required)")
		cmd.Flags().StringVar(&f.OwnershipChalleng, "ownership-challenge", "", "destination ownership challenge token as @file only")
	} else {
		cmd.Flags().StringVar(&f.DestinationConf, "destination-conf", "", "new destination URL as @file only (it embeds destination credentials)")
		cmd.Flags().StringVar(&f.OwnershipChalleng, "ownership-challenge", "", "destination ownership challenge token as @file only")
	}
	cmd.Flags().StringVar(&f.Name, "name", "", "job name")
	cmd.Flags().BoolVar(&f.Enabled, "enabled", false, "enable the job (use --enabled=false to disable)")
	cmd.Flags().StringVar(&f.Filter, "filter", "", "Logpush filter expression")
	cmd.Flags().StringVar(&f.Frequency, "frequency", "", "upload frequency (for example high or 5m)")
	cmd.Flags().StringVar(&f.Kind, "kind", "", "job kind (for example edge)")
	cmd.Flags().StringVar(&f.LogpullOptions, "logpull-options", "", "logpull options string")
	cmd.Flags().Int64Var(&f.MaxUploadBytes, "max-upload-bytes", 0, "maximum bytes per upload")
	cmd.Flags().Int64Var(&f.MaxUploadInterval, "max-upload-interval-seconds", 0, "maximum seconds between uploads")
	cmd.Flags().Int64Var(&f.MaxUploadRecords, "max-upload-records", 0, "maximum records per upload")
	cmd.Flags().StringVar(&f.OutputOptions, "output-options", "", "output options object as JSON, inline or @file")
	cmd.Flags().StringVar(&f.Settings, "settings", "", "additional job fields as a JSON object, inline or @file")
}

func (f *jobFlagValues) overrides(cmd *cobra.Command) (map[string]any, error) {
	body := map[string]any{}
	changed := func(name string) bool { return cmd.Flags().Changed(name) }
	if changed("destination-conf") {
		dest, err := cmdutil.FileOnly("destination-conf", f.DestinationConf)
		if err != nil {
			return nil, err
		}
		f.rt.ProtectSecret(dest)
		cmdutil.ProtectURLCredentials(f.rt, dest)
		body["destination_conf"] = dest
	}
	if changed("dataset") {
		body["dataset"] = f.Dataset
	}
	if changed("ownership-challenge") {
		challenge, err := cmdutil.FileOnly("ownership-challenge", f.OwnershipChalleng)
		if err != nil {
			return nil, err
		}
		f.rt.ProtectSecret(challenge)
		body["ownership_challenge"] = challenge
	}
	if changed("name") {
		body["name"] = f.Name
	}
	if changed("enabled") {
		body["enabled"] = f.Enabled
	}
	if changed("filter") {
		body["filter"] = f.Filter
	}
	if changed("frequency") {
		body["frequency"] = f.Frequency
	}
	if changed("kind") {
		body["kind"] = f.Kind
	}
	if changed("logpull-options") {
		body["logpull_options"] = f.LogpullOptions
	}
	if changed("max-upload-bytes") {
		body["max_upload_bytes"] = f.MaxUploadBytes
	}
	if changed("max-upload-interval-seconds") {
		body["max_upload_interval_seconds"] = f.MaxUploadInterval
	}
	if changed("max-upload-records") {
		body["max_upload_records"] = f.MaxUploadRecords
	}
	if changed("output-options") {
		obj, err := cmdutil.ParseSecretCarryingObject(f.rt, "output-options", f.OutputOptions)
		if err != nil {
			return nil, err
		}
		body["output_options"] = obj
	}
	if changed("settings") {
		extra, err := cmdutil.ParseSecretCarryingSettings(f.rt, "settings", f.Settings)
		if err != nil {
			return nil, err
		}
		for k, v := range extra {
			body[k] = v
		}
	}
	return body, nil
}

func newJobGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "job",
		Short: "Logpush jobs",
		Long:  "Logpush jobs (/accounts/{account_id}/logpush/jobs, or /zones/{zone_id}/logpush/jobs with --zone).\n\nThe destination URL embeds credentials (S3/GCS keys, tokens): --destination-conf\nis @file-only, is registered as a protected secret, and never appears in\ndiagnostics, error text or --dry-run previews. The destination is omitted from\nnormalized output; --raw shows it.",
	}
	cmd.AddCommand(newJobList(rt))
	cmd.AddCommand(newJobGet(rt))
	cmd.AddCommand(newJobCreate(rt))
	cmd.AddCommand(newJobUpdate(rt))
	cmd.AddCommand(newJobDelete(rt))
	return cmd
}

func newJobList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List Logpush jobs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, accountID, zoneID, err := scope(cmd.Context(), rt)
			if err != nil {
				return err
			}
			res, err := client.ListLogpushJobs(cmd.Context(), accountID, zoneID, rt.Policy())
			if err != nil {
				return err
			}
			return renderJobs(rt, res)
		},
	}
}

func newJobGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get JOB_ID",
		Short: "Show one Logpush job",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := jobID(args[0])
			if err != nil {
				return err
			}
			client, accountID, zoneID, err := scope(cmd.Context(), rt)
			if err != nil {
				return err
			}
			res, err := client.GetLogpushJob(cmd.Context(), accountID, zoneID, id)
			if err != nil {
				return err
			}
			return renderJob(rt, res)
		},
	}
}

func newJobCreate(rt *app.Runtime) *cobra.Command {
	var f jobFlagValues
	cmd := &cobra.Command{
		Use:   "create --destination-conf @dest.txt --dataset DATASET",
		Short: "Create a Logpush job",
		Long: "Create a Logpush job.\n\n" +
			"Example:\n" +
			"  flareadm logpush job create --destination-conf @dest.txt \\\n" +
			"    --dataset http_requests --name requests --enabled\n\n" +
			"--destination-conf is @file-only because the URL embeds destination\n" +
			"credentials; previews name the job and dataset but never the destination.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("destination-conf") {
				return errors.Usage("--destination-conf is required (@file only)")
			}
			if f.Dataset == "" {
				return errors.Usage("--dataset is required")
			}
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would create Logpush job "+f.Name+" for dataset "+f.Dataset+" (destination hidden)")
			}
			client, accountID, zoneID, err := scope(cmd.Context(), rt)
			if err != nil {
				return err
			}
			res, err := client.CreateLogpushJob(cmd.Context(), accountID, zoneID, body)
			if err != nil {
				return err
			}
			return renderJob(rt, res)
		},
	}
	addJobFlags(rt, cmd, &f, true)
	return cmd
}

func newJobUpdate(rt *app.Runtime) *cobra.Command {
	var f jobFlagValues
	cmd := &cobra.Command{
		Use:   "update JOB_ID",
		Short: "Update a Logpush job",
		Long: "Update a job. Provided fields are merged into the current job and the result is\n" +
			"PUT, so fields this CLI does not model are preserved.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := jobID(args[0])
			if err != nil {
				return err
			}
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if len(body) == 0 {
				return errors.Usage("nothing to update; pass at least one job flag or --settings")
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would update Logpush job "+args[0])
			}
			client, accountID, zoneID, err := scope(cmd.Context(), rt)
			if err != nil {
				return err
			}
			res, err := client.UpdateLogpushJob(cmd.Context(), accountID, zoneID, id, body)
			if err != nil {
				return err
			}
			return renderJob(rt, res)
		},
	}
	addJobFlags(rt, cmd, &f, false)
	return cmd
}

func newJobDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete JOB_ID",
		Short: "Delete a Logpush job",
		Long: "Delete a job. Destructive: prompts for confirmation unless --yes is given;\n" +
			"--dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := jobID(args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return cmdutil.PreviewLine(rt, "Would delete Logpush job "+args[0])
			}
			if err := rt.Confirm("Delete Logpush job " + args[0] + "?"); err != nil {
				return err
			}
			client, accountID, zoneID, err := scope(cmd.Context(), rt)
			if err != nil {
				return err
			}
			if err := client.DeleteLogpushJob(cmd.Context(), accountID, zoneID, id); err != nil {
				return err
			}
			rt.Logger().Infof("deleted Logpush job %s", args[0])
			return nil
		},
	}
	return cmd
}
