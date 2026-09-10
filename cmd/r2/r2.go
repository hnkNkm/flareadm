// Package r2 implements `flareadm r2 bucket ...`: R2 bucket administration.
package r2

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
)

// New builds the r2 command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "r2",
		Short: "R2 object storage administration",
		Long:  "R2 bucket administration. Account scope is resolved through the standard account resolution (--account-id, profile account_id, FLAREADM_ACCOUNT_ID or the single accessible account).",
	}
	cmd.AddCommand(newBucketGroup(rt))
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

func dateOnly(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

func bucketRow(b cloudflare.R2Bucket) []string {
	return []string{b.Name, b.Location, b.StorageClass, b.Jurisdiction, dateOnly(b.CreationDate)}
}

func newBucketGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bucket",
		Short: "R2 buckets",
	}
	cmd.AddCommand(newBucketList(rt))
	cmd.AddCommand(newBucketGet(rt))
	cmd.AddCommand(newBucketCreate(rt))
	cmd.AddCommand(newBucketDelete(rt))
	return cmd
}

func newBucketList(rt *app.Runtime) *cobra.Command {
	var nameContains, order, direction, jurisdiction string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List R2 buckets",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if order != "" && order != "name" && order != "creation_date" {
				return errors.Usage("invalid --order %q (supported: name, creation_date)", order)
			}
			if direction != "" && direction != "asc" && direction != "desc" {
				return errors.Usage("invalid --direction %q (supported: asc, desc)", direction)
			}
			if jurisdiction != "" && !contains(cloudflare.R2Jurisdictions, jurisdiction) {
				return errors.Usage("invalid --jurisdiction %q (supported: %v)", jurisdiction, cloudflare.R2Jurisdictions)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			q := cloudflare.R2BucketQuery{NameContains: nameContains, Order: order, Direction: direction, Jurisdiction: jurisdiction}
			res, err := client.ListR2Buckets(cmd.Context(), ref.ID, q, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, []string{"NAME", "LOCATION", "STORAGE CLASS", "JURISDICTION", "CREATED"}, bucketRow)
		},
	}
	cmd.Flags().StringVar(&nameContains, "name-contains", "", "only buckets whose name contains this string")
	cmd.Flags().StringVar(&order, "order", "", "sort field (name, creation_date)")
	cmd.Flags().StringVar(&direction, "direction", "", "sort direction (asc, desc)")
	cmd.Flags().StringVar(&jurisdiction, "jurisdiction", "", "bucket jurisdiction (default, eu, us, fedramp)")
	return cmd
}

func newBucketGet(rt *app.Runtime) *cobra.Command {
	var jurisdiction string
	cmd := &cobra.Command{
		Use:   "get BUCKET_NAME",
		Short: "Show one R2 bucket",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if jurisdiction != "" && !contains(cloudflare.R2Jurisdictions, jurisdiction) {
				return errors.Usage("invalid --jurisdiction %q (supported: %v)", jurisdiction, cloudflare.R2Jurisdictions)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetR2Bucket(cmd.Context(), ref.ID, args[0], jurisdiction)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"NAME", "LOCATION", "STORAGE CLASS", "JURISDICTION", "CREATED"}, bucketRow)
		},
	}
	cmd.Flags().StringVar(&jurisdiction, "jurisdiction", "", "bucket jurisdiction (default, eu, us, fedramp)")
	return cmd
}

func newBucketCreate(rt *app.Runtime) *cobra.Command {
	var locationHint, storageClass, jurisdiction string
	cmd := &cobra.Command{
		Use:   "create --name BUCKET",
		Short: "Create an R2 bucket",
		Long: "Create an R2 bucket.\n\n" +
			"Example:\n" +
			"  flareadm r2 bucket create --name assets --location-hint weur --storage-class Standard",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := cmd.Flags().GetString("name")
			if err != nil {
				return err
			}
			if name == "" {
				return errors.Usage("--name is required")
			}
			if locationHint != "" && !contains(cloudflare.R2LocationHints, locationHint) {
				return errors.Usage("invalid --location-hint %q (supported: %v)", locationHint, cloudflare.R2LocationHints)
			}
			if storageClass != "" && !contains(cloudflare.R2StorageClasses, storageClass) {
				return errors.Usage("invalid --storage-class %q (supported: %v)", storageClass, cloudflare.R2StorageClasses)
			}
			if jurisdiction != "" && !contains(cloudflare.R2Jurisdictions, jurisdiction) {
				return errors.Usage("invalid --jurisdiction %q (supported: %v)", jurisdiction, cloudflare.R2Jurisdictions)
			}
			if rt.DryRunFlag {
				return preview(rt, "Would create R2 bucket "+name)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateR2Bucket(cmd.Context(), ref.ID, cloudflare.R2BucketCreateParams{
				Name: name, LocationHint: locationHint, StorageClass: storageClass, Jurisdiction: jurisdiction,
			})
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"NAME", "LOCATION", "STORAGE CLASS", "JURISDICTION", "CREATED"}, bucketRow)
		},
	}
	cmd.Flags().String("name", "", "bucket name (required)")
	cmd.Flags().StringVar(&locationHint, "location-hint", "", "location hint (apac, eeur, enam, weur, wnam, oc)")
	cmd.Flags().StringVar(&storageClass, "storage-class", "", "storage class (Standard, InfrequentAccess)")
	cmd.Flags().StringVar(&jurisdiction, "jurisdiction", "", "bucket jurisdiction (default, eu, us, fedramp)")
	return cmd
}

func newBucketDelete(rt *app.Runtime) *cobra.Command {
	var jurisdiction string
	cmd := &cobra.Command{
		Use:   "delete BUCKET_NAME",
		Short: "Delete an R2 bucket",
		Long: "Delete an R2 bucket. Destructive: prompts for confirmation unless --yes is\n" +
			"given; --dry-run previews the deletion without confirming. The bucket must\n" +
			"be empty before it can be deleted.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if jurisdiction != "" && !contains(cloudflare.R2Jurisdictions, jurisdiction) {
				return errors.Usage("invalid --jurisdiction %q (supported: %v)", jurisdiction, cloudflare.R2Jurisdictions)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetR2Bucket(cmd.Context(), ref.ID, args[0], jurisdiction)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return preview(rt, "Would delete R2 bucket "+existing.Item.Name)
			}
			if err := rt.Confirm("Delete R2 bucket " + existing.Item.Name + "?"); err != nil {
				return err
			}
			if err := client.DeleteR2Bucket(cmd.Context(), ref.ID, args[0], jurisdiction); err != nil {
				return err
			}
			rt.Logger().Infof("deleted R2 bucket %s", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&jurisdiction, "jurisdiction", "", "bucket jurisdiction (default, eu, us, fedramp)")
	return cmd
}

func preview(rt *app.Runtime, line string) error {
	if rt.Format() == output.Table {
		_, _ = fmt.Fprintln(rt.Out, line)
		return nil
	}
	return rt.Printer().Emit(map[string]string{"preview": line})
}
