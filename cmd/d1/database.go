package d1

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
)

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

func sizeString(b float64) string {
	if b < 1024 {
		return strconv.FormatFloat(b, 'f', 0, 64) + " B"
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	v := b
	i := -1
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	return strconv.FormatFloat(v, 'f', 1, 64) + " " + units[i]
}

func databaseRow(d cloudflare.D1Database) []string {
	return []string{d.UUID, d.Name, strconv.FormatFloat(d.NumTables, 'f', 0, 64), sizeString(d.FileSize), dateOnly(d.CreatedAt)}
}

func previewLine(rt *app.Runtime, line string) error {
	if rt.Format() == output.Table {
		_, _ = fmt.Fprintln(rt.Out, line)
		return nil
	}
	return rt.Printer().Emit(map[string]string{"preview": rt.Redact(line)})
}

func newDatabaseGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "database",
		Short: "D1 databases",
	}
	cmd.AddCommand(newDatabaseList(rt))
	cmd.AddCommand(newDatabaseGet(rt))
	cmd.AddCommand(newDatabaseCreate(rt))
	cmd.AddCommand(newDatabaseUpdate(rt))
	cmd.AddCommand(newDatabaseDelete(rt))
	cmd.AddCommand(newDatabaseQuery(rt))
	cmd.AddCommand(newDatabaseRaw(rt))
	cmd.AddCommand(newDatabaseExport(rt))
	cmd.AddCommand(newDatabaseImport(rt))
	cmd.AddCommand(newDatabaseBookmark(rt))
	cmd.AddCommand(newDatabaseRestore(rt))
	return cmd
}

func newDatabaseList(rt *app.Runtime) *cobra.Command {
	var nameFlag string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List D1 databases",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListD1Databases(cmd.Context(), ref.ID, cloudflare.D1ListQuery{Name: nameFlag}, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, []string{"UUID", "NAME", "TABLES", "SIZE", "CREATED"}, databaseRow)
		},
	}
	cmd.Flags().StringVar(&nameFlag, "name", "", "only the database with this exact name")
	return cmd
}

func newDatabaseGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get DATABASE_ID",
		Short: "Show one D1 database",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetD1Database(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"UUID", "NAME", "TABLES", "SIZE", "CREATED"}, databaseRow)
		},
	}
}

func newDatabaseCreate(rt *app.Runtime) *cobra.Command {
	var nameFlag, locationFlag, jurisdictionFlag, replicationFlag string
	cmd := &cobra.Command{
		Use:   "create --name NAME",
		Short: "Create a D1 database",
		Long: "Create a D1 database.\n\n" +
			"Example:\n" +
			"  flareadm d1 database create --name app-db --location-hint weur --read-replication-mode auto",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if nameFlag == "" {
				return errors.Usage("--name is required")
			}
			if locationFlag != "" && !contains(cloudflare.D1LocationHints, locationFlag) {
				return errors.Usage("invalid --location-hint %q (supported: %s)", locationFlag, strings.Join(cloudflare.D1LocationHints, ", "))
			}
			if jurisdictionFlag != "" && !contains(cloudflare.D1Jurisdictions, jurisdictionFlag) {
				return errors.Usage("invalid --jurisdiction %q (supported: %s)", jurisdictionFlag, strings.Join(cloudflare.D1Jurisdictions, ", "))
			}
			if replicationFlag != "" && !contains(cloudflare.D1ReadReplicationModes, replicationFlag) {
				return errors.Usage("invalid --read-replication-mode %q (supported: %s)", replicationFlag, strings.Join(cloudflare.D1ReadReplicationModes, ", "))
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would create D1 database "+nameFlag)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateD1Database(cmd.Context(), ref.ID, cloudflare.D1DatabaseCreateParams{
				Name: nameFlag, PrimaryLocationHint: locationFlag,
				Jurisdiction: jurisdictionFlag, ReadReplicationMode: replicationFlag,
			})
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"UUID", "NAME", "TABLES", "SIZE", "CREATED"}, databaseRow)
		},
	}
	cmd.Flags().StringVar(&nameFlag, "name", "", "database name (required)")
	cmd.Flags().StringVar(&locationFlag, "location-hint", "", "primary location hint (wnam, enam, weur, eeur, apac, oc)")
	cmd.Flags().StringVar(&jurisdictionFlag, "jurisdiction", "", "jurisdiction (eu, fedramp, us)")
	cmd.Flags().StringVar(&replicationFlag, "read-replication-mode", "", "read replication mode (auto, disabled)")
	_ = cmd.RegisterFlagCompletionFunc("location-hint", cmdutil.EnumsOf(cloudflare.D1LocationHints))
	_ = cmd.RegisterFlagCompletionFunc("jurisdiction", cmdutil.EnumsOf(cloudflare.D1Jurisdictions))
	_ = cmd.RegisterFlagCompletionFunc("read-replication-mode", cmdutil.EnumsOf(cloudflare.D1ReadReplicationModes))
	return cmd
}

func newDatabaseUpdate(rt *app.Runtime) *cobra.Command {
	var replicationFlag string
	cmd := &cobra.Command{
		Use:   "update DATABASE_ID --read-replication-mode MODE",
		Short: "Update D1 read replication",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("read-replication-mode") {
				return errors.Usage("nothing to update; pass --read-replication-mode")
			}
			if !contains(cloudflare.D1ReadReplicationModes, replicationFlag) {
				return errors.Usage("invalid --read-replication-mode %q (supported: %s)", replicationFlag, strings.Join(cloudflare.D1ReadReplicationModes, ", "))
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would set the read replication mode of D1 database "+args[0]+" to "+replicationFlag)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateD1ReadReplication(cmd.Context(), ref.ID, args[0], replicationFlag)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"UUID", "NAME", "TABLES", "SIZE", "CREATED"}, databaseRow)
		},
	}
	cmd.Flags().StringVar(&replicationFlag, "read-replication-mode", "", "read replication mode (auto, disabled)")
	_ = cmd.RegisterFlagCompletionFunc("read-replication-mode", cmdutil.EnumsOf(cloudflare.D1ReadReplicationModes))
	return cmd
}

func newDatabaseDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete DATABASE_ID",
		Short: "Delete a D1 database",
		Long: "Delete a D1 database. Destructive: prompts for confirmation unless --yes is\n" +
			"given; --dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetD1Database(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would delete D1 database "+existing.Item.Name+" ("+existing.Item.UUID+")")
			}
			if err := rt.Confirm("Delete D1 database " + existing.Item.Name + "?"); err != nil {
				return err
			}
			if err := client.DeleteD1Database(cmd.Context(), ref.ID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted D1 database %s", args[0])
			return nil
		},
	}
	return cmd
}

func newDatabaseBookmark(rt *app.Runtime) *cobra.Command {
	var timestampFlag string
	cmd := &cobra.Command{
		Use:   "bookmark DATABASE_ID",
		Short: "Read a D1 time-travel bookmark",
		Long:  "Read the current time-travel bookmark, or the bookmark at --timestamp.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var at *time.Time
			if timestampFlag != "" {
				parsed, err := time.Parse(time.RFC3339, timestampFlag)
				if err != nil {
					return errors.Usage("invalid --timestamp %q (expected RFC3339, for example 2026-01-02T15:04:05Z)", timestampFlag)
				}
				at = &parsed
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.D1BookmarkAt(cmd.Context(), ref.ID, args[0], at)
			if err != nil {
				return err
			}
			row := func(b cloudflare.D1Bookmark) []string { return []string{b.Bookmark} }
			return app.RenderGet(rt, res, []string{"BOOKMARK"}, row)
		},
	}
	cmd.Flags().StringVar(&timestampFlag, "timestamp", "", "bookmark at this RFC3339 timestamp")
	return cmd
}

func newDatabaseRestore(rt *app.Runtime) *cobra.Command {
	var bookmarkFlag, timestampFlag string
	cmd := &cobra.Command{
		Use:   "restore DATABASE_ID",
		Short: "Restore a D1 database (time travel)",
		Long: "Restore a database to a bookmark or timestamp. Destructive: prompts for\n" +
			"confirmation unless --yes is given; --dry-run previews the restore.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if bookmarkFlag == "" && timestampFlag == "" {
				return errors.Usage("--bookmark or --timestamp is required")
			}
			if bookmarkFlag != "" && timestampFlag != "" {
				return errors.Usage("--bookmark and --timestamp are mutually exclusive")
			}
			var at *time.Time
			if timestampFlag != "" {
				parsed, err := time.Parse(time.RFC3339, timestampFlag)
				if err != nil {
					return errors.Usage("invalid --timestamp %q (expected RFC3339)", timestampFlag)
				}
				at = &parsed
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			target := bookmarkFlag
			if target == "" {
				target = timestampFlag
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would restore D1 database "+args[0]+" to "+target)
			}
			if err := rt.Confirm("Restore D1 database " + args[0] + " to " + target + "?"); err != nil {
				return err
			}
			res, err := client.RestoreD1(cmd.Context(), ref.ID, args[0], cloudflare.D1RestoreParams{Bookmark: bookmarkFlag, At: at})
			if err != nil {
				return err
			}
			row := func(r cloudflare.D1RestoreResult) []string {
				return []string{r.Bookmark, r.PreviousBookmark, r.Message}
			}
			return app.RenderGet(rt, res, []string{"BOOKMARK", "PREVIOUS BOOKMARK", "MESSAGE"}, row)
		},
	}
	cmd.Flags().StringVar(&bookmarkFlag, "bookmark", "", "time-travel bookmark to restore to")
	cmd.Flags().StringVar(&timestampFlag, "timestamp", "", "RFC3339 timestamp to restore to")
	return cmd
}
