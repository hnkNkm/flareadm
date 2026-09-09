// Package zone implements `flareadm zone list|get`.
package zone

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/resolver"
)

// New builds the zone command group.
func New(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "zone",
		Short: "Cloudflare zones",
	}
	cmd.AddCommand(newList(rt))
	cmd.AddCommand(newGet(rt))
	return cmd
}

func zoneRow(z cloudflare.Zone) []string {
	return []string{z.ID, z.Name, z.Status}
}

// zoneStatuses are the valid --status filter values.
var zoneStatuses = []string{"initializing", "pending", "active", "moved", "deleted", "deactivated"}

// newList lists zones.
func newList(rt *app.Runtime) *cobra.Command {
	var nameFlag, statusFlag, typeFlag string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List zones",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if statusFlag != "" && !contains(zoneStatuses, statusFlag) {
				return errors.Usage("invalid --status %q (supported: %s)", statusFlag, strings.Join(zoneStatuses, ", "))
			}
			if typeFlag != "" && typeFlag != "full" && typeFlag != "partial" {
				return errors.Usage("invalid --type %q (supported: full, partial)", typeFlag)
			}
			client, err := rt.CloudClient()
			if err != nil {
				return err
			}
			q := cloudflare.ZoneListQuery{Name: nameFlag, Status: statusFlag, Type: typeFlag}
			// The account filter is only applied when --account-id was
			// given explicitly; otherwise zone listing spans the accounts
			// the token can see.
			q.AccountID = rt.AccountIDFlag
			res, err := client.ListZones(cmd.Context(), q, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, []string{"ID", "NAME", "STATUS"}, zoneRow)
		},
	}
	cmd.Flags().StringVar(&nameFlag, "name", "", "only zones with this exact name")
	cmd.Flags().StringVar(&statusFlag, "status", "", "only zones with this status (initializing, pending, active, moved, deleted, deactivated)")
	cmd.Flags().StringVar(&typeFlag, "type", "", "only zones of this type (full, partial)")
	return cmd
}

// newGet shows one zone (positional name-or-id, --zone, or the profile
// default_zone).
func newGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get [NAME_OR_ID]",
		Short: "Show one zone",
		Long: "Show one zone. Accepts a zone name or id: the positional argument,\n" +
			"--zone, or the profile default_zone.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref := ""
			if len(args) == 1 {
				ref = args[0]
			}
			ref, err := rt.ZoneReference(ref)
			if err != nil {
				return err
			}
			client, err := rt.CloudClient()
			if err != nil {
				return err
			}
			zoneID, err := resolver.NewZone(client).Resolve(cmd.Context(), ref)
			if err != nil {
				return err
			}
			if zoneID != ref {
				rt.Logger().Infof("resolved zone %q to %s", ref, zoneID)
			}
			res, err := client.GetZone(cmd.Context(), zoneID)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"ID", "NAME", "STATUS"}, zoneRow)
		},
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
