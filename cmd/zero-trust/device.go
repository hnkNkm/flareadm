package zerotrust

import (
	"encoding/json"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

// userEmail extracts a user email from a device's user object (or plain string).
func userEmail(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var obj struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil && obj.Email != "" {
		return obj.Email
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return compactJSON(raw)
}

func deviceRow(d cloudflare.Device) []string {
	return []string{d.ID, d.Name, d.DeviceType, d.MacAddress, d.IP, dateOnly(d.LastSeen), userEmail(d.User)}
}

func deviceHeaders() []string {
	return []string{"ID", "NAME", "TYPE", "MAC", "IP", "LAST SEEN", "USER"}
}

func physicalDeviceRow(d cloudflare.PhysicalDevice) []string {
	return []string{d.ID, d.Name, d.DeviceType, d.OSVersion, d.ClientVersion, dateOnly(d.LastSeenAt), userEmail(d.LastSeenUser)}
}

func physicalDeviceHeaders() []string {
	return []string{"ID", "NAME", "TYPE", "OS VERSION", "CLIENT VERSION", "LAST SEEN", "USER"}
}

func newDeviceGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "device",
		Short: "Zero Trust devices",
		Long:  "Zero Trust device registrations and the device fleet (/accounts/{account_id}/devices).",
	}
	cmd.AddCommand(newDeviceList(rt))
	cmd.AddCommand(newDeviceGet(rt))
	cmd.AddCommand(newDevicePhysicalGroup(rt))
	cmd.AddCommand(newDevicePostureGroup(rt))
	cmd.AddCommand(newDeviceSettingsGroup(rt))
	return cmd
}

func newDeviceList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List device registrations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListDevices(cmd.Context(), ref.ID, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, deviceHeaders(), deviceRow)
		},
	}
}

func newDeviceGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get DEVICE_ID",
		Short: "Show one device registration",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetDevice(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, deviceHeaders(), deviceRow)
		},
	}
}

// newDevicePhysicalGroup builds the device-fleet sub-resource
// (/accounts/{account_id}/devices/physical-devices).
func newDevicePhysicalGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "physical-device",
		Short: "Devices in the device fleet",
		Long:  "Device fleet (/accounts/{account_id}/devices/physical-devices), the cursor-paginated\ndevice list used by the Cloudflare dashboard.",
	}
	cmd.AddCommand(newPhysicalDeviceList(rt))
	cmd.AddCommand(newPhysicalDeviceGet(rt))
	cmd.AddCommand(newPhysicalDeviceDelete(rt))
	cmd.AddCommand(newPhysicalDeviceRevoke(rt))
	return cmd
}

func newPhysicalDeviceList(rt *app.Runtime) *cobra.Command {
	var f cloudflare.PhysicalDeviceQuery
	var idsFlag string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List devices in the device fleet",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			f.IDs = splitList(idsFlag)
			if f.ActiveRegistrations != "" && !contains(cloudflare.PhysicalDeviceActiveRegistrationValues, f.ActiveRegistrations) {
				return errors.Usage("invalid --active-registrations %q (supported: %s)", f.ActiveRegistrations, strings.Join(cloudflare.PhysicalDeviceActiveRegistrationValues, ", "))
			}
			if f.SortBy != "" && !contains(cloudflare.PhysicalDeviceSortValues, f.SortBy) {
				return errors.Usage("invalid --sort-by %q (supported: %s)", f.SortBy, strings.Join(cloudflare.PhysicalDeviceSortValues, ", "))
			}
			if f.SortOrder != "" && f.SortOrder != "asc" && f.SortOrder != "desc" {
				return errors.Usage("invalid --sort-order %q (supported: asc, desc)", f.SortOrder)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListPhysicalDevices(cmd.Context(), ref.ID, f, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, physicalDeviceHeaders(), physicalDeviceRow)
		},
	}
	cmd.Flags().StringVar(&f.Search, "search", "", "search devices by name, serial number or user email")
	cmd.Flags().StringVar(&idsFlag, "id", "", "comma-separated device ids to include")
	cmd.Flags().StringVar(&f.ActiveRegistrations, "active-registrations", "", "filter by active registration: "+strings.Join(cloudflare.PhysicalDeviceActiveRegistrationValues, ", "))
	cmd.Flags().StringVar(&f.LastSeenUser, "last-seen-user", "", "filter by last seen user (email)")
	cmd.Flags().StringVar(&f.SortBy, "sort-by", "", "sort key: "+strings.Join(cloudflare.PhysicalDeviceSortValues, ", "))
	cmd.Flags().StringVar(&f.SortOrder, "sort-order", "", "sort order: asc, desc")
	cmd.Flags().StringVar(&f.SeenAfter, "seen-after", "", "only devices seen after this RFC3339 time")
	cmd.Flags().StringVar(&f.SeenBefore, "seen-before", "", "only devices seen before this RFC3339 time")
	return cmd
}

func newPhysicalDeviceGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get DEVICE_ID",
		Short: "Show one device in the device fleet",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetPhysicalDevice(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, physicalDeviceHeaders(), physicalDeviceRow)
		},
	}
}

func newPhysicalDeviceDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete DEVICE_ID",
		Short: "Delete a device from the device fleet",
		Long: "Delete a device. Destructive: prompts for confirmation unless --yes is given;\n" +
			"--dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetPhysicalDevice(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would delete device "+existing.Item.Name)
			}
			if err := rt.Confirm("Delete device " + existing.Item.Name + "?"); err != nil {
				return err
			}
			if err := client.DeletePhysicalDevice(cmd.Context(), ref.ID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted device %s", args[0])
			return nil
		},
	}
	return cmd
}

func newPhysicalDeviceRevoke(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke DEVICE_ID",
		Short: "Revoke a device",
		Long: "Revoke a device's registrations. The device keeps its record but loses access\n" +
			"until it is enrolled again. Prompts for confirmation unless --yes is given;\n" +
			"--dry-run previews the revocation without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetPhysicalDevice(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would revoke device "+existing.Item.Name)
			}
			if err := rt.Confirm("Revoke device " + existing.Item.Name + "?"); err != nil {
				return err
			}
			if err := client.RevokePhysicalDevice(cmd.Context(), ref.ID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("revoked device %s", args[0])
			return nil
		},
	}
	return cmd
}
