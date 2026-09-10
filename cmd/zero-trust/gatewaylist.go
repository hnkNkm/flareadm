package zerotrust

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func gatewayListRow(l cloudflare.GatewayList) []string {
	return []string{l.ID, l.Name, l.Type, strconv.FormatInt(l.Count, 10), l.Description}
}

func gatewayListHeaders() []string {
	return []string{"ID", "NAME", "TYPE", "ITEMS", "DESCRIPTION"}
}

func gatewayItemRow(i cloudflare.GatewayItem) []string {
	return []string{i.Value, i.Description, dateOnly(i.CreatedAt)}
}

func gatewayItemHeaders() []string {
	return []string{"VALUE", "DESCRIPTION", "CREATED"}
}

// parseGatewayItems reads an items array whose entries are either plain values
// or objects with value/description.
func parseGatewayItems(flag, v string) ([]cloudflare.GatewayItem, error) {
	text, err := cmdutilValueOrFile(flag, v)
	if err != nil {
		return nil, err
	}
	var raws []json.RawMessage
	if err := json.Unmarshal([]byte(strings.TrimSpace(text)), &raws); err != nil {
		return nil, errors.Usage("--%s must be a JSON array of values or objects", flag)
	}
	items := make([]cloudflare.GatewayItem, 0, len(raws))
	for _, raw := range raws {
		var item cloudflare.GatewayItem
		if err := json.Unmarshal(raw, &item); err != nil || item.Value == "" {
			var value string
			if err := json.Unmarshal(raw, &value); err != nil || value == "" {
				return nil, errors.Usage("--%s entries must be non-empty strings or objects with a value", flag)
			}
			item = cloudflare.GatewayItem{Value: value}
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		return nil, errors.Usage("--%s must not be empty", flag)
	}
	return items, nil
}

func newGatewayListGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Gateway lists",
		Long:  "Gateway lists (/accounts/{account_id}/gateway/lists), the reusable value lists referenced by Gateway rules.",
	}
	cmd.AddCommand(newGatewayListList(rt))
	cmd.AddCommand(newGatewayListGet(rt))
	cmd.AddCommand(newGatewayListCreate(rt))
	cmd.AddCommand(newGatewayListUpdate(rt))
	cmd.AddCommand(newGatewayListDelete(rt))
	cmd.AddCommand(newGatewayListItemGroup(rt))
	return cmd
}

func newGatewayListList(rt *app.Runtime) *cobra.Command {
	var typeFlag string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List Gateway lists",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if typeFlag != "" && !contains(cloudflare.GatewayListTypeValues, typeFlag) {
				return errors.Usage("invalid --type %q (supported: %s)", typeFlag, strings.Join(cloudflare.GatewayListTypeValues, ", "))
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListGatewayLists(cmd.Context(), ref.ID, typeFlag, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, gatewayListHeaders(), gatewayListRow)
		},
	}
	cmd.Flags().StringVar(&typeFlag, "type", "", "only lists of this type: "+strings.Join(cloudflare.GatewayListTypeValues, ", "))
	return cmd
}

func newGatewayListGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get LIST_ID",
		Short: "Show one Gateway list",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetGatewayList(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, gatewayListHeaders(), gatewayListRow)
		},
	}
}

func newGatewayListCreate(rt *app.Runtime) *cobra.Command {
	var nameFlag, typeFlag, descriptionFlag, itemsFlag string
	cmd := &cobra.Command{
		Use:   "create --name NAME --type TYPE",
		Short: "Create a Gateway list",
		Long: "Create a Gateway list.\n\n" +
			"Example:\n" +
			"  flareadm zero-trust gateway list create --name blocked --type DOMAIN \\\n" +
			"    --items '[\"ads.example.com\"]'",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if nameFlag == "" {
				return errors.Usage("--name is required")
			}
			if typeFlag == "" {
				return errors.Usage("--type is required")
			}
			if !contains(cloudflare.GatewayListTypeValues, typeFlag) {
				return errors.Usage("invalid --type %q (supported: %s)", typeFlag, strings.Join(cloudflare.GatewayListTypeValues, ", "))
			}
			body := map[string]any{"name": nameFlag, "type": typeFlag}
			if cmd.Flags().Changed("description") {
				body["description"] = descriptionFlag
			}
			if cmd.Flags().Changed("items") {
				items, err := parseGatewayItems("items", itemsFlag)
				if err != nil {
					return err
				}
				body["items"] = items
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would create Gateway list "+nameFlag)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateGatewayList(cmd.Context(), ref.ID, body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, gatewayListHeaders(), gatewayListRow)
		},
	}
	cmd.Flags().StringVar(&nameFlag, "name", "", "list name (required)")
	cmd.Flags().StringVar(&typeFlag, "type", "", "list type (required): "+strings.Join(cloudflare.GatewayListTypeValues, ", "))
	cmd.Flags().StringVar(&descriptionFlag, "description", "", "list description")
	cmd.Flags().StringVar(&itemsFlag, "items", "", "initial items as a JSON array of values or objects, inline or @file")
	return cmd
}

func newGatewayListUpdate(rt *app.Runtime) *cobra.Command {
	var nameFlag, descriptionFlag, itemsFlag string
	cmd := &cobra.Command{
		Use:   "update LIST_ID",
		Short: "Update a Gateway list",
		Long: "Update a Gateway list. Provided fields are merged into the current list and the\n" +
			"result is PUT, so fields this CLI does not model are preserved. --items replaces\n" +
			"the whole item set; use `zero-trust gateway list item create|delete` to add or\n" +
			"remove items without resending them all.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]any{}
			if cmd.Flags().Changed("name") {
				if nameFlag == "" {
					return errors.Usage("--name must not be empty")
				}
				body["name"] = nameFlag
			}
			if cmd.Flags().Changed("description") {
				body["description"] = descriptionFlag
			}
			if cmd.Flags().Changed("items") {
				items, err := parseGatewayItems("items", itemsFlag)
				if err != nil {
					return err
				}
				body["items"] = items
			}
			if len(body) == 0 {
				return errors.Usage("nothing to update; pass at least one of --name, --description, --items")
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would update Gateway list "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateGatewayList(cmd.Context(), ref.ID, args[0], body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, gatewayListHeaders(), gatewayListRow)
		},
	}
	cmd.Flags().StringVar(&nameFlag, "name", "", "list name")
	cmd.Flags().StringVar(&descriptionFlag, "description", "", "list description")
	cmd.Flags().StringVar(&itemsFlag, "items", "", "replacement items as a JSON array of values or objects, inline or @file")
	return cmd
}

func newGatewayListDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete LIST_ID",
		Short: "Delete a Gateway list",
		Long: "Delete a Gateway list. Destructive: rules referencing it must be updated first.\n" +
			"Prompts for confirmation unless --yes is given; --dry-run previews the deletion.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetGatewayList(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would delete Gateway list "+existing.Item.Name)
			}
			if err := rt.Confirm("Delete Gateway list " + existing.Item.Name + "?"); err != nil {
				return err
			}
			if err := client.DeleteGatewayList(cmd.Context(), ref.ID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted Gateway list %s", args[0])
			return nil
		},
	}
	return cmd
}

// newGatewayListItemGroup builds the item sub-resource. The API adds and
// removes items through a PATCH on the list (append/remove), so the verbs are
// create (add items) and delete (remove item values); `update LIST_ID --items`
// replaces the whole set.
func newGatewayListItemGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "item",
		Short: "Items of a Gateway list",
		Long:  "Items of one Gateway list (/accounts/{account_id}/gateway/lists/{list_id}/items).",
	}
	cmd.AddCommand(newGatewayListItemList(rt))
	cmd.AddCommand(newGatewayListItemCreate(rt))
	cmd.AddCommand(newGatewayListItemDelete(rt))
	return cmd
}

func newGatewayListItemList(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list LIST_ID",
		Short: "List a Gateway list's items",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListGatewayListItems(cmd.Context(), ref.ID, args[0], rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, gatewayItemHeaders(), gatewayItemRow)
		},
	}
}

func newGatewayListItemCreate(rt *app.Runtime) *cobra.Command {
	var itemsFlag string
	cmd := &cobra.Command{
		Use:   "create LIST_ID --items @items.json",
		Short: "Add items to a Gateway list",
		Long: "Add items to a Gateway list (the API appends them to the list).\n\n" +
			"Example:\n" +
			"  flareadm zero-trust gateway list item create <list> --items '[\"ads.example.com\"]'",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("items") {
				return errors.Usage("--items is required (JSON array of values or objects)")
			}
			items, err := parseGatewayItems("items", itemsFlag)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would add "+strconv.Itoa(len(items))+" item(s) to Gateway list "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.EditGatewayList(cmd.Context(), ref.ID, args[0], items, nil)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, gatewayListHeaders(), gatewayListRow)
		},
	}
	cmd.Flags().StringVar(&itemsFlag, "items", "", "items to add as a JSON array of values or objects, inline or @file")
	return cmd
}

func newGatewayListItemDelete(rt *app.Runtime) *cobra.Command {
	var valuesFlag string
	cmd := &cobra.Command{
		Use:   "delete LIST_ID --values VALUE[,VALUE...]",
		Short: "Remove items from a Gateway list",
		Long: "Remove items from a Gateway list by value (the API's remove operation).\n" +
			"Prompts for confirmation unless --yes is given; --dry-run previews the removal.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			values := splitList(valuesFlag)
			if len(values) == 0 {
				return errors.Usage("--values is required (comma-separated item values)")
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would remove "+strconv.Itoa(len(values))+" item(s) from Gateway list "+args[0])
			}
			if err := rt.Confirm("Remove " + strconv.Itoa(len(values)) + " item(s) from Gateway list " + args[0] + "?"); err != nil {
				return err
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.EditGatewayList(cmd.Context(), ref.ID, args[0], nil, values)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, gatewayListHeaders(), gatewayListRow)
		},
	}
	cmd.Flags().StringVar(&valuesFlag, "values", "", "item values to remove, comma-separated")
	return cmd
}
