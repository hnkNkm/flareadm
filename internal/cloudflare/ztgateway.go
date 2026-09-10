package cloudflare

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"

	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/pagination"
)

// GatewayRuleActionValues are the accepted Gateway rule actions.
var GatewayRuleActionValues = []string{
	"on", "off", "allow", "block", "scan", "noscan", "safesearch", "ytrestricted",
	"isolate", "noisolate", "override", "l4_override", "egress", "resolve", "quarantine", "redirect",
}

// GatewayListTypeValues are the accepted Gateway list types.
var GatewayListTypeValues = []string{"SERIAL", "URL", "DOMAIN", "EMAIL", "IP", "CATEGORY", "LOCATION", "DEVICE", "AAGUID"}

// DevicePostureTypeValues are the accepted device posture rule types.
var DevicePostureTypeValues = []string{
	"file", "application", "tanium", "gateway", "warp", "disk_encryption", "serial_number",
	"sentinelone", "carbonblack", "firewall", "os_version", "domain_joined", "client_certificate",
	"client_certificate_v2", "antivirus", "unique_client_id", "kolide", "tanium_s2s",
	"crowdstrike_s2s", "intune", "workspace_one", "sentinelone_s2s", "custom_s2s",
}

// PhysicalDeviceSortValues are the accepted fleet sort keys.
var PhysicalDeviceSortValues = []string{
	"name", "id", "client_version", "last_seen_user.email", "last_seen_at", "active_registrations", "created_at",
}

// PhysicalDeviceActiveRegistrationValues filter registrations in the fleet list.
var PhysicalDeviceActiveRegistrationValues = []string{"include", "only", "exclude"}

func gatewayPath(accountID string, resource string, id string) string {
	p := "/accounts/" + url.PathEscape(accountID) + "/gateway/" + resource
	if id != "" {
		p += "/" + url.PathEscape(id)
	}
	return p
}

func devicePath(accountID string, resource string, id string, suffix string) string {
	p := "/accounts/" + url.PathEscape(accountID) + "/devices"
	if resource != "" {
		p += "/" + resource
	}
	if id != "" {
		p += "/" + url.PathEscape(id)
	}
	if suffix != "" {
		p += "/" + suffix
	}
	return p
}

// singlePageList fetches a collection the API returns without pagination. The
// shared policy still applies --max-items (and --no-paginate is a no-op).
func singlePageList[T any](ctx context.Context, c *Client, path string, query url.Values, pol pagination.Policy) (*ListResult[T], error) {
	if err := pol.Validate(); err != nil {
		return nil, errors.Usage("%s", err.Error())
	}
	env, raw, err := c.requestJSON(ctx, "GET", path, query, nil, "")
	if err != nil {
		return nil, err
	}
	if c.raw {
		return &ListResult[T]{RawBody: raw}, nil
	}
	var items []T
	if err := decodeResult(env, &items); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding list response", err)
	}
	if pol.MaxItems > 0 && len(items) > pol.MaxItems {
		items = items[:pol.MaxItems]
	}
	return &ListResult[T]{Items: items}, nil
}

// ---- Gateway rules --------------------------------------------------------

// ListGatewayRules lists Gateway rules (the endpoint is not paginated).
func (c *Client) ListGatewayRules(ctx context.Context, accountID string, pol pagination.Policy) (*ListResult[GatewayRule], error) {
	return singlePageList[GatewayRule](ctx, c, gatewayPath(accountID, "rules", ""), nil, pol)
}

// GetGatewayRule fetches one Gateway rule.
func (c *Client) GetGatewayRule(ctx context.Context, accountID, ruleID string) (*GetResult[GatewayRule], error) {
	return accessGet[GatewayRule](ctx, c, gatewayPath(accountID, "rules", ruleID))
}

// CreateGatewayRule creates a Gateway rule (POST).
func (c *Client) CreateGatewayRule(ctx context.Context, accountID string, body map[string]any) (*GetResult[GatewayRule], error) {
	return accessCreate[GatewayRule](ctx, c, gatewayPath(accountID, "rules", ""), body)
}

// UpdateGatewayRule patches a Gateway rule by read-modify-PUT.
func (c *Client) UpdateGatewayRule(ctx context.Context, accountID, ruleID string, overrides map[string]any) (*GetResult[GatewayRule], error) {
	return accessMergeUpdate[GatewayRule](ctx, c, gatewayPath(accountID, "rules", ruleID), overrides)
}

// DeleteGatewayRule deletes a Gateway rule (DELETE, idempotent).
func (c *Client) DeleteGatewayRule(ctx context.Context, accountID, ruleID string) error {
	return accessDelete(ctx, c, gatewayPath(accountID, "rules", ruleID))
}

// ---- Gateway lists and items ----------------------------------------------

// ListGatewayLists lists Gateway lists (the endpoint is not paginated).
func (c *Client) ListGatewayLists(ctx context.Context, accountID, typeFilter string, pol pagination.Policy) (*ListResult[GatewayList], error) {
	query := url.Values{}
	if typeFilter != "" {
		query.Set("type", typeFilter)
	}
	return singlePageList[GatewayList](ctx, c, gatewayPath(accountID, "lists", ""), query, pol)
}

// GetGatewayList fetches one Gateway list.
func (c *Client) GetGatewayList(ctx context.Context, accountID, listID string) (*GetResult[GatewayList], error) {
	return accessGet[GatewayList](ctx, c, gatewayPath(accountID, "lists", listID))
}

// CreateGatewayList creates a Gateway list (POST).
func (c *Client) CreateGatewayList(ctx context.Context, accountID string, body map[string]any) (*GetResult[GatewayList], error) {
	return accessCreate[GatewayList](ctx, c, gatewayPath(accountID, "lists", ""), body)
}

// UpdateGatewayList patches a Gateway list by read-modify-PUT.
func (c *Client) UpdateGatewayList(ctx context.Context, accountID, listID string, overrides map[string]any) (*GetResult[GatewayList], error) {
	return accessMergeUpdate[GatewayList](ctx, c, gatewayPath(accountID, "lists", listID), overrides)
}

// DeleteGatewayList deletes a Gateway list (DELETE, idempotent).
func (c *Client) DeleteGatewayList(ctx context.Context, accountID, listID string) error {
	return accessDelete(ctx, c, gatewayPath(accountID, "lists", listID))
}

// ListGatewayListItems lists the items of one Gateway list (not paginated).
func (c *Client) ListGatewayListItems(ctx context.Context, accountID, listID string, pol pagination.Policy) (*ListResult[GatewayItem], error) {
	return singlePageList[GatewayItem](ctx, c, gatewayPath(accountID, "lists", listID)+"/items", nil, pol)
}

// EditGatewayList appends items and/or removes item values (PATCH).
func (c *Client) EditGatewayList(ctx context.Context, accountID, listID string, append []GatewayItem, remove []string) (*GetResult[GatewayList], error) {
	body := map[string]any{}
	if len(append) > 0 {
		body["append"] = append
	}
	if len(remove) > 0 {
		body["remove"] = remove
	}
	if len(body) == 0 {
		return nil, errors.Usage("nothing to change")
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "PATCH", gatewayPath(accountID, "lists", listID), nil, payload, "application/json")
	if err != nil {
		return nil, err
	}
	var item GatewayList
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding Gateway list response", err)
	}
	return &GetResult[GatewayList]{Item: item, RawBody: raw}, nil
}

// ---- Gateway locations ----------------------------------------------------

// ListGatewayLocations lists Gateway DNS locations (not paginated).
func (c *Client) ListGatewayLocations(ctx context.Context, accountID string, pol pagination.Policy) (*ListResult[GatewayLocation], error) {
	return singlePageList[GatewayLocation](ctx, c, gatewayPath(accountID, "locations", ""), nil, pol)
}

// GetGatewayLocation fetches one location.
func (c *Client) GetGatewayLocation(ctx context.Context, accountID, locationID string) (*GetResult[GatewayLocation], error) {
	return accessGet[GatewayLocation](ctx, c, gatewayPath(accountID, "locations", locationID))
}

// CreateGatewayLocation creates a location (POST).
func (c *Client) CreateGatewayLocation(ctx context.Context, accountID string, body map[string]any) (*GetResult[GatewayLocation], error) {
	return accessCreate[GatewayLocation](ctx, c, gatewayPath(accountID, "locations", ""), body)
}

// UpdateGatewayLocation patches a location by read-modify-PUT.
func (c *Client) UpdateGatewayLocation(ctx context.Context, accountID, locationID string, overrides map[string]any) (*GetResult[GatewayLocation], error) {
	return accessMergeUpdate[GatewayLocation](ctx, c, gatewayPath(accountID, "locations", locationID), overrides)
}

// DeleteGatewayLocation deletes a location (DELETE, idempotent).
func (c *Client) DeleteGatewayLocation(ctx context.Context, accountID, locationID string) error {
	return accessDelete(ctx, c, gatewayPath(accountID, "locations", locationID))
}

// ---- devices --------------------------------------------------------------

// ListDevices lists device registrations (the legacy endpoint is not paginated).
func (c *Client) ListDevices(ctx context.Context, accountID string, pol pagination.Policy) (*ListResult[Device], error) {
	return singlePageList[Device](ctx, c, devicePath(accountID, "", "", ""), nil, pol)
}

// GetDevice fetches one device registration.
func (c *Client) GetDevice(ctx context.Context, accountID, deviceID string) (*GetResult[Device], error) {
	return accessGet[Device](ctx, c, devicePath(accountID, "", deviceID, ""))
}

// PhysicalDeviceQuery carries the supported fleet list filters.
type PhysicalDeviceQuery struct {
	IDs                 []string
	Search              string
	ActiveRegistrations string
	LastSeenUser        string
	SortBy              string
	SortOrder           string
	SeenAfter           string
	SeenBefore          string
}

// ListPhysicalDevices lists the device fleet (cursor pagination).
func (c *Client) ListPhysicalDevices(ctx context.Context, accountID string, q PhysicalDeviceQuery, pol pagination.Policy) (*ListResult[PhysicalDevice], error) {
	if err := pol.Validate(); err != nil {
		return nil, errors.Usage("%s", err.Error())
	}
	limit := pageSize(pol)
	path := devicePath(accountID, "physical-devices", "", "")

	var (
		items    []PhysicalDevice
		rawItems []json.RawMessage
		bodies   [][]byte
		cursor   string
		guard    = pagination.NewCursorGuard()
	)
	count := func() int {
		if c.raw {
			return len(rawItems)
		}
		return len(items)
	}
	for {
		if err := guard.Step(cursor); err != nil {
			return nil, err
		}
		query := url.Values{}
		query.Set("per_page", strconv.Itoa(limit))
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		for _, id := range q.IDs {
			query.Add("id", id)
		}
		if q.Search != "" {
			query.Set("search", q.Search)
		}
		if q.ActiveRegistrations != "" {
			query.Set("active_registrations", q.ActiveRegistrations)
		}
		if q.LastSeenUser != "" {
			query.Set("last_seen_user", q.LastSeenUser)
		}
		if q.SortBy != "" {
			query.Set("sort_by", q.SortBy)
		}
		if q.SortOrder != "" {
			query.Set("sort_order", q.SortOrder)
		}
		if q.SeenAfter != "" {
			query.Set("seen_after", q.SeenAfter)
		}
		if q.SeenBefore != "" {
			query.Set("seen_before", q.SeenBefore)
		}
		env, raw, err := c.requestJSON(ctx, "GET", path, query, nil, "")
		if err != nil {
			return nil, err
		}
		bodies = append(bodies, raw)
		var page struct {
			Result []json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, errors.Wrap(errors.CodeUnclassified, "decoding device list page", err)
		}
		for _, itemRaw := range page.Result {
			if c.raw {
				rawItems = append(rawItems, itemRaw)
				continue
			}
			var d PhysicalDevice
			if err := json.Unmarshal(itemRaw, &d); err != nil {
				return nil, errors.Wrap(errors.CodeUnclassified, "decoding device", err)
			}
			items = append(items, d)
		}
		cursor = nextCursor(env.ResultInfo)
		if pol.NoPaginate || cursor == "" || (pol.MaxItems > 0 && count() >= pol.MaxItems) || len(page.Result) == 0 {
			break
		}
	}
	if pol.MaxItems > 0 {
		if c.raw && len(rawItems) > pol.MaxItems {
			rawItems = rawItems[:pol.MaxItems]
		}
		if !c.raw && len(items) > pol.MaxItems {
			items = items[:pol.MaxItems]
		}
	}
	if c.raw {
		if len(bodies) == 1 && pol.MaxItems == 0 {
			return &ListResult[PhysicalDevice]{RawBody: bodies[0]}, nil
		}
		merged, err := json.Marshal(map[string]any{
			"success": true, "errors": []any{}, "messages": []any{},
			"result":      rawItems,
			"result_info": map[string]any{"count": len(rawItems)},
		})
		if err != nil {
			return nil, err
		}
		return &ListResult[PhysicalDevice]{RawBody: merged}, nil
	}
	return &ListResult[PhysicalDevice]{Items: items}, nil
}

// GetPhysicalDevice fetches one fleet device.
func (c *Client) GetPhysicalDevice(ctx context.Context, accountID, deviceID string) (*GetResult[PhysicalDevice], error) {
	return accessGet[PhysicalDevice](ctx, c, devicePath(accountID, "physical-devices", deviceID, ""))
}

// DeletePhysicalDevice deletes a fleet device (DELETE, idempotent).
func (c *Client) DeletePhysicalDevice(ctx context.Context, accountID, deviceID string) error {
	return accessDelete(ctx, c, devicePath(accountID, "physical-devices", deviceID, ""))
}

// RevokePhysicalDevice revokes a fleet device's registrations (POST).
func (c *Client) RevokePhysicalDevice(ctx context.Context, accountID, deviceID string) error {
	_, _, err := c.requestJSON(ctx, "POST", devicePath(accountID, "physical-devices", deviceID, "revoke"), nil, nil, "")
	return err
}

// ---- device posture rules -------------------------------------------------

// ListDevicePostureRules lists posture rules (not paginated).
func (c *Client) ListDevicePostureRules(ctx context.Context, accountID string, pol pagination.Policy) (*ListResult[DevicePostureRule], error) {
	return singlePageList[DevicePostureRule](ctx, c, devicePath(accountID, "posture", "", ""), nil, pol)
}

// GetDevicePostureRule fetches one posture rule.
func (c *Client) GetDevicePostureRule(ctx context.Context, accountID, ruleID string) (*GetResult[DevicePostureRule], error) {
	return accessGet[DevicePostureRule](ctx, c, devicePath(accountID, "posture", ruleID, ""))
}

// CreateDevicePostureRule creates a posture rule (POST).
func (c *Client) CreateDevicePostureRule(ctx context.Context, accountID string, body map[string]any) (*GetResult[DevicePostureRule], error) {
	return accessCreate[DevicePostureRule](ctx, c, devicePath(accountID, "posture", "", ""), body)
}

// UpdateDevicePostureRule patches a posture rule by read-modify-PUT.
func (c *Client) UpdateDevicePostureRule(ctx context.Context, accountID, ruleID string, overrides map[string]any) (*GetResult[DevicePostureRule], error) {
	return accessMergeUpdate[DevicePostureRule](ctx, c, devicePath(accountID, "posture", ruleID, ""), overrides)
}

// DeleteDevicePostureRule deletes a posture rule (DELETE, idempotent).
func (c *Client) DeleteDevicePostureRule(ctx context.Context, accountID, ruleID string) error {
	return accessDelete(ctx, c, devicePath(accountID, "posture", ruleID, ""))
}

// ---- device settings ------------------------------------------------------

// deviceSettingsBase extracts the settings object from a GET result, accepting
// both the flat and the wrapped envelope shape.
func deviceSettingsBase(result json.RawMessage) (map[string]any, error) {
	var decoded map[string]any
	if err := json.Unmarshal(result, &decoded); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding device settings", err)
	}
	if inner, ok := decoded["device_settings"].(map[string]any); ok {
		return inner, nil
	}
	return decoded, nil
}

// GetDeviceSettings reads the account device settings. The result is returned
// untyped so every field the API exposes survives normalization.
func (c *Client) GetDeviceSettings(ctx context.Context, accountID string) (*GetResult[map[string]any], error) {
	env, raw, err := c.requestJSON(ctx, "GET", devicePath(accountID, "settings", "", ""), nil, nil, "")
	if err != nil {
		return nil, err
	}
	base, err := deviceSettingsBase(env.Result)
	if err != nil {
		return nil, err
	}
	return &GetResult[map[string]any]{Item: base, RawBody: raw}, nil
}

// UpdateDeviceSettings merges overrides onto the current settings and PUTs the
// result, so fields this CLI does not model are preserved.
func (c *Client) UpdateDeviceSettings(ctx context.Context, accountID string, overrides map[string]any) (*GetResult[map[string]any], error) {
	if len(overrides) == 0 {
		return nil, errors.Usage("nothing to update")
	}
	env, _, err := c.requestJSON(ctx, "GET", devicePath(accountID, "settings", "", ""), nil, nil, "")
	if err != nil {
		return nil, err
	}
	base, err := deviceSettingsBase(env.Result)
	if err != nil {
		return nil, err
	}
	for k, v := range overrides {
		base[k] = v
	}
	payload, err := json.Marshal(map[string]any{"device_settings": base})
	if err != nil {
		return nil, err
	}
	putEnv, raw, err := c.requestJSON(ctx, "PUT", devicePath(accountID, "settings", "", ""), nil, payload, "application/json")
	if err != nil {
		return nil, err
	}
	result, err := deviceSettingsBase(putEnv.Result)
	if err != nil {
		return nil, err
	}
	return &GetResult[map[string]any]{Item: result, RawBody: raw}, nil
}
