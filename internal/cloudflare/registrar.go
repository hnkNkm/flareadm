package cloudflare

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"

	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/pagination"
)

func registrarPath(accountID, resource, name string) string {
	p := "/accounts/" + url.PathEscape(accountID) + "/registrar/" + resource
	if name != "" {
		p += "/" + url.PathEscape(name)
	}
	return p
}

// ListRegistrarDomains lists the registrar domain inventory (not paginated).
func (c *Client) ListRegistrarDomains(ctx context.Context, accountID string, pol pagination.Policy) (*ListResult[RegistrarDomain], error) {
	return singlePageList[RegistrarDomain](ctx, c, registrarPath(accountID, "domains", ""), nil, pol)
}

// GetRegistrarDomain fetches one domain. The API response is untyped.
func (c *Client) GetRegistrarDomain(ctx context.Context, accountID, domainName string) (*GetResult[json.RawMessage], error) {
	env, raw, err := c.requestJSON(ctx, "GET", registrarPath(accountID, "domains", domainName), nil, nil, "")
	if err != nil {
		return nil, err
	}
	return &GetResult[json.RawMessage]{Item: env.Result, RawBody: raw}, nil
}

// UpdateRegistrarDomain patches a domain by read-modify-PUT (the API replaces
// the object, and the untyped GET keeps unmodeled fields).
func (c *Client) UpdateRegistrarDomain(ctx context.Context, accountID, domainName string, overrides map[string]any) (*GetResult[json.RawMessage], error) {
	if len(overrides) == 0 {
		return nil, errors.Usage("nothing to update")
	}
	env, _, err := c.requestJSON(ctx, "GET", registrarPath(accountID, "domains", domainName), nil, nil, "")
	if err != nil {
		return nil, err
	}
	current := map[string]any{}
	if err := json.Unmarshal(env.Result, &current); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding registrar domain", err)
	}
	for k, v := range overrides {
		current[k] = v
	}
	payload, err := json.Marshal(current)
	if err != nil {
		return nil, err
	}
	putEnv, raw, err := c.requestJSON(ctx, "PUT", registrarPath(accountID, "domains", domainName), nil, payload, "application/json")
	if err != nil {
		return nil, err
	}
	return &GetResult[json.RawMessage]{Item: putEnv.Result, RawBody: raw}, nil
}

// RegistrarRegistrationQuery carries the registration list filters.
type RegistrarRegistrationQuery struct {
	Direction string
	SortBy    string
}

// ListRegistrarRegistrations lists registrations (cursor pagination).
func (c *Client) ListRegistrarRegistrations(ctx context.Context, accountID string, q RegistrarRegistrationQuery, pol pagination.Policy) (*ListResult[RegistrarRegistration], error) {
	if err := pol.Validate(); err != nil {
		return nil, errors.Usage("%s", err.Error())
	}
	limit := pageSize(pol)
	path := registrarPath(accountID, "registrations", "")

	var (
		items    []RegistrarRegistration
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
		if q.Direction != "" {
			query.Set("direction", q.Direction)
		}
		if q.SortBy != "" {
			query.Set("sort_by", q.SortBy)
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
			return nil, errors.Wrap(errors.CodeUnclassified, "decoding registration list page", err)
		}
		for _, itemRaw := range page.Result {
			if c.raw {
				rawItems = append(rawItems, itemRaw)
				continue
			}
			var item RegistrarRegistration
			if err := json.Unmarshal(itemRaw, &item); err != nil {
				return nil, errors.Wrap(errors.CodeUnclassified, "decoding registration", err)
			}
			items = append(items, item)
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
			return &ListResult[RegistrarRegistration]{RawBody: bodies[0]}, nil
		}
		merged, err := json.Marshal(map[string]any{
			"success": true, "errors": []any{}, "messages": []any{},
			"result":      rawItems,
			"result_info": map[string]any{"count": len(rawItems)},
		})
		if err != nil {
			return nil, err
		}
		return &ListResult[RegistrarRegistration]{RawBody: merged}, nil
	}
	return &ListResult[RegistrarRegistration]{Items: items}, nil
}

// GetRegistrarRegistration fetches one registration.
func (c *Client) GetRegistrarRegistration(ctx context.Context, accountID, domainName string) (*GetResult[RegistrarRegistration], error) {
	return accessGet[RegistrarRegistration](ctx, c, registrarPath(accountID, "registrations", domainName))
}

// UpdateRegistrarRegistration partially updates a registration (PATCH).
func (c *Client) UpdateRegistrarRegistration(ctx context.Context, accountID, domainName string, overrides map[string]any) (*GetResult[RegistrarRegistration], error) {
	return mergePatch[RegistrarRegistration](ctx, c, registrarPath(accountID, "registrations", domainName), overrides)
}
