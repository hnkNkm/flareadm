package cloudflare

import (
	"context"
	"net/url"
	"strconv"

	"github.com/hnkNkm/flareadm/internal/pagination"
)

// AuditLogQuery carries the supported audit log filters.
type AuditLogQuery struct {
	Since        string
	Before       string
	Action       string
	Actor        string
	Zone         string
	Direction    string
	ID           string
	HideUserLogs bool
}

// ListAuditLogs lists account audit logs (page pagination).
func (c *Client) ListAuditLogs(ctx context.Context, accountID string, q AuditLogQuery, pol pagination.Policy) (*ListResult[AuditLog], error) {
	query := url.Values{}
	for _, item := range []struct{ key, value string }{
		{"since", q.Since}, {"before", q.Before}, {"action", q.Action}, {"actor", q.Actor},
		{"zone", q.Zone}, {"direction", q.Direction}, {"id", q.ID},
	} {
		if item.value != "" {
			query.Set(item.key, item.value)
		}
	}
	if q.HideUserLogs {
		query.Set("hide_user_logs", strconv.FormatBool(true))
	}
	return listTyped[AuditLog](ctx, c, listQuery{path: "/accounts/" + url.PathEscape(accountID) + "/audit_logs", q: query, pol: pol})
}
