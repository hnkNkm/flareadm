package logs

import (
	"context"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
)

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
