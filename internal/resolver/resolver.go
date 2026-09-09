// Package resolver centralizes account and zone resolution so every service
// shares identical semantics (docs/configuration.md).
//
// Account resolution order:
//
//  1. --account-id;
//  2. profile account_id;
//  3. FLAREADM_ACCOUNT_ID;
//  4. automatic discovery when exactly one accessible account exists.
//
// Multiple accessible accounts without an explicit choice fail with a useful
// error rather than silently choosing one.
//
// Zone resolution accepts either a zone ID or a zone name; names are looked
// up server-side and cached per resolver instance.
package resolver

import (
	"context"
	"fmt"
	"strings"

	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/config"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/pagination"
)

// AccountEnvVar is the environment variable that can supply the account id.
const AccountEnvVar = "FLAREADM_ACCOUNT_ID"

// AccountRef is a resolved account identifier and where it came from.
type AccountRef struct {
	ID     string
	Name   string
	Source string
}

// Account resolves the account id for a command, honoring the documented
// precedence. explicit is the --account-id flag value ("" when absent);
// profile is the active profile (may be nil).
func Account(ctx context.Context, c *cloudflare.Client, explicit string, profile *config.Profile, env func(string) string) (AccountRef, error) {
	if explicit != "" {
		return AccountRef{ID: explicit, Source: "--account-id"}, nil
	}
	if profile != nil && profile.AccountID != "" {
		return AccountRef{ID: profile.AccountID, Source: "profile account_id"}, nil
	}
	if v := env(AccountEnvVar); v != "" {
		return AccountRef{ID: v, Source: AccountEnvVar}, nil
	}

	// Discovery: exactly one accessible account.
	list, err := c.ListAccounts(ctx, pagination.Policy{PageSize: 50, MaxItems: 100})
	if err != nil {
		return AccountRef{}, err
	}
	accounts := list.Items
	switch len(accounts) {
	case 0:
		return AccountRef{}, errors.New(errors.CodePermission,
			"no Cloudflare accounts are accessible with the current token; "+
				"check the token's account permissions or select an account with --account-id")
	case 1:
		return AccountRef{ID: accounts[0].ID, Name: accounts[0].Name, Source: "account discovery"}, nil
	default:
		var names []string
		for _, a := range accounts {
			names = append(names, fmt.Sprintf("%s (%s)", a.Name, a.ID))
		}
		return AccountRef{}, errors.New(errors.CodeInvalid,
			"multiple Cloudflare accounts are accessible (%s); "+
				"select one with --account-id or a profile account_id", strings.Join(names, ", "))
	}
}

// ZoneID validates that ref is a zone id (32 lowercase hex chars).
func ZoneID(ref string) bool { return cloudflare.ValidID(ref) }

// Zone resolves a zone reference (id or name) to a zone ID. References that
// are already 32-character hex ids pass through; names are resolved with a
// server-side exact-name lookup. Resolved names are cached.
type Zone struct {
	client *cloudflare.Client
	cache  map[string]string
}

// NewZone builds a zone resolver over a Cloudflare client.
func NewZone(c *cloudflare.Client) *Zone {
	return &Zone{client: c, cache: map[string]string{}}
}

// Resolve maps a zone reference to a zone ID.
func (z *Zone) Resolve(ctx context.Context, ref string) (string, error) {
	if ref == "" {
		return "", errors.Usage("a zone is required (--zone <name-or-id> or a profile default_zone)")
	}
	if ZoneID(ref) {
		return ref, nil
	}
	if id, ok := z.cache[ref]; ok {
		return id, nil
	}
	res, err := z.client.ListZones(ctx, cloudflare.ZoneListQuery{Name: ref},
		pagination.Policy{PageSize: 50, MaxItems: 100})
	if err != nil {
		return "", err
	}
	switch len(res.Items) {
	case 0:
		return "", errors.New(errors.CodeNotFound, "zone %q not found", ref)
	case 1:
		z.cache[ref] = res.Items[0].ID
		return res.Items[0].ID, nil
	default:
		var ids []string
		for _, zone := range res.Items {
			ids = append(ids, zone.ID)
		}
		return "", errors.New(errors.CodeInvalid,
			"zone name %q is ambiguous (matches %s); pass the zone id instead",
			ref, strings.Join(ids, ", "))
	}
}
