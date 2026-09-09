package cloudflare

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/hnkNkm/flareadm/internal/errors"
)

// PurgeTargets describes one cache purge request. Exactly one kind of purge
// is expressed per call (PurgeEverything or one of the scoped lists).
type PurgeTargets struct {
	PurgeEverything bool
	Files           []string // full URLs
	Hosts           []string // hostnames
	Tags            []string // cache tags
	Prefixes        []string // URL prefixes
}

// PurgeCache purges the zone cache (POST; never automatically retried).
func (c *Client) PurgeCache(ctx context.Context, zoneID string, t PurgeTargets) (*GetResult[PurgeResult], error) {
	body, err := buildPurgeBody(t)
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "POST", "/zones/"+url.PathEscape(zoneID)+"/purge_cache", nil, body, "application/json")
	if err != nil {
		return nil, err
	}
	var item PurgeResult
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding purge response", err)
	}
	return &GetResult[PurgeResult]{Item: item, RawBody: raw}, nil
}

func buildPurgeBody(t PurgeTargets) ([]byte, error) {
	count := 0
	if t.PurgeEverything {
		count++
	}
	for _, l := range [][]string{t.Files, t.Hosts, t.Tags, t.Prefixes} {
		if len(l) > 0 {
			count++
		}
	}
	switch count {
	case 0:
		return nil, errors.Usage("specify something to purge: --everything, or one of --files, --hosts, --tags, --prefixes")
	case 1:
	default:
		return nil, errors.Usage("purge targets are mutually exclusive: choose --everything or one of --files, --hosts, --tags, --prefixes")
	}
	m := map[string]any{}
	switch {
	case t.PurgeEverything:
		m["purge_everything"] = true
	case len(t.Files) > 0:
		m["files"] = t.Files
	case len(t.Hosts) > 0:
		m["hosts"] = t.Hosts
	case len(t.Tags) > 0:
		m["tags"] = t.Tags
	case len(t.Prefixes) > 0:
		m["prefixes"] = t.Prefixes
	}
	return json.Marshal(m)
}
