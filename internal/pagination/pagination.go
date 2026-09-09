// Package pagination implements FlareADM's centralized pagination semantics
// for list commands:
//
//   - auto-pagination is the default: pages are fetched until the API
//     returns an empty page (or result_info.total_pages is reached);
//   - --page-size controls the per-page request size;
//   - --max-items caps how many items are collected (fetching stops as soon
//     as the cap is reached; a cap of 0 means unlimited);
//   - --no-paginate fetches only the first page.
package pagination

import (
	"context"
	"fmt"
)

// Policy captures the pagination flags for one list operation.
type Policy struct {
	PageSize   int
	MaxItems   int
	NoPaginate bool
}

// DefaultPageSize is used when --page-size is not given.
const DefaultPageSize = 100

// Validate checks flag values. PageSize == 0 selects the default page size;
// MaxItems == 0 means "no limit".
func (p Policy) Validate() error {
	if p.PageSize < 0 {
		return fmt.Errorf("--page-size must be >= 1 (got %d)", p.PageSize)
	}
	if p.MaxItems < 0 {
		return fmt.Errorf("--max-items must be >= 0 (got %d)", p.MaxItems)
	}
	return nil
}

// FetchFunc fetches one page. It receives the 1-based page number and
// returns that page's items. The returned slice length is used to detect the
// end of the result set.
type FetchFunc[T any] func(ctx context.Context, page int) ([]T, error)

// Page is one fetched page together with the request page number.
type Page[T any] struct {
	Number int
	Items  []T
}

// Collect runs the pagination loop per the policy and returns the collected
// items plus the raw fetched pages (used by --raw list output).
func Collect[T any](ctx context.Context, pol Policy, fetch FetchFunc[T]) (items []T, pages []Page[T], err error) {
	if err := pol.Validate(); err != nil {
		return nil, nil, err
	}

	for pageNum := 1; ; pageNum++ {
		pageItems, err := fetch(ctx, pageNum)
		if err != nil {
			return nil, pages, err
		}
		pages = append(pages, Page[T]{Number: pageNum, Items: pageItems})
		items = append(items, pageItems...)

		if pol.NoPaginate || len(pageItems) == 0 {
			break
		}
		if pol.MaxItems > 0 && len(items) >= pol.MaxItems {
			break
		}
	}
	if pol.MaxItems > 0 && len(items) > pol.MaxItems {
		items = items[:pol.MaxItems]
	}
	return items, pages, nil
}
