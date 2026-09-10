// Package pagination implements FlareADM's centralized pagination semantics
// for list commands:
//
//   - auto-pagination is the default: pages are fetched until a terminal
//     condition is reached;
//   - --page-size controls the per-page request size;
//   - --max-items caps how many items are collected (fetching stops as soon
//     as the cap is reached; a cap of 0 means unlimited);
//   - --no-paginate fetches only the first page.
//
// A page loop terminates deterministically on the first of:
//
//   - an empty page (no items returned);
//   - a short page: fewer items than the page size actually requested
//     (PageMeta.RequestedPageSize), which marks the last page for APIs that
//     clamp per-page server-side;
//   - total_pages: page >= result_info.total_pages when the API reports it;
//   - cursor exhaustion: a cursor-based endpoint that reports no next cursor;
//   - --max-items reached.
//
// As a defense against APIs that never reach a terminal condition (for
// example always returning a full page without result_info, or repeating the
// same cursor), every loop is additionally bounded by MaxPages; exceeding it
// fails with ErrPageLimitExceeded and a diagnostic instead of looping
// forever.
package pagination

import (
	"context"
	"errors"
	"fmt"
)

// DefaultPageSize is used when --page-size is not given.
const DefaultPageSize = 100

// MaxPages is the hard safety cap for any single pagination loop. A loop
// that reaches this many pages without a terminal condition fails with
// ErrPageLimitExceeded rather than issuing unbounded requests.
const MaxPages = 1000

// ErrPageLimitExceeded reports that a pagination loop exceeded MaxPages or
// repeated a cursor without advancing.
var ErrPageLimitExceeded = errors.New("pagination safety limit exceeded")

func limitError(pages int, detail string) error {
	return fmt.Errorf("%w after %d pages: %s; narrow the request with --max-items or --page-size, "+
		"or use --no-paginate with manual paging", ErrPageLimitExceeded, pages, detail)
}

// Policy captures the pagination flags for one list operation.
type Policy struct {
	PageSize   int
	MaxItems   int
	NoPaginate bool
}

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

// PageMeta describes the pagination state of one fetched page. Zero values
// mean "unknown / not applicable" and disable that stop condition.
type PageMeta struct {
	// RequestedPageSize is the per-page size the caller asked for (not the
	// size the server clamped to). When the returned page is shorter, the
	// loop stops.
	RequestedPageSize int
	// TotalPages comes from result_info.total_pages when the API reports it.
	TotalPages int64
	// CursorBased marks cursor-paginated endpoints; NextCursor is the cursor
	// for the following page ("" means exhausted).
	CursorBased bool
	NextCursor  string
}

// FetchFunc fetches one page. It receives the 1-based page number and
// returns that page's items plus its pagination metadata.
type FetchFunc[T any] func(ctx context.Context, page int) ([]T, PageMeta, error)

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
	requestedPageSize := pol.PageSize
	if requestedPageSize <= 0 {
		requestedPageSize = DefaultPageSize
	}

	for pageNum := 1; ; pageNum++ {
		if pageNum > MaxPages {
			return nil, pages, limitError(pageNum-1, "the API never returned a terminal page")
		}
		pageItems, meta, err := fetch(ctx, pageNum)
		if err != nil {
			return nil, pages, err
		}
		pages = append(pages, Page[T]{Number: pageNum, Items: pageItems})
		items = append(items, pageItems...)

		if pol.NoPaginate {
			break
		}
		if len(pageItems) == 0 {
			break // empty page
		}
		size := meta.RequestedPageSize
		if size <= 0 {
			size = requestedPageSize
		}
		if len(pageItems) < size {
			break // short page: the server returned less than requested
		}
		if meta.TotalPages > 0 && int64(pageNum) >= meta.TotalPages {
			break // reached the advertised last page
		}
		if meta.CursorBased && meta.NextCursor == "" {
			break // cursor pagination exhausted
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

// CursorGuard bounds a manual cursor pagination loop: it fails when the loop
// exceeds MaxPages or when the API repeats a cursor without advancing.
type CursorGuard struct {
	pages int
	seen  map[string]bool
}

// NewCursorGuard creates a guard for one cursor pagination loop.
func NewCursorGuard() *CursorGuard {
	return &CursorGuard{seen: map[string]bool{}}
}

// Step records the cursor about to be used for the next request ("" for the
// first page) and reports an error when the loop cannot make progress.
func (g *CursorGuard) Step(cursor string) error {
	g.pages++
	if g.pages > MaxPages {
		return limitError(g.pages-1, "cursor pagination never exhausted")
	}
	if cursor == "" {
		return nil
	}
	if g.seen[cursor] {
		return limitError(g.pages, "the API repeated the same cursor without advancing")
	}
	g.seen[cursor] = true
	return nil
}
