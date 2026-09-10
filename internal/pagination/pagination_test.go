package pagination

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// fakeFetch serves pages from a static map with optional metadata.
func fakeFetch(pages map[int][]int, meta PageMeta) FetchFunc[int] {
	return func(ctx context.Context, page int) ([]int, PageMeta, error) {
		items, ok := pages[page]
		if !ok {
			return nil, meta, nil
		}
		return items, meta, nil
	}
}

func collect(t *testing.T, pol Policy, pages map[int][]int, meta PageMeta) ([]int, []Page[int], error) {
	t.Helper()
	return Collect(context.Background(), pol, fakeFetch(pages, meta))
}

func TestCollectAutoPaginates(t *testing.T) {
	pages := map[int][]int{
		1: {1, 2}, 2: {3, 4}, 3: {}, // 3rd page empty ends the loop
	}
	items, fetched, err := collect(t, Policy{PageSize: 2}, pages, PageMeta{RequestedPageSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 4 || items[0] != 1 || items[3] != 4 {
		t.Fatalf("items = %v", items)
	}
	if len(fetched) != 3 {
		t.Fatalf("pages fetched = %d, want 3 (incl. trailing empty page)", len(fetched))
	}
}

func TestCollectNoPaginate(t *testing.T) {
	pages := map[int][]int{1: {1, 2}, 2: {3}}
	items, fetched, err := collect(t, Policy{PageSize: 2, NoPaginate: true}, pages, PageMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || len(fetched) != 1 {
		t.Fatalf("items=%v pages=%d", items, len(fetched))
	}
}

func TestCollectMaxItemsTruncatesAcrossPages(t *testing.T) {
	pages := map[int][]int{1: {1, 2}, 2: {3, 4}, 3: {5, 6}}
	items, fetched, err := collect(t, Policy{PageSize: 2, MaxItems: 5}, pages, PageMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 5 || items[4] != 5 {
		t.Fatalf("items = %v", items)
	}
	if len(fetched) != 3 {
		t.Fatalf("fetched %d pages, want 3", len(fetched))
	}
}

func TestCollectMaxItemsInsideOnePage(t *testing.T) {
	pages := map[int][]int{1: {1, 2, 3, 4}}
	items, _, err := collect(t, Policy{PageSize: 10, MaxItems: 2}, pages, PageMeta{RequestedPageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0] != 1 || items[1] != 2 {
		t.Fatalf("items = %v", items)
	}
}

func TestCollectShortPageTerminates(t *testing.T) {
	// A full first page followed by a short second page: the short page is
	// the last one, so no further request may be made (without this rule an
	// always-full response would loop forever).
	full := make([]int, 100)
	for i := range full {
		full[i] = i
	}
	short := []int{100, 101, 102}
	calls := 0
	items, fetched, err := Collect(context.Background(), Policy{PageSize: 100}, func(ctx context.Context, page int) ([]int, PageMeta, error) {
		calls++
		switch page {
		case 1:
			return full, PageMeta{RequestedPageSize: 100}, nil
		case 2:
			return short, PageMeta{RequestedPageSize: 100}, nil
		default:
			t.Fatalf("unexpected page %d request", page)
			return nil, PageMeta{}, nil
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(fetched) != 2 || len(items) != 103 {
		t.Fatalf("calls=%d pages=%d items=%d, want 2 pages / 103 items", calls, len(fetched), len(items))
	}
}

func TestCollectTotalPagesTerminates(t *testing.T) {
	// Full page forever, but result_info says there is exactly one page.
	calls := 0
	items, fetched, err := Collect(context.Background(), Policy{PageSize: 2}, func(ctx context.Context, page int) ([]int, PageMeta, error) {
		calls++
		return []int{1, 2}, PageMeta{RequestedPageSize: 2, TotalPages: 1}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(fetched) != 1 || len(items) != 2 {
		t.Fatalf("calls=%d pages=%d items=%v", calls, len(fetched), items)
	}
}

func TestCollectCursorExhaustionTerminates(t *testing.T) {
	calls := 0
	items, _, err := Collect(context.Background(), Policy{PageSize: 2}, func(ctx context.Context, page int) ([]int, PageMeta, error) {
		calls++
		// A full page with no next cursor: cursor pagination is done.
		return []int{1, 2}, PageMeta{RequestedPageSize: 2, CursorBased: true, NextCursor: ""}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(items) != 2 {
		t.Fatalf("calls=%d items=%v", calls, items)
	}
}

func TestCollectHardCapFailsInsteadOfLooping(t *testing.T) {
	// No result_info, no short pages, no empty page: only the cap stops it.
	calls := 0
	_, _, err := Collect(context.Background(), Policy{PageSize: 2}, func(ctx context.Context, page int) ([]int, PageMeta, error) {
		calls++
		return []int{1, 2}, PageMeta{RequestedPageSize: 2}, nil
	})
	if err == nil {
		t.Fatal("expected the safety cap to fail the loop")
	}
	if !errors.Is(err, ErrPageLimitExceeded) {
		t.Fatalf("err = %v, want ErrPageLimitExceeded", err)
	}
	if calls != MaxPages {
		t.Fatalf("calls = %d, want exactly MaxPages (%d)", calls, MaxPages)
	}
}

func TestCollectErrorPropagates(t *testing.T) {
	boom := errors.New("boom")
	fetch := func(ctx context.Context, page int) ([]int, PageMeta, error) {
		if page == 2 {
			return nil, PageMeta{}, boom
		}
		return []int{1}, PageMeta{}, nil
	}
	_, _, err := Collect(context.Background(), Policy{PageSize: 1}, fetch)
	if err != boom {
		t.Fatalf("err = %v", err)
	}
}

func TestCollectEmptyFirstPage(t *testing.T) {
	items, _, err := collect(t, Policy{PageSize: 10}, map[int][]int{1: {}}, PageMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("items = %v", items)
	}
}

func TestPolicyValidation(t *testing.T) {
	if err := (Policy{PageSize: -1}).Validate(); err == nil {
		t.Error("negative page size must fail")
	}
	if err := (Policy{MaxItems: -1}).Validate(); err == nil {
		t.Error("negative max items must fail")
	}
	if err := (Policy{PageSize: 0, MaxItems: 0}).Validate(); err != nil {
		t.Errorf("defaults must validate: %v", err)
	}
}

func TestCursorGuardRepeatedCursorFails(t *testing.T) {
	g := NewCursorGuard()
	if err := g.Step(""); err != nil {
		t.Fatalf("first page: %v", err)
	}
	if err := g.Step("c2"); err != nil {
		t.Fatalf("second page: %v", err)
	}
	err := g.Step("c2") // the API is not advancing
	if !errors.Is(err, ErrPageLimitExceeded) {
		t.Fatalf("err = %v, want ErrPageLimitExceeded", err)
	}
}

func TestCursorGuardBoundsLoop(t *testing.T) {
	g := NewCursorGuard()
	for i := 0; i < MaxPages; i++ {
		cursor := ""
		if i > 0 {
			cursor = fmt.Sprintf("cursor-%d", i)
		}
		if err := g.Step(cursor); err != nil {
			t.Fatalf("page %d: %v", i+1, err)
		}
	}
	if err := g.Step("cursor-final"); !errors.Is(err, ErrPageLimitExceeded) {
		t.Fatalf("err = %v, want ErrPageLimitExceeded", err)
	}
}
