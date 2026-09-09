package pagination

import (
	"context"
	"errors"
	"testing"
)

// fakeFetch serves pages from a static map.
func fakeFetch(pages map[int][]int) FetchFunc[int] {
	return func(ctx context.Context, page int) ([]int, error) {
		items, ok := pages[page]
		if !ok {
			return nil, nil
		}
		return items, nil
	}
}

func collect(t *testing.T, pol Policy, pages map[int][]int) ([]int, []Page[int], error) {
	t.Helper()
	return Collect(context.Background(), pol, fakeFetch(pages))
}

func TestCollectAutoPaginates(t *testing.T) {
	pages := map[int][]int{
		1: {1, 2}, 2: {3, 4}, 3: {}, // 3rd page empty ends the loop
	}
	items, fetched, err := collect(t, Policy{PageSize: 2}, pages)
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
	items, fetched, err := collect(t, Policy{PageSize: 2, NoPaginate: true}, pages)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("items = %v", items)
	}
	if len(fetched) != 1 {
		t.Fatalf("no-paginate fetched %d pages", len(fetched))
	}
}

func TestCollectMaxItemsTruncatesAcrossPages(t *testing.T) {
	pages := map[int][]int{
		1: {1, 2}, 2: {3, 4}, 3: {5, 6},
	}
	items, fetched, err := collect(t, Policy{PageSize: 2, MaxItems: 5}, pages)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 5 || items[4] != 5 {
		t.Fatalf("items = %v", items)
	}
	// The cap is reached inside page 3; the loop stops without fetching
	// page 4.
	if len(fetched) != 3 {
		t.Fatalf("fetched %d pages, want 3", len(fetched))
	}
}

func TestCollectMaxItemsInsideOnePage(t *testing.T) {
	pages := map[int][]int{1: {1, 2, 3, 4}}
	items, _, err := collect(t, Policy{PageSize: 10, MaxItems: 2}, pages)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0] != 1 || items[1] != 2 {
		t.Fatalf("items = %v", items)
	}
}

func TestCollectErrorPropagates(t *testing.T) {
	boom := errors.New("boom")
	fetch := func(ctx context.Context, page int) ([]int, error) {
		if page == 2 {
			return nil, boom
		}
		return []int{1}, nil
	}
	_, _, err := Collect(context.Background(), Policy{PageSize: 1}, fetch)
	if err != boom {
		t.Fatalf("err = %v", err)
	}
}

func TestCollectEmptyFirstPage(t *testing.T) {
	items, _, err := collect(t, Policy{PageSize: 10}, map[int][]int{1: {}})
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
