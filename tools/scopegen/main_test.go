package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// generatedPath is the file the committed catalog lives in, relative to this
// package dir (tests run with the package dir as the working directory).
const generatedPath = "../../cmd/auth/scopes_generated.go"

// testdataPath is the committed capture of GET /oauth/scopes.
const testdataPath = "testdata/oauth_scopes.json"

// TestGenerateIsDeterministicAndFresh regenerates the catalog from the committed
// capture and requires byte-identical output, twice and against the checked-in
// file. The second comparison is what makes stale catalogs impossible: editing
// the capture without regenerating fails here.
func TestGenerateIsDeterministicAndFresh(t *testing.T) {
	raw, err := os.ReadFile(testdataPath)
	if err != nil {
		t.Fatal(err)
	}
	first, err := generate(raw)
	if err != nil {
		t.Fatal(err)
	}
	second, err := generate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("generator is not deterministic: %d vs %d bytes", len(first), len(second))
	}
	if len(first) == 0 {
		t.Fatal("generator produced no output")
	}
	if !bytes.HasPrefix(first, []byte(header)) {
		t.Fatalf("missing generated header:\n%s", head(first, 3))
	}
	committed, err := os.ReadFile(filepath.FromSlash(generatedPath))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, committed) {
		t.Fatalf("%s is stale: regenerate with\n  go run ./tools/scopegen -in %s -out %s",
			generatedPath, defaultTestdata, filepath.ToSlash(generatedPath))
	}
}

// TestGenerateCounts pins the captured list's size so a regeneration that loses
// scopes cannot pass unnoticed.
func TestGenerateCounts(t *testing.T) {
	raw, err := os.ReadFile(testdataPath)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 385 {
		t.Fatalf("captured scopes = %d, want 385", len(entries))
	}
	categories := map[string]bool{}
	for _, entry := range entries {
		if entry.Category == "" {
			t.Fatalf("scope %q has no category", entry.ID)
		}
		categories[entry.Category] = true
	}
	if len(categories) != 13 {
		t.Fatalf("captured categories = %d, want 13", len(categories))
	}
}

// TestGenerateRejectsBadInput: the generator refuses input it cannot represent
// faithfully instead of writing a partial catalog.
func TestGenerateRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"empty":         `{"result":[]}`,
		"not json":      `not json at all`,
		"missing id":    `{"result":[{"name":"No id","category":"other"}]}`,
		"duplicate id":  `{"result":[{"id":"a.read","category":"x"},{"id":"a.read","category":"y"}]}`,
		"bare array ok": `[{"id":"a.read","category":"x"}]`,
	}
	for name, input := range cases {
		_, err := generate([]byte(input))
		wantErr := name != "bare array ok"
		if wantErr && err == nil {
			t.Fatalf("%s: expected an error", name)
		}
		if !wantErr && err != nil {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}
	}
}

// TestGenerateGroupsAndSorts: categories and ids come out sorted regardless of
// input order.
func TestGenerateGroupsAndSorts(t *testing.T) {
	out, err := generate([]byte(`{"result":[
		{"id":"z.read","category":"second"},
		{"id":"a.write","category":"first"},
		{"id":"a.read","category":"first"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	first := bytes.Index(out, []byte(`"first"`))
	second := bytes.Index(out, []byte(`"second"`))
	if first < 0 || second < 0 || first > second {
		t.Fatalf("categories are not sorted:\n%s", out)
	}
	if ai, aw := bytes.Index(out, []byte(`"a.read"`)), bytes.Index(out, []byte(`"a.write"`)); ai < 0 || aw < 0 || ai > aw {
		t.Fatalf("ids are not sorted:\n%s", out)
	}
}

func head(b []byte, lines int) []byte {
	split := bytes.SplitN(b, []byte("\n"), lines+1)
	if len(split) > lines {
		split = split[:lines]
	}
	return bytes.Join(split, []byte("\n"))
}
