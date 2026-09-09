package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type sample struct {
	ID     string `json:"id" yaml:"id"`
	Name   string `json:"name" yaml:"name"`
	Status string `json:"status" yaml:"status"`
}

var sampleItems = []sample{{ID: "023e105f4ecef8ad9ca31a8372d0c353", Name: "example.com", Status: "active"}}

func TestJSONEnvelopeShape(t *testing.T) {
	var buf bytes.Buffer
	p := &Printer{W: &buf, Fmt: JSON}
	if err := p.Emit(sampleItems); err != nil {
		t.Fatal(err)
	}
	var env struct {
		Version string   `json:"version"`
		Data    []sample `json:"data"`
		Meta    struct {
			Count int `json:"count"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if env.Version != "v1" {
		t.Fatalf("version = %q, want v1", env.Version)
	}
	if len(env.Data) != 1 || env.Data[0].ID != "023e105f4ecef8ad9ca31a8372d0c353" {
		t.Fatalf("data = %+v", env.Data)
	}
	if env.Meta.Count != 1 {
		t.Fatalf("meta.count = %d, want 1", env.Meta.Count)
	}
	// Only version/data/meta top-level keys (v1 compatibility surface).
	var m map[string]any
	_ = json.Unmarshal(buf.Bytes(), &m)
	for k := range m {
		if k != "version" && k != "data" && k != "meta" {
			t.Fatalf("unexpected envelope key %q", k)
		}
	}
}

func TestJSONEnvelopeEmptyListAndObject(t *testing.T) {
	for _, tc := range []struct {
		name string
		data any
		want int
	}{
		{"empty list", []sample{}, 0},
		{"nil", nil, 0},
		{"single object", sample{ID: "x"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			p := &Printer{W: &buf, Fmt: JSON}
			if err := p.Emit(tc.data); err != nil {
				t.Fatal(err)
			}
			var env struct {
				Meta struct {
					Count int `json:"count"`
				} `json:"meta"`
			}
			if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
				t.Fatal(err)
			}
			if env.Meta.Count != tc.want {
				t.Fatalf("count = %d, want %d", env.Meta.Count, tc.want)
			}
		})
	}
}

func TestYAMLEnvelope(t *testing.T) {
	var buf bytes.Buffer
	p := &Printer{W: &buf, Fmt: YAML}
	if err := p.Emit(sampleItems); err != nil {
		t.Fatal(err)
	}
	var env struct {
		Version string `yaml:"version"`
		Meta    struct {
			Count int `yaml:"count"`
		} `yaml:"meta"`
	}
	if err := yaml.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatalf("output is not valid YAML: %v", err)
	}
	if env.Version != "v1" || env.Meta.Count != 1 {
		t.Fatalf("yaml envelope = %+v", env)
	}
}

func TestTextOutputDeterministic(t *testing.T) {
	items := []sample{
		{ID: "bb", Name: "z.example", Status: "pending"},
		{ID: "aa", Name: "a.example", Status: "active"},
	}
	var buf bytes.Buffer
	p := &Printer{W: &buf, Fmt: Text}
	if err := p.Emit(items); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	// One object after another, sorted keys per object, no separators.
	if len(lines) != 6 {
		t.Fatalf("lines = %d: %q", len(lines), lines)
	}
	if lines[0] != "id\tbb" || lines[1] != "name\tz.example" || lines[2] != "status\tpending" {
		t.Fatalf("first object text wrong: %q", lines[:3])
	}
	if lines[3] != "id\taa" || lines[4] != "name\ta.example" || lines[5] != "status\tactive" {
		t.Fatalf("second object text wrong: %q", lines[3:])
	}
}

func TestPrintTable(t *testing.T) {
	var buf bytes.Buffer
	p := &Printer{W: &buf, Fmt: Table, Color: false}
	if err := p.PrintTable([]string{"ID", "NAME", "STATUS"}, [][]string{
		{"023e105f4ecef8ad9ca31a8372d0c353", "example.com", "active"},
		{"abc", "x", "pending"},
	}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("rows = %q", lines)
	}
	// Header present and aligned: NAME column is 11 wide ("example.com"),
	// so 7 pad + 2 separator spaces follow the header text.
	expected := "ID                                NAME         STATUS"
	if lines[0] != expected {
		t.Fatalf("header = %q, want %q", lines[0], expected)
	}
	if !strings.HasPrefix(lines[1], "023e105f4ecef8ad9ca31a8372d0c353  example.com") {
		t.Fatalf("row = %q", lines[1])
	}
}

func TestColorHeaderOnly(t *testing.T) {
	var buf bytes.Buffer
	p := &Printer{W: &buf, Fmt: Table, Color: true}
	_ = p.PrintTable([]string{"NAME"}, [][]string{{"x"}})
	first := strings.SplitN(buf.String(), "\n", 2)[0]
	if !strings.HasPrefix(first, "\x1b[1m") || !strings.HasSuffix(first, "\x1b[0m") {
		t.Fatalf("colored header expected, got %q", first)
	}
}

func TestRawTrailingNewline(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{`{"a":1}`, `{"a":1}` + "\n"},
		{`{"a":1}` + "\n", `{"a":1}` + "\n"},
		{"", ""},
	} {
		var buf bytes.Buffer
		p := &Printer{W: &buf, Fmt: JSON}
		if err := p.Raw([]byte(tc.body)); err != nil {
			t.Fatal(err)
		}
		if buf.String() != tc.want {
			t.Fatalf("Raw(%q) = %q, want %q", tc.body, buf.String(), tc.want)
		}
	}
}

func TestParseFormat(t *testing.T) {
	for _, s := range []string{"table", "json", "yaml", "text", ""} {
		if _, err := ParseFormat(s); err != nil {
			t.Errorf("ParseFormat(%q) failed: %v", s, err)
		}
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Error("ParseFormat(xml) should fail")
	}
}
