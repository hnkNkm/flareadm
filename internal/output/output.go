// Package output implements FlareADM's output contract (docs/cli.md):
//
//   - default human output: a compact table for interactive terminals;
//   - --json / --output json: the versioned normalized envelope
//     {"version":"v1","data":...,"meta":{"count":N}};
//   - --raw: the closest practical representation of the Cloudflare API
//     response, bypassing the normalized model;
//   - --output yaml: the same envelope rendered as YAML;
//   - --output text: flat key<TAB>value lines per item (AWS CLI text style).
//
// Machine output is written only to stdout; diagnostics go to stderr (the
// caller's responsibility). ANSI color is used only for table headers on an
// interactive terminal and is disabled by --no-color.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Format selects the output representation.
type Format int

// Supported output formats.
const (
	Table Format = iota
	JSON
	YAML
	Text
)

// Formats lists the accepted --output values in the order the help text lists
// them. ParseFormat accepts exactly these, and the shell completion for
// --output reads this list instead of repeating it.
var Formats = []string{"table", "json", "yaml", "text"}

// ParseFormat validates a --output value.
func ParseFormat(s string) (Format, error) {
	switch s {
	case "", "table":
		return Table, nil
	case "json":
		return JSON, nil
	case "yaml":
		return YAML, nil
	case "text":
		return Text, nil
	}
	return Table, fmt.Errorf("invalid --output %q (supported: table, json, yaml, text)", s)
}

// Envelope is the versioned normalized machine output.
type Envelope struct {
	Version string `json:"version" yaml:"version"`
	Data    any    `json:"data" yaml:"data"`
	Meta    Meta   `json:"meta" yaml:"meta"`
}

// Meta carries envelope bookkeeping.
type Meta struct {
	Count int `json:"count" yaml:"count"`
}

// EnvelopeVersion is the normalized output schema version.
const EnvelopeVersion = "v1"

// Printer renders data in the selected format.
type Printer struct {
	W     io.Writer
	Fmt   Format
	Color bool
}

// countData computes meta.count for a data payload: slice length, 1 for a
// single object, 0 for nil/empty.
func countData(data any) int {
	if data == nil {
		return 0
	}
	v := reflect.ValueOf(data)
	switch v.Kind() {
	case reflect.Slice, reflect.Array:
		return v.Len()
	case reflect.Map:
		if v.Len() == 0 {
			return 0
		}
		return 1
	default:
		return 1
	}
}

// Emit renders a normalized data payload (single object or slice) in the
// configured format. Tables are not produced here: list-style commands build
// their own rows through PrintTable so columns can be controlled.
func (p *Printer) Emit(data any) error {
	if p.Fmt != Table {
		return p.emitStructured(data)
	}
	// Callers that reach the default printer for a table format get the
	// flattened text form; commands with a real table call PrintTable.
	return p.emitText(data)
}

func (p *Printer) emitStructured(data any) error {
	env := Envelope{Version: EnvelopeVersion, Data: data, Meta: Meta{Count: countData(data)}}
	switch p.Fmt {
	case JSON:
		b, err := json.MarshalIndent(env, "", "  ")
		if err != nil {
			return fmt.Errorf("encoding json output: %w", err)
		}
		_, err = fmt.Fprintln(p.W, string(b))
		return err
	case YAML:
		b, err := yaml.Marshal(&env)
		if err != nil {
			return fmt.Errorf("encoding yaml output: %w", err)
		}
		_, err = p.W.Write(b)
		return err
	default:
		return p.emitText(data)
	}
}

// emitText renders the data payload as AWS-CLI-style text: one
// "key<TAB>value" line per field, one object after another, keys sorted.
func (p *Printer) emitText(data any) error {
	items := asSlice(data)
	for _, item := range items {
		if err := writeItemText(p.W, item); err != nil {
			return err
		}
	}
	return nil
}

func asSlice(data any) []any {
	if data == nil {
		return nil
	}
	v := reflect.ValueOf(data)
	switch v.Kind() {
	case reflect.Slice, reflect.Array:
		out := make([]any, 0, v.Len())
		for i := 0; i < v.Len(); i++ {
			out = append(out, v.Index(i).Interface())
		}
		return out
	default:
		// A single object renders as one item.
		return []any{data}
	}
}

// writeItemText flattens one object through JSON so field names match the
// normalized JSON keys exactly, then prints sorted key<TAB>value lines.
// Scalar values are printed bare; nested values as compact JSON.
func writeItemText(w io.Writer, item any) error {
	b, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("encoding text output: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("encoding text output: %w", err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		val := m[k]
		var sv string
		switch v := val.(type) {
		case nil:
			continue
		case string:
			sv = v
		default:
			jb, err := json.Marshal(v)
			if err != nil {
				sv = fmt.Sprintf("%v", v)
			} else {
				sv = string(jb)
			}
		}
		if _, err := fmt.Fprintf(w, "%s\t%s\n", k, sv); err != nil {
			return err
		}
	}
	return nil
}

// PrintTable renders rows with aligned columns. The header is bold when
// color output is enabled. Table output is only produced when the configured
// format is Table; the caller decides when to call this.
func (p *Printer) PrintTable(headers []string, rows [][]string) error {
	if len(headers) == 0 {
		return nil
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	pad := func(line []string) string {
		var sb strings.Builder
		for i, cell := range line {
			if i > 0 {
				sb.WriteString("  ")
			}
			sb.WriteString(cell)
			if i < len(line)-1 {
				sb.WriteString(strings.Repeat(" ", widths[i]-len(cell)))
			}
		}
		return sb.String()
	}

	var sb strings.Builder
	headerLine := pad(headers)
	if p.Color {
		headerLine = "\x1b[1m" + headerLine + "\x1b[0m"
	}
	sb.WriteString(headerLine)
	sb.WriteString("\n")
	for _, row := range rows {
		sb.WriteString(pad(row))
		sb.WriteString("\n")
	}
	_, err := io.WriteString(p.W, sb.String())
	return err
}

// Raw writes raw API response bytes verbatim, appending a trailing newline
// when the payload does not end with one. Used for --raw mode.
func (p *Printer) Raw(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if _, err := p.W.Write(b); err != nil {
		return err
	}
	if b[len(b)-1] != '\n' {
		_, err := fmt.Fprintln(p.W)
		return err
	}
	return nil
}
