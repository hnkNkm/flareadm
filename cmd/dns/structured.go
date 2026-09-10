package dns

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

// Structured record types use Cloudflare's record "data" object instead of
// content. The field names below mirror the cloudflare-go/v7 union types
// (github.com/cloudflare/cloudflare-go/v7/dns), kebab-cased for flags.
//
// Mapping summary (required unless marked optional):
//
//	CAA       --flags --tag --value
//	CERT      --algorithm --cert-type --certificate --key-tag
//	DNSKEY    --flags --protocol --algorithm --public-key
//	DS        --key-tag --algorithm --digest-type --digest
//	HTTPS     --priority --target --value
//	LOC       --lat-degrees --lat-minutes --lat-seconds --lat-direction
//	          --long-degrees --long-minutes --long-seconds --long-direction
//	          --altitude [--precision-horz --precision-vert]
//	NAPTR     --order --preference --flags --service --regex --replacement
//	SMIMEA    --usage --selector --matching-type --certificate
//	SRV       --priority --weight --port --target
//	SSHFP     --algorithm --fingerprint-type --fingerprint
//	SVCB      --priority --target --value
//	TLSA      --usage --selector --matching-type --certificate
//	URI       --priority --weight --target
//
// OPENPGPKEY is content-based in the SDK (no data object) and uses
// --content like other content-based types.

type structuredKind int

const (
	kindString structuredKind = iota
	kindInt
	kindFloat
	kindDirection // N/S or E/W
)

// structuredField maps one Cloudflare data field to a CLI flag.
type structuredField struct {
	key      string // Cloudflare data JSON key
	flag     string // CLI flag name
	required bool
	kind     structuredKind
}

// structuredSpec describes one structured record type.
type structuredSpec struct {
	fields []structuredField
	// topLevelPriority: URI carries priority as a record-level field
	// instead of inside data (MX behaves the same way).
	topLevelPriority bool
}

// structuredTypes is the authoritative per-type field mapping.
var structuredTypes = map[string]structuredSpec{
	"CAA": {fields: []structuredField{
		{key: "flags", flag: "flags", required: true, kind: kindInt},
		{key: "tag", flag: "tag", required: true, kind: kindString},
		{key: "value", flag: "value", required: true, kind: kindString},
	}},
	"CERT": {fields: []structuredField{
		{key: "algorithm", flag: "algorithm", required: true, kind: kindInt},
		{key: "type", flag: "cert-type", required: true, kind: kindInt},
		{key: "certificate", flag: "certificate", required: true, kind: kindString},
		{key: "key_tag", flag: "key-tag", required: true, kind: kindInt},
	}},
	"DNSKEY": {fields: []structuredField{
		{key: "flags", flag: "flags", required: true, kind: kindInt},
		{key: "protocol", flag: "protocol", required: true, kind: kindInt},
		{key: "algorithm", flag: "algorithm", required: true, kind: kindInt},
		{key: "public_key", flag: "public-key", required: true, kind: kindString},
	}},
	"DS": {fields: []structuredField{
		{key: "key_tag", flag: "key-tag", required: true, kind: kindInt},
		{key: "algorithm", flag: "algorithm", required: true, kind: kindInt},
		{key: "digest_type", flag: "digest-type", required: true, kind: kindInt},
		{key: "digest", flag: "digest", required: true, kind: kindString},
	}},
	"HTTPS": {fields: []structuredField{
		{key: "priority", flag: "priority", required: true, kind: kindInt},
		{key: "target", flag: "target", required: true, kind: kindString},
		{key: "value", flag: "value", required: true, kind: kindString},
	}},
	"LOC": {fields: []structuredField{
		{key: "lat_degrees", flag: "lat-degrees", required: true, kind: kindFloat},
		{key: "lat_minutes", flag: "lat-minutes", required: true, kind: kindFloat},
		{key: "lat_seconds", flag: "lat-seconds", required: true, kind: kindFloat},
		{key: "lat_direction", flag: "lat-direction", required: true, kind: kindDirection},
		{key: "long_degrees", flag: "long-degrees", required: true, kind: kindFloat},
		{key: "long_minutes", flag: "long-minutes", required: true, kind: kindFloat},
		{key: "long_seconds", flag: "long-seconds", required: true, kind: kindFloat},
		{key: "long_direction", flag: "long-direction", required: true, kind: kindDirection},
		{key: "altitude", flag: "altitude", required: true, kind: kindFloat},
		{key: "precision_horz", flag: "precision-horz", required: false, kind: kindFloat},
		{key: "precision_vert", flag: "precision-vert", required: false, kind: kindFloat},
	}},
	"NAPTR": {fields: []structuredField{
		{key: "order", flag: "order", required: true, kind: kindInt},
		{key: "preference", flag: "preference", required: true, kind: kindInt},
		{key: "flags", flag: "flags", required: true, kind: kindString},
		{key: "service", flag: "service", required: true, kind: kindString},
		{key: "regex", flag: "regex", required: true, kind: kindString},
		{key: "replacement", flag: "replacement", required: true, kind: kindString},
	}},
	"SMIMEA": {fields: []structuredField{
		{key: "usage", flag: "usage", required: true, kind: kindInt},
		{key: "selector", flag: "selector", required: true, kind: kindInt},
		{key: "matching_type", flag: "matching-type", required: true, kind: kindInt},
		{key: "certificate", flag: "certificate", required: true, kind: kindString},
	}},
	"SRV": {fields: []structuredField{
		{key: "priority", flag: "priority", required: true, kind: kindInt},
		{key: "weight", flag: "weight", required: true, kind: kindInt},
		{key: "port", flag: "port", required: true, kind: kindInt},
		{key: "target", flag: "target", required: true, kind: kindString},
	}},
	"SSHFP": {fields: []structuredField{
		{key: "algorithm", flag: "algorithm", required: true, kind: kindInt},
		{key: "type", flag: "fingerprint-type", required: true, kind: kindInt},
		{key: "fingerprint", flag: "fingerprint", required: true, kind: kindString},
	}},
	"SVCB": {fields: []structuredField{
		{key: "priority", flag: "priority", required: true, kind: kindInt},
		{key: "target", flag: "target", required: true, kind: kindString},
		{key: "value", flag: "value", required: true, kind: kindString},
	}},
	"TLSA": {fields: []structuredField{
		{key: "usage", flag: "usage", required: true, kind: kindInt},
		{key: "selector", flag: "selector", required: true, kind: kindInt},
		{key: "matching_type", flag: "matching-type", required: true, kind: kindInt},
		{key: "certificate", flag: "certificate", required: true, kind: kindString},
	}},
	"URI": {
		fields: []structuredField{
			{key: "weight", flag: "weight", required: true, kind: kindInt},
			{key: "target", flag: "target", required: true, kind: kindString},
		},
		topLevelPriority: true,
	},
}

// structuredFlagAllowed maps every structured flag to the record types that
// accept it. Used to reject flags that belong to a different type instead
// of silently ignoring them.
var structuredFlagAllowed = map[string][]string{
	"flags":            {"CAA", "DNSKEY", "NAPTR"},
	"tag":              {"CAA"},
	"value":            {"CAA", "SVCB", "HTTPS"},
	"cert-type":        {"CERT"},
	"certificate":      {"CERT", "SMIMEA", "TLSA"},
	"key-tag":          {"CERT", "DS"},
	"protocol":         {"DNSKEY"},
	"public-key":       {"DNSKEY"},
	"digest":           {"DS"},
	"digest-type":      {"DS"},
	"fingerprint":      {"SSHFP"},
	"fingerprint-type": {"SSHFP"},
	"algorithm":        {"CERT", "DNSKEY", "DS", "SSHFP"},
	"weight":           {"SRV", "URI"},
	"port":             {"SRV"},
	"target":           {"SRV", "URI", "SVCB", "HTTPS"},
	"order":            {"NAPTR"},
	"preference":       {"NAPTR"},
	"service":          {"NAPTR"},
	"regex":            {"NAPTR"},
	"replacement":      {"NAPTR"},
	"usage":            {"SMIMEA", "TLSA"},
	"selector":         {"SMIMEA", "TLSA"},
	"matching-type":    {"SMIMEA", "TLSA"},
	"lat-degrees":      {"LOC"},
	"lat-minutes":      {"LOC"},
	"lat-seconds":      {"LOC"},
	"lat-direction":    {"LOC"},
	"long-degrees":     {"LOC"},
	"long-minutes":     {"LOC"},
	"long-seconds":     {"LOC"},
	"long-direction":   {"LOC"},
	"altitude":         {"LOC"},
	"precision-horz":   {"LOC"},
	"precision-vert":   {"LOC"},
	// priority is also a content-path flag (MX); SRV/SVCB/HTTPS keep it in
	// data, URI at record level.
	"priority": {"MX", "SRV", "URI", "SVCB", "HTTPS"},
}

// structuredFlagOrder returns the flag names in deterministic order.
func structuredFlagOrder() []string {
	names := make([]string, 0, len(structuredFlagAllowed))
	for name := range structuredFlagAllowed {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// invalidStructuredFlag returns the first (sorted) structured flag that was
// set but is not valid for the given record type, or "".
func invalidStructuredFlag(cmd *cobra.Command, typ string) string {
	for _, flag := range structuredFlagOrder() {
		if !cmd.Flags().Changed(flag) {
			continue
		}
		if !contains(structuredFlagAllowed[flag], typ) {
			return flag
		}
	}
	return ""
}

// structuredFlagValues holds the registered structured flag storage.
type structuredFlagValues struct {
	strs   map[string]*string
	ints   map[string]*int64
	floats map[string]*float64
}

// fieldHelp renders a flag description listing the types that accept it.
func fieldHelp(flag string) string {
	allowed := structuredFlagAllowed[flag]
	return fmt.Sprintf("structured %q field for %s records", flag, strings.Join(allowed, ", "))
}

// registerStructuredFlags declares every structured flag on cmd. Kinds are
// chosen from the union of all type usages; per-type numeric validation
// happens while building the payload.
func registerStructuredFlags(cmd *cobra.Command) *structuredFlagValues {
	sf := &structuredFlagValues{
		strs:   map[string]*string{},
		ints:   map[string]*int64{},
		floats: map[string]*float64{},
	}
	// --flags is registered as a string because NAPTR uses a string value
	// while CAA and DNSKEY require a number (validated per type).
	registerString := func(flag string) {
		sf.strs[flag] = new(string)
		cmd.Flags().StringVar(sf.strs[flag], flag, "", fieldHelp(flag))
	}
	registerInt := func(flag string) {
		sf.ints[flag] = new(int64)
		cmd.Flags().Int64Var(sf.ints[flag], flag, 0, fieldHelp(flag))
	}
	registerFloat := func(flag string) {
		sf.floats[flag] = new(float64)
		cmd.Flags().Float64Var(sf.floats[flag], flag, 0, fieldHelp(flag))
	}
	for _, flag := range structuredFlagOrder() {
		if flag == "priority" {
			continue // registered by addRecordFlags
		}
		switch flag {
		case "flags", "tag", "value", "target", "public-key", "digest",
			"fingerprint", "service", "regex", "replacement", "certificate",
			"lat-direction", "long-direction":
			registerString(flag)
		case "lat-degrees", "lat-minutes", "lat-seconds",
			"long-degrees", "long-minutes", "long-seconds", "altitude",
			"precision-horz", "precision-vert":
			registerFloat(flag)
		default:
			registerInt(flag)
		}
	}
	return sf
}

// parseFieldValue renders one field value in its wire form. priorityValue
// carries the shared --priority flag value (MX/URI record-level;
// SRV/SVCB/HTTPS data field).
func parseFieldValue(sf *structuredFlagValues, f structuredField, priorityValue int) (any, error) {
	switch f.kind {
	case kindString:
		return *sf.strs[f.flag], nil
	case kindInt:
		if f.flag == "priority" {
			return int64(priorityValue), nil
		}
		if f.flag == "flags" {
			// --flags is a string flag; CAA and DNSKEY require a number.
			n, err := strconv.ParseInt(*sf.strs[f.flag], 10, 64)
			if err != nil {
				return nil, errors.Usage("invalid value for --%s: %q is not a number", f.flag, *sf.strs[f.flag])
			}
			return n, nil
		}
		return *sf.ints[f.flag], nil
	case kindFloat:
		return *sf.floats[f.flag], nil
	case kindDirection:
		v := strings.ToUpper(*sf.strs[f.flag])
		valid := []string{"N", "S"}
		if f.key == "long_direction" {
			valid = []string{"E", "W"}
		}
		if !contains(valid, v) {
			return nil, errors.Usage("invalid value for --%s: %q (expected one of %s)",
				f.flag, *sf.strs[f.flag], strings.Join(valid, ", "))
		}
		return v, nil
	}
	return nil, errors.Usage("internal error: unknown field kind for --%s", f.flag)
}

// buildStructuredWrite assembles a data-payload record write for one of the
// structured types, inheriting unchanged fields from an existing record of
// the same type on update.
func buildStructuredWrite(cmd *cobra.Command, rf *recordFlags, sf *structuredFlagValues, existing *cloudflare.DNSRecord, forCreate bool, typ string) (cloudflare.RecordWrite, error) {
	spec := structuredTypes[typ]

	if cmd.Flags().Changed("content") {
		return cloudflare.RecordWrite{}, errors.Usage(
			"record type %s does not accept --content; it uses structured flags (see 'dns record create --help')", typ)
	}
	if cmd.Flags().Changed("proxied") {
		return cloudflare.RecordWrite{}, errors.Usage("--proxied is only valid for A, AAAA and CNAME records")
	}
	if bad := invalidStructuredFlag(cmd, typ); bad != "" {
		return cloudflare.RecordWrite{}, errors.Usage("flag --%s is not valid for record type %s (valid for: %s)",
			bad, typ, strings.Join(structuredFlagAllowed[bad], ", "))
	}

	name := rf.name
	if name == "" && !forCreate {
		name = existing.Name
	}
	if name == "" {
		return cloudflare.RecordWrite{}, errors.Usage("record name is required (--name)")
	}

	// Seed unchanged fields from the existing record when its type matches.
	seed := map[string]any{}
	if !forCreate && existing != nil && existing.Type == typ && len(existing.Data) > 0 {
		if err := json.Unmarshal(existing.Data, &seed); err != nil {
			return cloudflare.RecordWrite{}, errors.Wrap(errors.CodeUnclassified,
				fmt.Sprintf("decoding existing %s record data", typ), err)
		}
	}

	ttl, err := computeTTL(cmd, rf, existing, forCreate)
	if err != nil {
		return cloudflare.RecordWrite{}, err
	}

	data := map[string]any{}
	for _, f := range spec.fields {
		if cmd.Flags().Changed(f.flag) {
			v, err := parseFieldValue(sf, f, rf.priority)
			if err != nil {
				return cloudflare.RecordWrite{}, err
			}
			data[f.key] = v
			continue
		}
		if v, ok := seed[f.key]; ok {
			data[f.key] = v
			continue
		}
		if f.required {
			return cloudflare.RecordWrite{}, errors.Usage("record type %s requires --%s", typ, f.flag)
		}
	}

	var priority *float64
	if spec.topLevelPriority {
		switch {
		case cmd.Flags().Changed("priority"):
			v := float64(rf.priority)
			priority = &v
		case !forCreate && existing != nil && existing.Type == typ && existing.Priority > 0:
			v := existing.Priority
			priority = &v
		default:
			return cloudflare.RecordWrite{}, errors.Usage("record type %s requires --priority", typ)
		}
	}

	comment := computeComment(cmd, rf, existing, forCreate)

	return cloudflare.RecordWrite{
		Name:     name,
		Type:     typ,
		TTL:      ttl,
		Data:     data,
		Priority: priority,
		Comment:  comment,
	}, nil
}

// structuredHelpSection renders the per-type flag mapping for command help.
func structuredHelpSection() string {
	types := make([]string, 0, len(structuredTypes))
	for t := range structuredTypes {
		types = append(types, t)
	}
	sort.Strings(types)
	var sb strings.Builder
	sb.WriteString("Structured record types (flags are required unless marked optional):\n")
	for _, t := range types {
		spec := structuredTypes[t]
		var required, optional []string
		for _, f := range spec.fields {
			if f.required {
				required = append(required, "--"+f.flag)
			} else {
				optional = append(optional, "--"+f.flag)
			}
		}
		line := fmt.Sprintf("  %-9s %s", t, strings.Join(required, " "))
		if spec.topLevelPriority {
			line += " [record-level]"
		}
		if len(optional) > 0 {
			line += fmt.Sprintf(" (optional: %s)", strings.Join(optional, " "))
		}
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	sb.WriteString("OPENPGPKEY uses --content like other content-based types.")
	return sb.String()
}
