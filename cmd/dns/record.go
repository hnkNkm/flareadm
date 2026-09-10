package dns

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/output"
	"github.com/hnkNkm/flareadm/internal/resolver"
)

// recordTypes is the full set of Cloudflare DNS record types accepted on
// create/update/filter.
var recordTypes = []string{
	"A", "AAAA", "CAA", "CERT", "CNAME", "DNSKEY", "DS", "HTTPS", "LOC", "MX",
	"NAPTR", "NS", "OPENPGPKEY", "PTR", "SMIMEA", "SRV", "SSHFP", "SVCB", "TLSA", "TXT", "URI",
}

func recordRow(r cloudflare.DNSRecord) []string {
	return []string{r.ID, r.Name, r.Type, truncate(r.Content, 48), ttlString(r.TTL), yesNo(r.Proxied)}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func ttlString(ttl float64) string {
	if ttl == 1 {
		return "auto"
	}
	return strconv.FormatFloat(ttl, 'f', 0, 64)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// newRecordGroup builds `dns record`.
func newRecordGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "record",
		Short: "DNS records",
	}
	cmd.AddCommand(
		newRecordList(rt),
		newRecordGet(rt),
		newRecordCreate(rt),
		newRecordUpdate(rt),
		newRecordDelete(rt),
		newRecordImport(rt),
		newRecordExport(rt),
	)
	return cmd
}

// resolveZone resolves the zone reference (--zone or profile default_zone)
// and returns the client plus zone id.
func resolveZone(ctx context.Context, rt *app.Runtime) (*cloudflare.Client, string, error) {
	ref, err := rt.ZoneReference("")
	if err != nil {
		return nil, "", err
	}
	client, err := rt.CloudClient()
	if err != nil {
		return nil, "", err
	}
	zoneID, err := resolver.NewZone(client).Resolve(ctx, ref)
	if err != nil {
		return nil, "", err
	}
	if zoneID != ref {
		rt.Logger().Infof("resolved zone %q to %s", ref, zoneID)
	}
	return client, zoneID, nil
}

// recordFlags are the shared record mutation flags.
type recordFlags struct {
	name       string
	typ        string
	content    string
	ttl        int
	proxied    bool
	priority   int
	comment    string
	structured *structuredFlagValues
}

func addRecordFlags(cmd *cobra.Command, rf *recordFlags) {
	cmd.Flags().StringVar(&rf.name, "name", "", "record name (may be relative to the zone, e.g. api)")
	cmd.Flags().StringVar(&rf.typ, "type", "", "record type (A, AAAA, CNAME, MX, TXT, or a structured type: CAA, CERT, DNSKEY, DS, HTTPS, LOC, NAPTR, OPENPGPKEY, SMIMEA, SRV, SSHFP, SVCB, TLSA, URI)")
	cmd.Flags().StringVar(&rf.content, "content", "", "record content (e.g. 192.0.2.10); content-based types only")
	cmd.Flags().IntVar(&rf.ttl, "ttl", 0, "time to live in seconds, or 1 for automatic")
	cmd.Flags().BoolVar(&rf.proxied, "proxied", false, "proxy through Cloudflare (A/AAAA/CNAME only)")
	cmd.Flags().IntVar(&rf.priority, "priority", 0, "record priority (MX, URI: record-level; SRV, SVCB, HTTPS: data field)")
	cmd.Flags().StringVar(&rf.comment, "comment", "", "record comment")
	rf.structured = registerStructuredFlags(cmd)
}

// validateTTL enforces the Cloudflare TTL contract.
func validateTTL(ttl int) error {
	if ttl != 1 && (ttl < 60 || ttl > 86400) {
		return errors.Usage("invalid --ttl %d: must be 1 (automatic) or between 60 and 86400", ttl)
	}
	return nil
}

// computeTTL resolves the record TTL from flags, falling back to automatic
// (1) on create and to the existing value on update.
func computeTTL(cmd *cobra.Command, rf *recordFlags, existing *cloudflare.DNSRecord, forCreate bool) (float64, error) {
	if cmd.Flags().Changed("ttl") {
		if err := validateTTL(rf.ttl); err != nil {
			return 0, err
		}
		return float64(rf.ttl), nil
	}
	if forCreate {
		return 1, nil
	}
	return existing.TTL, nil
}

// computeComment resolves the record comment: explicit flag wins, otherwise
// an existing comment is preserved on update.
func computeComment(cmd *cobra.Command, rf *recordFlags, existing *cloudflare.DNSRecord, forCreate bool) *string {
	if cmd.Flags().Changed("comment") {
		v := rf.comment
		return &v
	}
	if !forCreate && existing.Comment != "" {
		v := existing.Comment
		return &v
	}
	return nil
}

// buildWrite assembles a record write from flags plus existing values. It
// dispatches to the structured-type builder for data-payload types
// (CAA, SRV, TLSA, ...); content-based types keep the content path.
func buildWrite(cmd *cobra.Command, rf *recordFlags, existing *cloudflare.DNSRecord, forCreate bool) (cloudflare.RecordWrite, error) {
	changed := func(name string) bool { return cmd.Flags().Changed(name) }

	typ := strings.ToUpper(rf.typ)
	name := rf.name
	content := rf.content
	if !forCreate {
		if typ == "" {
			typ = existing.Type
		}
		if name == "" {
			name = existing.Name
		}
		if content == "" {
			content = existing.Content
		}
	}
	if typ == "" {
		return cloudflare.RecordWrite{}, errors.Usage("record type is required (--type)")
	}
	if !contains(recordTypes, typ) {
		return cloudflare.RecordWrite{}, errors.Usage("invalid record type %q", typ)
	}
	if _, ok := structuredTypes[typ]; ok {
		return buildStructuredWrite(cmd, rf, rf.structured, existing, forCreate, typ)
	}
	// Content-based types reject structured flags instead of ignoring them.
	if bad := invalidStructuredFlag(cmd, typ); bad != "" {
		return cloudflare.RecordWrite{}, errors.Usage("flag --%s is not valid for record type %s (valid for: %s)",
			bad, typ, strings.Join(structuredFlagAllowed[bad], ", "))
	}
	if name == "" {
		return cloudflare.RecordWrite{}, errors.Usage("record name is required (--name)")
	}
	if content == "" {
		return cloudflare.RecordWrite{}, errors.Usage("record content is required (--content)")
	}

	ttl, err := computeTTL(cmd, rf, existing, forCreate)
	if err != nil {
		return cloudflare.RecordWrite{}, err
	}

	var proxied *bool
	switch {
	case cloudflare.ProxiableType(typ):
		if changed("proxied") {
			v := rf.proxied
			proxied = &v
		} else if forCreate {
			v := false
			proxied = &v
		} else {
			v := existing.Proxied
			proxied = &v
		}
	case changed("proxied"):
		return cloudflare.RecordWrite{}, errors.Usage("--proxied is only valid for A, AAAA and CNAME records")
	}

	var priority *float64
	switch {
	case typ == "MX":
		switch {
		case changed("priority"):
			if rf.priority <= 0 || rf.priority > 65535 {
				return cloudflare.RecordWrite{}, errors.Usage("invalid --priority %d (must be between 1 and 65535)", rf.priority)
			}
			v := float64(rf.priority)
			priority = &v
		case forCreate:
			return cloudflare.RecordWrite{}, errors.Usage("MX records require --priority")
		default:
			if existing.Priority > 0 {
				v := existing.Priority
				priority = &v
			}
		}
	case changed("priority"):
		return cloudflare.RecordWrite{}, errors.Usage("--priority is only valid for MX and structured SRV/URI/SVCB/HTTPS records")
	}

	return cloudflare.RecordWrite{
		Name: name, Type: typ, Content: content, TTL: ttl,
		Proxied: proxied, Priority: priority, Comment: computeComment(cmd, rf, existing, forCreate),
	}, nil
}

// newRecordList lists DNS records of a zone.
func newRecordList(rt *app.Runtime) *cobra.Command {
	var nameFlag, typeFlag, contentFlag string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List DNS records of a zone",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if typeFlag != "" && !contains(recordTypes, strings.ToUpper(typeFlag)) {
				return errors.Usage("invalid record type %q", typeFlag)
			}
			client, zoneID, err := resolveZone(cmd.Context(), rt)
			if err != nil {
				return err
			}
			q := cloudflare.RecordListQuery{Name: nameFlag, Type: strings.ToUpper(typeFlag), Content: contentFlag}
			res, err := client.ListRecords(cmd.Context(), zoneID, q, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, []string{"ID", "NAME", "TYPE", "CONTENT", "TTL", "PROXIED"}, recordRow)
		},
	}
	cmd.Flags().StringVar(&nameFlag, "name", "", "only records with this exact name")
	cmd.Flags().StringVar(&typeFlag, "type", "", "only records of this type")
	cmd.Flags().StringVar(&contentFlag, "content", "", "only records with this exact content")
	return cmd
}

// newRecordGet shows one DNS record by id.
func newRecordGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get RECORD_ID",
		Short: "Show one DNS record",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, zoneID, err := resolveZone(cmd.Context(), rt)
			if err != nil {
				return err
			}
			res, err := client.GetRecord(cmd.Context(), zoneID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"ID", "NAME", "TYPE", "CONTENT", "TTL", "PROXIED"}, recordRow)
		},
	}
}

// newRecordCreate creates a DNS record.
func newRecordCreate(rt *app.Runtime) *cobra.Command {
	var rf recordFlags
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a DNS record",
		Long: "Create a DNS record in a zone.\n\n" +
			"Content-based example:\n" +
			"  flareadm dns record create --zone example.com --type A --name api --content 192.0.2.10 --proxied\n\n" +
			"Structured example:\n" +
			"  flareadm dns record create --zone example.com --type SRV --name _sip._tcp \\\n" +
			"    --priority 10 --weight 5 --port 5060 --target sip.example.com\n\n" +
			structuredHelpSection(),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			write, err := buildWrite(cmd, &rf, nil, true)
			if err != nil {
				return err
			}
			client, zoneID, err := resolveZone(cmd.Context(), rt)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewRecord(rt, fmt.Sprintf("Would create DNS record %s (%s) in zone %s", write.Name, write.Type, zoneID))
			}
			res, err := client.CreateRecord(cmd.Context(), zoneID, write)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"ID", "NAME", "TYPE", "CONTENT", "TTL", "PROXIED"}, recordRow)
		},
	}
	addRecordFlags(cmd, &rf)
	return cmd
}

// newRecordUpdate overwrites a DNS record with merged values.
func newRecordUpdate(rt *app.Runtime) *cobra.Command {
	var rf recordFlags
	cmd := &cobra.Command{
		Use:   "update RECORD_ID",
		Short: "Update a DNS record",
		Long: "Update a DNS record by id. Provided flags override the existing record;\n" +
			"omitted fields keep their current values (including structured data fields\n" +
			"when the record type is unchanged).\n\n" +
			structuredHelpSection(),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			changed := false
			for _, name := range structuredFlagOrder() {
				changed = changed || cmd.Flags().Changed(name)
			}
			for _, name := range []string{"name", "type", "content", "ttl", "proxied", "comment"} {
				changed = changed || cmd.Flags().Changed(name)
			}
			if !changed {
				return errors.Usage("nothing to update; pass at least one record flag (see 'dns record update --help')")
			}
			client, zoneID, err := resolveZone(cmd.Context(), rt)
			if err != nil {
				return err
			}
			existingRes, err := client.GetRecord(cmd.Context(), zoneID, args[0])
			if err != nil {
				return err
			}
			existing := existingRes.Item
			write, err := buildWrite(cmd, &rf, &existing, false)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewRecord(rt, fmt.Sprintf("Would update DNS record %s (%s) in zone %s", write.Name, write.Type, zoneID))
			}
			res, err := client.UpdateRecord(cmd.Context(), zoneID, args[0], write)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, []string{"ID", "NAME", "TYPE", "CONTENT", "TTL", "PROXIED"}, recordRow)
		},
	}
	addRecordFlags(cmd, &rf)
	return cmd
}

// newRecordDelete deletes a DNS record after confirmation.
func newRecordDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete RECORD_ID",
		Short: "Delete a DNS record",
		Long: "Delete a DNS record by id. Destructive: prompts for confirmation unless\n" +
			"--yes is given; --dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, zoneID, err := resolveZone(cmd.Context(), rt)
			if err != nil {
				return err
			}
			existingRes, err := client.GetRecord(cmd.Context(), zoneID, args[0])
			if err != nil {
				return err
			}
			existing := existingRes.Item

			if rt.DryRunFlag {
				return previewRecord(rt, fmt.Sprintf("Would delete DNS record %s (%s %s) in zone %s",
					existing.ID, existing.Type, existing.Name, zoneID))
			}
			if err := rt.Confirm(fmt.Sprintf("Delete DNS record %s?", existing.Name)); err != nil {
				return err
			}
			if err := client.DeleteRecord(cmd.Context(), zoneID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted DNS record %s from zone %s", args[0], zoneID)
			return nil
		},
	}
	return cmd
}

// previewRecord prints a dry-run preview through the normal output paths.
func previewRecord(rt *app.Runtime, line string) error {
	if rt.Format() == output.Table {
		_, _ = fmt.Fprintln(rt.Out, line)
		return nil
	}
	return rt.Printer().Emit(map[string]string{"preview": line})
}

// newRecordImport imports a BIND zone file.
func newRecordImport(rt *app.Runtime) *cobra.Command {
	var fileFlag string
	var proxiedFlag bool
	cmd := &cobra.Command{
		Use:   "import --file records.txt",
		Short: "Import DNS records from a BIND zone file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if fileFlag == "" {
				return errors.Usage("--file is required")
			}
			data, err := os.ReadFile(fileFlag)
			if err != nil {
				return errors.Wrap(errors.CodeInvalid, fmt.Sprintf("reading %s", fileFlag), err)
			}
			client, zoneID, err := resolveZone(cmd.Context(), rt)
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewRecord(rt, fmt.Sprintf("Would import DNS records from %s into zone %s", fileFlag, zoneID))
			}
			var proxied *bool
			if cmd.Flags().Changed("proxied") {
				v := proxiedFlag
				proxied = &v
			}
			res, err := client.ImportRecords(cmd.Context(), zoneID, data, proxied)
			if err != nil {
				return err
			}
			return renderImport(rt, res)
		},
	}
	cmd.Flags().StringVar(&fileFlag, "file", "", "path to the BIND zone file")
	cmd.Flags().BoolVar(&proxiedFlag, "proxied", false, "proxy proxiable imported records")
	return cmd
}

// renderImport renders the import summary; a partial import (some records
// parsed but not added) exits with code 9.
func renderImport(rt *app.Runtime, res *cloudflare.ImportResult) error {
	failed := res.TotalRecordsParsed - res.RecsAdded
	partial := failed > 0
	if rt.Format() == output.Table {
		row := []string{fmtFloat(res.RecsAdded), fmtFloat(res.TotalRecordsParsed), fmtFloat(failed)}
		if err := rt.Printer().PrintTable([]string{"RECORDS ADDED", "TOTAL PARSED", "FAILED"}, [][]string{row}); err != nil {
			return err
		}
	} else if err := rt.Printer().Emit(res); err != nil {
		return err
	}
	if partial {
		return errors.New(errors.CodePartial, "partial import: %s of %s records failed",
			fmtFloat(failed), fmtFloat(res.TotalRecordsParsed))
	}
	return nil
}

func fmtFloat(f float64) string { return strconv.FormatFloat(f, 'f', 0, 64) }

// newRecordExport writes the zone's records as BIND text.
func newRecordExport(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "export",
		Short: "Export DNS records as a BIND zone file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, zoneID, err := resolveZone(cmd.Context(), rt)
			if err != nil {
				return err
			}
			data, err := client.ExportRecords(cmd.Context(), zoneID)
			if err != nil {
				return err
			}
			switch rt.Format() {
			case output.JSON, output.YAML:
				return rt.Printer().Emit(map[string]string{"content": string(data)})
			default:
				// Default, text and raw all print the zone text verbatim.
				return rt.Printer().Raw(data)
			}
		},
	}
}
