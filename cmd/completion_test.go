package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// complete runs one completion request the way the generated shell scripts do
// (`flareadm __complete <words typed so far> ""`) and returns the candidates
// and the trailing directive line.
func complete(t *testing.T, words ...string) ([]string, string) {
	t.Helper()
	res := runCLI(t, append([]string{"__complete"}, words...)...)
	if res.code != 0 {
		t.Fatalf("__complete %v: code=%d stdout=%q stderr=%q", words, res.code, res.stdout, res.stderr)
	}
	lines := strings.Split(strings.TrimSuffix(res.stdout, "\n"), "\n")
	directive := lines[len(lines)-1]
	if !strings.HasPrefix(directive, ":") {
		t.Fatalf("__complete %v: no directive in stdout %q", words, res.stdout)
	}
	return lines[:len(lines)-1], directive
}

// writeCompletionConfig seeds the configuration the profile and account-id
// completions read.
func writeCompletionConfig(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(cfgPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	config := "[profile.work]\naccount_id = \"acct-1\"\n\n[profile.staging]\naccount_id = \"acct-2\"\n"
	if err := os.WriteFile(cfgPath(), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestCompletionOffersValidatedValues pins what every flag and positional
// argument offers. Each expected list is the exact set the command's own
// validator accepts, in the order it documents: a completion may never suggest
// a value the command would reject, and the directive must disable file
// completion (":4") so a mistyped prefix does not offer filenames.
func TestCompletionOffersValidatedValues(t *testing.T) {
	setToken(t, "tok")
	newHome(t)
	writeCompletionConfig(t)

	recordTypes := []string{"A", "AAAA", "CAA", "CERT", "CNAME", "DNSKEY", "DS", "HTTPS", "LOC", "MX",
		"NAPTR", "NS", "OPENPGPKEY", "PTR", "SMIMEA", "SRV", "SSHFP", "SVCB", "TLSA", "TXT", "URI"}

	for _, tc := range []struct {
		name  string
		words []string
		want  []string
	}{
		{"global --output", []string{"--output", ""}, []string{"table", "json", "yaml", "text"}},
		{"global --profile", []string{"--profile", ""}, []string{"staging", "work"}},
		{"global --account-id", []string{"--account-id", ""}, []string{"acct-2", "acct-1"}},

		{"zone list --status", []string{"zone", "list", "--status", ""},
			[]string{"initializing", "pending", "active", "moved", "deleted", "deactivated"}},
		{"zone list --type", []string{"zone", "list", "--type", ""}, []string{"full", "partial"}},

		{"dns record create --type", []string{"dns", "record", "create", "--type", ""}, recordTypes},
		{"dns record update --type", []string{"dns", "record", "update", "--type", ""}, recordTypes},
		{"dns record list --type", []string{"dns", "record", "list", "--type", ""}, recordTypes},
		{"dns record create --lat-direction", []string{"dns", "record", "create", "--lat-direction", ""}, []string{"N", "S"}},
		{"dns record create --long-direction", []string{"dns", "record", "create", "--long-direction", ""}, []string{"E", "W"}},

		{"ssl setting get NAME", []string{"ssl", "setting", "get", ""},
			[]string{"always_use_https", "automatic_https_rewrites", "min_tls_version", "opportunistic_encryption", "ssl", "tls_1_3"}},
		{"ssl setting update --mode", []string{"ssl", "setting", "update", "--mode", ""}, []string{"off", "flexible", "full", "strict"}},
		{"ssl setting update --min-tls-version", []string{"ssl", "setting", "update", "--min-tls-version", ""}, []string{"1.0", "1.1", "1.2", "1.3"}},
		{"ssl setting update --tls-1-3", []string{"ssl", "setting", "update", "--tls-1-3", ""}, []string{"on", "off"}},
		{"ssl setting update --always-use-https", []string{"ssl", "setting", "update", "--always-use-https", ""}, []string{"on", "off"}},
		{"ssl certificate-pack list --deploy", []string{"ssl", "certificate-pack", "list", "--deploy", ""}, []string{"staging", "production"}},

		{"certificate list --status", []string{"certificate", "list", "--status", ""},
			[]string{"active", "expired", "deleted", "pending", "initializing"}},
		{"certificate create --bundle-method", []string{"certificate", "create", "--bundle-method", ""}, []string{"ubiquitous", "optimal", "force"}},
		{"certificate create --deploy", []string{"certificate", "create", "--deploy", ""}, []string{"staging", "production"}},
		{"certificate create --type", []string{"certificate", "create", "--type", ""}, []string{"legacy_custom", "sni_custom"}},

		{"ruleset list --kind", []string{"ruleset", "list", "--kind", ""}, []string{"managed", "custom", "root", "zone"}},
		{"ruleset create --kind", []string{"ruleset", "create", "--kind", ""}, []string{"custom", "root", "zone"}},
		{"waf ruleset list --phase", []string{"waf", "ruleset", "list", "--phase", ""},
			[]string{"http_request_firewall_managed", "http_request_firewall_custom", "http_ratelimit", "http_response_firewall_managed"}},

		{"r2 bucket list --order", []string{"r2", "bucket", "list", "--order", ""}, []string{"name", "creation_date"}},
		{"r2 bucket list --direction", []string{"r2", "bucket", "list", "--direction", ""}, []string{"asc", "desc"}},
		{"r2 bucket list --jurisdiction", []string{"r2", "bucket", "list", "--jurisdiction", ""}, []string{"default", "eu", "us", "fedramp"}},
		{"r2 bucket create --location-hint", []string{"r2", "bucket", "create", "--location-hint", ""}, []string{"apac", "eeur", "enam", "weur", "wnam", "oc"}},
		{"r2 bucket create --storage-class", []string{"r2", "bucket", "create", "--storage-class", ""}, []string{"Standard", "InfrequentAccess"}},

		{"d1 database create --location-hint", []string{"d1", "database", "create", "--location-hint", ""}, []string{"wnam", "enam", "weur", "eeur", "apac", "oc"}},
		{"d1 database create --jurisdiction", []string{"d1", "database", "create", "--jurisdiction", ""}, []string{"eu", "fedramp", "us"}},
		{"d1 database create --read-replication-mode", []string{"d1", "database", "create", "--read-replication-mode", ""}, []string{"auto", "disabled"}},
		{"d1 database update --read-replication-mode", []string{"d1", "database", "update", "--read-replication-mode", ""}, []string{"auto", "disabled"}},
		{"d1 database export --output-format", []string{"d1", "database", "export", "--output-format", ""}, []string{"polling"}},
		{"d1 database import --action", []string{"d1", "database", "import", "--action", ""}, []string{"init", "ingest", "poll"}},

		{"queue consumer create --type", []string{"queue", "consumer", "create", "--type", ""}, []string{"worker", "http_pull"}},
		{"queue consumer update --type", []string{"queue", "consumer", "update", "--type", ""}, []string{"worker", "http_pull"}},
		{"queue message push --content-type", []string{"queue", "message", "push", "--content-type", ""}, []string{"text", "json"}},

		{"vectorize index create --metric", []string{"vectorize", "index", "create", "--metric", ""}, []string{"cosine", "euclidean", "dot-product"}},
		{"vectorize index metadata create --type", []string{"vectorize", "index", "metadata", "create", "--type", ""}, []string{"string", "number", "boolean"}},
		{"vectorize vector query --return-metadata", []string{"vectorize", "vector", "query", "--return-metadata", ""}, []string{"none", "indexed", "all"}},
		{"vectorize vector insert --unparsable-behavior", []string{"vectorize", "vector", "insert", "--unparsable-behavior", ""}, []string{"error", "discard"}},

		{"load-balancer monitor create --type", []string{"load-balancer", "monitor", "create", "--type", ""},
			[]string{"http", "https", "tcp", "udp_icmp", "icmp_ping", "smtp"}},
		{"load-balancer monitor update --type", []string{"load-balancer", "monitor", "update", "--type", ""},
			[]string{"http", "https", "tcp", "udp_icmp", "icmp_ping", "smtp"}},

		{"page-rule list --status", []string{"page-rule", "list", "--status", ""}, []string{"active", "disabled"}},
		{"page-rule list --direction", []string{"page-rule", "list", "--direction", ""}, []string{"asc", "desc"}},
		{"page-rule list --match", []string{"page-rule", "list", "--match", ""}, []string{"all", "any"}},
		{"page-rule create --status", []string{"page-rule", "create", "--status", ""}, []string{"active", "disabled"}},
		{"audit-log list --direction", []string{"audit-log", "list", "--direction", ""}, []string{"asc", "desc"}},
		{"registrar registration list --direction", []string{"registrar", "registration", "list", "--direction", ""}, []string{"asc", "desc"}},

		{"zero-trust access app create --type", []string{"zero-trust", "access", "app", "create", "--type", ""},
			[]string{"self_hosted", "saas", "ssh", "vnc", "app_launcher", "warp", "biso", "bookmark", "dash_sso", "infrastructure", "rdp", "mcp", "mcp_portal", "proxy_endpoint"}},
		{"zero-trust access policy create --decision", []string{"zero-trust", "access", "policy", "create", "--decision", ""},
			[]string{"allow", "deny", "non_identity", "bypass"}},
		{"zero-trust gateway rule create --action", []string{"zero-trust", "gateway", "rule", "create", "--action", ""},
			[]string{"on", "off", "allow", "block", "scan", "noscan", "safesearch", "ytrestricted", "isolate", "noisolate", "override", "l4_override", "egress", "resolve", "quarantine", "redirect"}},
		{"zero-trust gateway list list --type", []string{"zero-trust", "gateway", "list", "list", "--type", ""},
			[]string{"SERIAL", "URL", "DOMAIN", "EMAIL", "IP", "CATEGORY", "LOCATION", "DEVICE", "AAGUID"}},
		{"zero-trust gateway list create --type", []string{"zero-trust", "gateway", "list", "create", "--type", ""},
			[]string{"SERIAL", "URL", "DOMAIN", "EMAIL", "IP", "CATEGORY", "LOCATION", "DEVICE", "AAGUID"}},
		{"zero-trust device physical-device list --active-registrations", []string{"zero-trust", "device", "physical-device", "list", "--active-registrations", ""},
			[]string{"include", "only", "exclude"}},
		{"zero-trust device physical-device list --sort-by", []string{"zero-trust", "device", "physical-device", "list", "--sort-by", ""},
			[]string{"name", "id", "client_version", "last_seen_user.email", "last_seen_at", "active_registrations", "created_at"}},
		{"zero-trust device physical-device list --sort-order", []string{"zero-trust", "device", "physical-device", "list", "--sort-order", ""},
			[]string{"asc", "desc"}},
		{"zero-trust device posture create --type", []string{"zero-trust", "device", "posture", "create", "--type", ""},
			[]string{"file", "application", "tanium", "gateway", "warp", "disk_encryption", "serial_number", "sentinelone",
				"carbonblack", "firewall", "os_version", "domain_joined", "client_certificate", "client_certificate_v2",
				"antivirus", "unique_client_id", "kolide", "tanium_s2s", "crowdstrike_s2s", "intune", "workspace_one",
				"sentinelone_s2s", "custom_s2s"}},
		{"zero-trust tunnel create --config-src", []string{"zero-trust", "tunnel", "create", "--config-src", ""},
			[]string{"local", "cloudflare"}},

		{"api request METHOD", []string{"api", "request", ""}, []string{"GET", "POST", "PUT", "PATCH", "DELETE"}},
		{"completion SHELL", []string{"completion", ""}, []string{"bash", "zsh", "fish", "powershell"}},
		{"configure get KEY", []string{"configure", "get", ""}, []string{"account_id", "api_token_env", "default_zone", "oauth_client_id"}},
		{"configure set KEY", []string{"configure", "set", ""}, []string{"account_id", "api_token_env", "default_zone", "oauth_client_id"}},
		{"auth scopes --category", []string{"auth", "scopes", "--category", ""},
			[]string{"account_and_billing", "ai_and_machine_learning", "analytics_and_logs", "app_security",
				"cache_and_performance", "cloudflare_one_and_zero_trust", "developer_platform", "dns_and_zones",
				"email_and_messaging", "media", "network_services", "other", "rules_and_configuration"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, directive := complete(t, tc.words...)
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Fatalf("candidates = %v, want %v", got, tc.want)
			}
			if directive != ":4" {
				t.Fatalf("directive = %q, want \":4\" (no file completion)", directive)
			}
		})
	}
}

// TestCompletionOffersZoneReferences covers the network-backed completion: the
// --zone flag, the one positional zone argument, and the zone-valued flags of
// other commands all offer the zones the token can see (names and ids).
func TestCompletionOffersZoneReferences(t *testing.T) {
	api := defaultAPI(t)
	setToken(t, "tok")
	newHome(t)
	endpoint := api.srv.URL

	for _, tc := range []struct {
		name  string
		words []string
	}{
		{"--zone flag", []string{"--endpoint-url", endpoint, "--zone", ""}},
		{"zone get positional", []string{"zone", "get", "--endpoint-url", endpoint, ""}},
		{"profile create --default-zone", []string{"profile", "create", "--endpoint-url", endpoint, "--default-zone", ""}},
		{"workers domain list --zone-name", []string{"workers", "domain", "list", "--endpoint-url", endpoint, "--zone-name", ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, directive := complete(t, tc.words...)
			want := []string{"example.com", zoneID}
			if strings.Join(got, " ") != strings.Join(want, " ") {
				t.Fatalf("candidates = %v, want %v", got, want)
			}
			if directive != ":4" {
				t.Fatalf("directive = %q, want \":4\"", directive)
			}
		})
	}
}

// TestZoneCompletionIsSilentWhenTheAPIFails: a broken API must degrade to "no
// suggestions" and must not leak the failure into the completion stream - the
// shell parses stdout, and an error page there would be read as candidates.
func TestZoneCompletionIsSilentWhenTheAPIFails(t *testing.T) {
	api := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		status, body := apiErr(500, 1000, "completion probe must stay silent")
		return status, body
	})
	setToken(t, "tok")
	newHome(t)

	res := runCLI(t, "__complete", "zone", "get", "--endpoint-url", api.srv.URL, "")
	lines := strings.Split(strings.TrimSuffix(res.stdout, "\n"), "\n")
	if len(lines) != 1 || lines[0] != ":4" {
		t.Fatalf("stdout = %q, want just the directive on a failed lookup", res.stdout)
	}
	if strings.Contains(res.stderr, "Error:") || strings.Contains(res.stderr, "completion probe must stay silent") {
		t.Fatalf("stderr leaked the API failure: %q", res.stderr)
	}
}

// TestZoneCompletionWithoutCredentialIsOffline: no credential means no request
// at all, and still no output beyond the directive.
func TestZoneCompletionWithoutCredentialIsOffline(t *testing.T) {
	api := newAPI(t, func(method, path string, r recordedRequest) (int, string) {
		t.Errorf("the API must not be called without a credential: %s %s", method, path)
		return 200, envelope([]any{})
	})
	newHome(t)
	for _, name := range []string{"FLAREADM_API_TOKEN", "CLOUDFLARE_API_TOKEN", "CF_API_TOKEN"} {
		t.Setenv(name, "")
	}

	res := runCLI(t, "__complete", "zone", "get", "--endpoint-url", api.srv.URL, "")
	if res.stdout != ":4\n" {
		t.Fatalf("stdout = %q, want just the directive", res.stdout)
	}
}
