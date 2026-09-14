package zerotrust

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/hnkNkm/flareadm/cmd/internal/cmdutil"
	"github.com/hnkNkm/flareadm/internal/app"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func accessAppRow(a cloudflare.AccessApplication) []string {
	return []string{a.ID, a.Name, a.Type, a.Domain, a.SessionDuration, a.AUD}
}

func accessAppHeaders() []string {
	return []string{"ID", "NAME", "TYPE", "DOMAIN", "SESSION DURATION", "AUD"}
}

// appFlagValues collects the shared create/update flags of access applications.
type appFlagValues struct {
	rt                      *app.Runtime
	Name                    string
	Type                    string
	Domain                  string
	SessionDuration         string
	AllowedIdPs             string
	SameSiteCookieAttribute string
	CustomDenyURL           string
	CustomDenyMessage       string
	LogoURL                 string
	SelfHostedDomains       string
	Tags                    string
	Policies                string
	SaaSApp                 string
	Settings                string
	AutoRedirect            bool
	AppLauncherVisible      bool
	SkipInterstitial        bool
	EnableBindingCookie     bool
	HTTPOnlyCookie          bool
	ServiceAuth401Redirect  bool
	PathCookieAttribute     bool
	OptionsPreflightBypass  bool
}

func addAppFlags(rt *app.Runtime, cmd *cobra.Command, f *appFlagValues) {
	f.rt = rt
	cmd.Flags().StringVar(&f.Name, "name", "", "application name (required on create)")
	cmd.Flags().StringVar(&f.Type, "type", "", "application type: "+strings.Join(cloudflare.AccessApplicationTypeValues, ", "))
	_ = cmd.RegisterFlagCompletionFunc("type", cmdutil.EnumsOf(cloudflare.AccessApplicationTypeValues))
	cmd.Flags().StringVar(&f.Domain, "domain", "", "application domain (required on create unless the type is SaaS, WARP, infrastructure or MCP portal)")
	cmd.Flags().StringVar(&f.SessionDuration, "session-duration", "", "session duration (for example 24h)")
	cmd.Flags().StringVar(&f.AllowedIdPs, "allowed-idps", "", "comma-separated identity provider ids allowed to authenticate")
	cmd.Flags().BoolVar(&f.AutoRedirect, "auto-redirect-to-identity", false, "redirect to the identity provider instead of showing a login page")
	cmd.Flags().BoolVar(&f.AppLauncherVisible, "app-launcher-visible", false, "show the application in the App Launcher")
	cmd.Flags().BoolVar(&f.SkipInterstitial, "skip-interstitial", false, "skip the consent interstitial")
	cmd.Flags().BoolVar(&f.EnableBindingCookie, "enable-binding-cookie", false, "bind the session cookie to the client")
	cmd.Flags().BoolVar(&f.HTTPOnlyCookie, "http-only-cookie-attribute", false, "mark the session cookie HTTP-only")
	cmd.Flags().StringVar(&f.SameSiteCookieAttribute, "same-site-cookie-attribute", "", "SameSite cookie attribute (none, lax, strict)")
	cmd.Flags().BoolVar(&f.ServiceAuth401Redirect, "service-auth-401-redirect", false, "redirect service-auth failures to the login page")
	cmd.Flags().BoolVar(&f.PathCookieAttribute, "path-cookie-attribute", false, "scope the session cookie to the application path")
	cmd.Flags().BoolVar(&f.OptionsPreflightBypass, "options-preflight-bypass", false, "bypass Access for CORS preflight requests")
	cmd.Flags().StringVar(&f.CustomDenyURL, "custom-deny-url", "", "URL to redirect denied users to")
	cmd.Flags().StringVar(&f.CustomDenyMessage, "custom-deny-message", "", "message shown to denied users")
	cmd.Flags().StringVar(&f.LogoURL, "logo-url", "", "application logo URL")
	cmd.Flags().StringVar(&f.SelfHostedDomains, "self-hosted-domains", "", "comma-separated additional self-hosted domains")
	cmd.Flags().StringVar(&f.Tags, "tags", "", "comma-separated tags")
	cmd.Flags().StringVar(&f.Policies, "policies", "", "inline policy definitions as a JSON array, inline or @file")
	cmd.Flags().StringVar(&f.SaaSApp, "saas-app", "", "SaaS application definition as a JSON object, inline or @file")
	cmd.Flags().StringVar(&f.Settings, "settings", "", "additional application fields as a JSON object, inline or @file")
}

// overrides builds the request body fragment from the flags that were changed.
// --settings wins over the dedicated flags for the same key.
func (f *appFlagValues) overrides(cmd *cobra.Command) (map[string]any, error) {
	body := map[string]any{}
	changed := func(name string) bool { return cmd.Flags().Changed(name) }
	if changed("name") {
		body["name"] = f.Name
	}
	if changed("type") {
		if !contains(cloudflare.AccessApplicationTypeValues, f.Type) {
			return nil, errors.Usage("invalid --type %q (supported: %s)", f.Type, strings.Join(cloudflare.AccessApplicationTypeValues, ", "))
		}
		body["type"] = f.Type
	}
	if changed("domain") {
		body["domain"] = f.Domain
	}
	if changed("session-duration") {
		body["session_duration"] = f.SessionDuration
	}
	if changed("allowed-idps") {
		body["allowed_idps"] = splitList(f.AllowedIdPs)
	}
	if changed("auto-redirect-to-identity") {
		body["auto_redirect_to_identity"] = f.AutoRedirect
	}
	if changed("app-launcher-visible") {
		body["app_launcher_visible"] = f.AppLauncherVisible
	}
	if changed("skip-interstitial") {
		body["skip_interstitial"] = f.SkipInterstitial
	}
	if changed("enable-binding-cookie") {
		body["enable_binding_cookie"] = f.EnableBindingCookie
	}
	if changed("http-only-cookie-attribute") {
		body["http_only_cookie_attribute"] = f.HTTPOnlyCookie
	}
	if changed("same-site-cookie-attribute") {
		body["same_site_cookie_attribute"] = f.SameSiteCookieAttribute
	}
	if changed("service-auth-401-redirect") {
		body["service_auth_401_redirect"] = f.ServiceAuth401Redirect
	}
	if changed("path-cookie-attribute") {
		body["path_cookie_attribute"] = f.PathCookieAttribute
	}
	if changed("options-preflight-bypass") {
		body["options_preflight_bypass"] = f.OptionsPreflightBypass
	}
	if changed("custom-deny-url") {
		body["custom_deny_url"] = f.CustomDenyURL
	}
	if changed("custom-deny-message") {
		body["custom_deny_message"] = f.CustomDenyMessage
	}
	if changed("logo-url") {
		body["logo_url"] = f.LogoURL
	}
	if changed("self-hosted-domains") {
		body["self_hosted_domains"] = splitList(f.SelfHostedDomains)
	}
	if changed("tags") {
		body["tags"] = splitList(f.Tags)
	}
	if changed("policies") {
		arr, err := parseJSONArrayList("policies", f.Policies)
		if err != nil {
			return nil, err
		}
		body["policies"] = arr
	}
	if changed("saas-app") {
		text, err := cmdutilValueOrFile("saas-app", f.SaaSApp)
		if err != nil {
			return nil, err
		}
		obj, err := parseJSONObjectText("saas-app", text)
		if err != nil {
			return nil, err
		}
		body["saas_app"] = obj
	}
	if changed("settings") {
		extra, err := parseSettingsObject("settings", f.Settings)
		if err != nil {
			return nil, err
		}
		for k, v := range extra {
			body[k] = v
		}
	}
	return body, nil
}

// accessAppTypesWithoutDomain are the types whose application is not addressed
// by a customer domain.
var accessAppTypesWithoutDomain = []string{"saas", "warp", "infrastructure", "mcp_portal"}

func newAccessAppGroup(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "app",
		Short: "Access applications",
	}
	cmd.AddCommand(newAccessAppList(rt))
	cmd.AddCommand(newAccessAppGet(rt))
	cmd.AddCommand(newAccessAppCreate(rt))
	cmd.AddCommand(newAccessAppUpdate(rt))
	cmd.AddCommand(newAccessAppDelete(rt))
	cmd.AddCommand(newAccessAppPolicyGroup(rt))
	return cmd
}

func newAccessAppList(rt *app.Runtime) *cobra.Command {
	var f cloudflare.AccessApplicationQuery
	var exactFlag bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List Access applications",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			f.Exact = exactFlag
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.ListAccessApplications(cmd.Context(), ref.ID, f, rt.Policy())
			if err != nil {
				return err
			}
			return app.RenderList(rt, res, accessAppHeaders(), accessAppRow)
		},
	}
	cmd.Flags().StringVar(&f.Name, "name", "", "only applications with this exact name")
	cmd.Flags().StringVar(&f.Domain, "domain", "", "only applications with this domain")
	cmd.Flags().StringVar(&f.Search, "search", "", "search applications by name or domain")
	cmd.Flags().BoolVar(&exactFlag, "exact", false, "match --name and --domain exactly")
	cmd.Flags().StringVar(&f.AUD, "aud", "", "only the application with this audience tag")
	return cmd
}

func newAccessAppGet(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get APP_ID",
		Short: "Show one Access application",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.GetAccessApplication(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, accessAppHeaders(), accessAppRow)
		},
	}
}

func newAccessAppCreate(rt *app.Runtime) *cobra.Command {
	var f appFlagValues
	cmd := &cobra.Command{
		Use:   "create --name NAME --type TYPE",
		Short: "Create an Access application",
		Long: "Create an Access application.\n\n" +
			"Example:\n" +
			"  flareadm zero-trust access app create --name wiki --type self_hosted \\\n" +
			"    --domain wiki.example.com --session-duration 24h --allowed-idps <idp-id>\n\n" +
			"--policies takes an inline Cloudflare policies array; --settings accepts any\n" +
			"additional application field as a JSON object.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.Name == "" {
				return errors.Usage("--name is required")
			}
			if f.Type == "" {
				return errors.Usage("--type is required")
			}
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if _, ok := body["domain"]; !ok && !contains(accessAppTypesWithoutDomain, f.Type) {
				return errors.Usage("--domain is required for type %q", f.Type)
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would create access application "+f.Name)
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.CreateAccessApplication(cmd.Context(), ref.ID, body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, accessAppHeaders(), accessAppRow)
		},
	}
	addAppFlags(rt, cmd, &f)
	return cmd
}

func newAccessAppUpdate(rt *app.Runtime) *cobra.Command {
	var f appFlagValues
	cmd := &cobra.Command{
		Use:   "update APP_ID",
		Short: "Update an Access application",
		Long: "Update an Access application. Provided fields are merged into the current\n" +
			"application and the result is PUT, so fields this CLI does not model are\n" +
			"preserved.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := f.overrides(cmd)
			if err != nil {
				return err
			}
			if len(body) == 0 {
				return errors.Usage("nothing to update; pass at least one application flag or --settings")
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would update access application "+args[0])
			}
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			res, err := client.UpdateAccessApplication(cmd.Context(), ref.ID, args[0], body)
			if err != nil {
				return err
			}
			return app.RenderGet(rt, res, accessAppHeaders(), accessAppRow)
		},
	}
	addAppFlags(rt, cmd, &f)
	return cmd
}

func newAccessAppDelete(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete APP_ID",
		Short: "Delete an Access application",
		Long: "Delete an Access application. Destructive: prompts for confirmation unless\n" +
			"--yes is given; --dry-run previews the deletion without confirming.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, ref, err := rt.ResolveAccount(cmd.Context())
			if err != nil {
				return err
			}
			existing, err := client.GetAccessApplication(cmd.Context(), ref.ID, args[0])
			if err != nil {
				return err
			}
			if rt.DryRunFlag {
				return previewLine(rt, "Would delete access application "+existing.Item.Name)
			}
			if err := rt.Confirm("Delete access application " + existing.Item.Name + "?"); err != nil {
				return err
			}
			if err := client.DeleteAccessApplication(cmd.Context(), ref.ID, args[0]); err != nil {
				return err
			}
			rt.Logger().Infof("deleted access application %s", args[0])
			return nil
		},
	}
	return cmd
}
