// Package app wires the per-command runtime: global flag state, the
// configuration file, diagnostics logging, output rendering, credential
// resolution and the Cloudflare client. Command packages depend on Runtime
// but never on each other.
package app

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hnkNkm/flareadm/internal/auth"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/config"
	"github.com/hnkNkm/flareadm/internal/confirm"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/logging"
	"github.com/hnkNkm/flareadm/internal/oauth"
	"github.com/hnkNkm/flareadm/internal/output"
	"github.com/hnkNkm/flareadm/internal/pagination"
	"github.com/hnkNkm/flareadm/internal/profile"
	"github.com/hnkNkm/flareadm/internal/resolver"
)

// DefaultTimeout is the per-request attempt timeout when --timeout is not
// given.
const DefaultTimeout = 30 * time.Second

// Runtime carries all per-execution state for one CLI invocation.
type Runtime struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer

	// Flag values (bound by cmd/root).
	ProfileFlag     string
	AccountIDFlag   string
	ZoneFlag        string
	OutputFlag      string
	JSONFlag        bool
	RawFlag         bool
	PageSizeFlag    int
	MaxItemsFlag    int
	NoPaginateFlag  bool
	YesFlag         bool
	DryRunFlag      bool
	NoInputFlag     bool
	NoColorFlag     bool
	VerboseFlag     bool
	DebugFlag       bool
	TimeoutFlag     time.Duration
	EndpointURLFlag string

	// Environment access (tests inject a fake).
	env func(string) string

	// Derived state.
	secrets   []string
	format    output.Format
	cfg       *config.Config
	cfgErr    error
	cfgLoaded bool
	logger    *logging.Logger
	client    *cloudflare.Client

	// credentialKind records how the resolved credential was obtained and
	// oauthTokenInUse the access token the current client was built with.
	credentialKind  string
	oauthTokenInUse string

	stdinIsTTY  bool
	stdoutIsTTY bool
}

// NewRuntime creates a Runtime bound to the process streams.
// Credential kinds reported by CredentialKind.
const (
	credentialKindEnv   = "env"
	credentialKindOAuth = "oauth"
)

func NewRuntime(in io.Reader, out, errOut io.Writer) *Runtime {
	rt := &Runtime{
		In:  in,
		Out: out,
		Err: errOut,
		env: os.Getenv,
	}
	rt.stdinIsTTY = readerIsTerminal(in)
	rt.stdoutIsTTY = writerIsTerminal(out)
	return rt
}

// SetEnv overrides environment lookup (tests).
func (rt *Runtime) SetEnv(fn func(string) string) { rt.env = fn }

// Getenv reads an environment variable through the runtime's environment
// source.
func (rt *Runtime) Getenv(key string) string { return rt.env(key) }

// ProtectSecret registers sensitive material (for example an uploaded
// private key) that must be scrubbed from diagnostics and error output.
func (rt *Runtime) ProtectSecret(secret string) {
	if secret == "" {
		return
	}
	for _, existing := range rt.secrets {
		if existing == secret {
			return
		}
	}
	rt.secrets = append(rt.secrets, secret)
	if rt.logger != nil {
		rt.logger.AddSecret(secret)
	}
}

// Redact scrubs every registered secret, the resolved API token and any
// embedded PEM private-key block from s.
func (rt *Runtime) Redact(s string) string {
	for _, secret := range rt.secrets {
		s = auth.Redact(s, secret)
	}
	return auth.RedactPEMBlocks(s)
}

// Init validates flags and prepares shared state. It runs once per
// invocation from the root command's PersistentPreRunE. Configuration file
// loading is deliberately lazy so local-only commands (version, help,
// completion) never depend on it.
func (rt *Runtime) Init() error {
	if rt.TimeoutFlag <= 0 {
		rt.TimeoutFlag = DefaultTimeout
	}
	rt.logger = logging.New(rt.Err, "", rt.VerboseFlag, rt.DebugFlag)

	format, err := output.ParseFormat(rt.OutputFlag)
	if err != nil {
		return errors.New(errors.CodeInvalid, "%s", err.Error())
	}
	if rt.JSONFlag {
		if rt.OutputFlag != "" && rt.OutputFlag != "json" {
			return errors.Usage("--json conflicts with --output %s", rt.OutputFlag)
		}
		format = output.JSON
	}
	rt.format = format
	if err := rt.ValidatePolicy(); err != nil {
		return err
	}
	return nil
}

// Config returns the loaded configuration, loading it on first use. A
// missing file yields an empty configuration; parse errors fail with exit
// code 2.
func (rt *Runtime) Config() (*config.Config, error) {
	if !rt.cfgLoaded {
		cfg, err := config.Load(config.DefaultPath())
		if err != nil {
			rt.cfgErr = errors.New(errors.CodeInvalid, "%s", err.Error())
		}
		rt.cfg = cfg
		rt.cfgLoaded = true
	}
	return rt.cfg, rt.cfgErr
}

// Format returns the resolved output format (table unless --output/--json).
func (rt *Runtime) Format() output.Format { return rt.format }

// Raw reports whether --raw was given.
func (rt *Runtime) Raw() bool { return rt.RawFlag }

// Logger returns the diagnostics logger.
func (rt *Runtime) Logger() *logging.Logger { return rt.logger }

// Printer builds the output printer for the configured format.
func (rt *Runtime) Printer() *output.Printer {
	color := rt.stdoutIsTTY && !rt.NoColorFlag
	return &output.Printer{W: rt.Out, Fmt: rt.format, Color: color}
}

// ActiveProfileName resolves the selected profile name.
func (rt *Runtime) ActiveProfileName() string {
	return profile.ActiveName(rt.ProfileFlag, rt.env)
}

// ActiveProfile loads the effective active profile.
func (rt *Runtime) ActiveProfile() (profile.Effective, error) {
	cfg, err := rt.Config()
	if err != nil {
		return profile.Effective{}, err
	}
	return profile.Select(cfg, rt.ActiveProfileName()), nil
}

// ActiveProfilePtr returns the active profile's configuration, or nil when
// the profile does not exist (credential resolution then falls back to the
// environment chain).
func (rt *Runtime) ActiveProfilePtr() (*config.Profile, error) {
	eff, err := rt.ActiveProfile()
	if err != nil {
		return nil, err
	}
	return eff.Profile, nil
}

// Credential resolves the API token for the active profile: environment
// credentials first, then the stored OAuth credential (docs/oauth.md §8).
func (rt *Runtime) Credential() (auth.Credential, error) {
	eff, err := rt.ActiveProfile()
	if err != nil {
		return auth.Credential{}, err
	}
	var cred auth.Credential
	if eff.Exists {
		cred, err = auth.RequireWithOAuth(eff.Profile, rt.OAuthCredential)
	} else {
		cred, err = auth.RequireWithOAuth(nil, rt.OAuthCredential)
	}
	if err != nil {
		return auth.Credential{}, err
	}
	rt.credentialKind = credentialKindEnv
	if strings.HasPrefix(cred.Source, "oauth:") {
		rt.credentialKind = credentialKindOAuth
		rt.oauthTokenInUse = cred.Token
	}
	return cred, nil
}

// CredentialKind reports how the last resolved credential was obtained:
// credentialKindEnv or credentialKindOAuth. It is empty before the first
// resolution.
func (rt *Runtime) CredentialKind() string { return rt.credentialKind }

// IsOAuthCredential reports whether the resolved credential came from the
// OAuth store (as opposed to an environment API token).
func (rt *Runtime) IsOAuthCredential() bool { return rt.credentialKind == credentialKindOAuth }

// PermissionHint returns the extra guidance appended to a 403 when the request
// used an OAuth credential. Cloudflare's 403 body does not say whether the
// granted scopes or the account role is at fault, so the hint states both
// possibilities and points at the check that distinguishes them
// (docs/oauth.md §13 Q9). It is empty for API-token credentials.
func (rt *Runtime) PermissionHint() string {
	if rt.credentialKind != credentialKindOAuth {
		return ""
	}
	return "\nnote: this request used an OAuth credential. A 403 can mean the granted scopes do not cover " +
		"this command, or that your Cloudflare account role lacks the permission; the API does not say which. " +
		"Check the granted scopes with 'flareadm auth status'; if the scope is missing, re-run " +
		"'flareadm auth login --all-scopes'."
}

// refreshStoredOAuth performs a forced refresh of the stored credential and
// returns the new access token. A token rotated by a sibling process (or an
// earlier retry) is reused instead of burning another refresh.
func (rt *Runtime) refreshStoredOAuth(ctx context.Context) (string, error) {
	profileName := rt.ActiveProfileName()
	store := rt.OAuthStore()
	cred, ok, err := store.Load(profileName)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errors.New(errors.CodeAuth,
			"no OAuth credential is stored for profile %q; run 'flareadm auth login'", profileName)
	}
	if cred.AccessToken != rt.oauthTokenInUse && cred.AccessToken != "" {
		// A concurrent process already rotated: use its token.
		rt.ProtectSecret(cred.AccessToken)
		rt.oauthTokenInUse = cred.AccessToken
		return cred.AccessToken, nil
	}
	clientID := cred.ClientID
	if clientID == "" {
		if eff, err := rt.ActiveProfile(); err == nil && eff.Exists {
			clientID = eff.Profile.OAuthClientID
		}
	}
	refreshed, err := oauth.Refresh(ctx, oauth.RefreshOptions{
		ClientID:   clientID,
		Credential: cred,
		Endpoints:  oauth.EndpointsFromEnv(rt.Getenv),
		Protect:    rt.ProtectSecret,
	})
	if err != nil {
		if errors.CodeOf(err) == errors.CodeAuth {
			return "", errors.New(errors.CodeAuth, "%s; run 'flareadm auth login' to sign in again", err)
		}
		return "", err
	}
	if err := store.Save(profileName, refreshed); err != nil {
		return "", err
	}
	rt.ProtectSecret(refreshed.AccessToken)
	rt.ProtectSecret(refreshed.RefreshToken)
	rt.oauthTokenInUse = refreshed.AccessToken
	return refreshed.AccessToken, nil
}

// OAuthStore returns the OAuth credential store, which lives beside the
// configuration file so both share the platform path rules
// (docs/oauth.md §7.1).
func (rt *Runtime) OAuthStore() oauth.Store {
	return oauth.Store{Dir: filepath.Join(config.DefaultDir(), "oauth")}
}

// OAuthCredential loads the stored OAuth credential for the active profile,
// refreshing it first when it is about to expire. ok is false when no
// credential is stored; a rejected refresh fails with exit code 3 and points
// at `auth login`.
func (rt *Runtime) OAuthCredential() (auth.Credential, bool, error) {
	profileName := rt.ActiveProfileName()
	store := rt.OAuthStore()
	cred, ok, err := store.Load(profileName)
	if err != nil || !ok {
		return auth.Credential{}, false, err
	}
	rt.ProtectSecret(cred.AccessToken)
	rt.ProtectSecret(cred.RefreshToken)
	source := "oauth:" + profileName
	if !cred.Expired(time.Now()) {
		return auth.Credential{Token: cred.AccessToken, Source: source}, true, nil
	}
	clientID := cred.ClientID
	if clientID == "" {
		if eff, err := rt.ActiveProfile(); err == nil && eff.Exists {
			clientID = eff.Profile.OAuthClientID
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), rt.oauthRequestTimeout())
	defer cancel()
	refreshed, err := oauth.Refresh(ctx, oauth.RefreshOptions{
		ClientID:   clientID,
		Credential: cred,
		Endpoints:  oauth.EndpointsFromEnv(rt.Getenv),
		Protect:    rt.ProtectSecret,
	})
	if err != nil {
		if errors.CodeOf(err) == errors.CodeAuth {
			return auth.Credential{}, false, errors.New(errors.CodeAuth,
				"%s; run 'flareadm auth login' to sign in again", err)
		}
		return auth.Credential{}, false, err
	}
	if err := store.Save(profileName, refreshed); err != nil {
		return auth.Credential{}, false, err
	}
	rt.ProtectSecret(refreshed.AccessToken)
	rt.ProtectSecret(refreshed.RefreshToken)
	return auth.Credential{Token: refreshed.AccessToken, Source: source}, true, nil
}

// oauthRequestTimeout bounds a credential refresh.
func (rt *Runtime) oauthRequestTimeout() time.Duration {
	if rt.TimeoutFlag > 0 {
		return rt.TimeoutFlag
	}
	return 30 * time.Second
}

// Policy returns the pagination policy from the global flags.
func (rt *Runtime) Policy() pagination.Policy {
	return pagination.Policy{
		PageSize:   rt.PageSizeFlag,
		MaxItems:   rt.MaxItemsFlag,
		NoPaginate: rt.NoPaginateFlag,
	}
}

// ValidatePolicy checks pagination flag values up front.
func (rt *Runtime) ValidatePolicy() error {
	p := rt.Policy()
	if p.PageSize < 0 {
		return errors.Usage("--page-size must be >= 1 (got %d)", p.PageSize)
	}
	if p.MaxItems < 0 {
		return errors.Usage("--max-items must be >= 0 (got %d)", p.MaxItems)
	}
	return nil
}

// CloudClient resolves credentials and builds (once) the Cloudflare client.
func (rt *Runtime) CloudClient() (*cloudflare.Client, error) {
	if rt.client != nil {
		return rt.client, nil
	}
	client, err := rt.newClient(clientSpec{raw: rt.RawFlag, logger: rt.logger, refresh401: true})
	if err != nil {
		return nil, err
	}
	rt.client = client
	return client, nil
}

// CompletionClient builds a Cloudflare client for a shell completion request:
// the same credential chain and endpoint as CloudClient, but a single attempt
// (nothing may queue behind backoff while a prompt waits), no diagnostics sink
// and normalized output. It is never cached, so a completion can never change
// the client the command itself uses.
//
// A failure to resolve a credential is returned as-is; the caller treats it as
// "no suggestions".
func (rt *Runtime) CompletionClient() (*cloudflare.Client, error) {
	return rt.newClient(clientSpec{maxAttempts: 1})
}

// clientSpec selects how a client differs from the default one. The zero value
// keeps the command client's behaviour: default retry policy, normalized
// output, no diagnostics, no refresh hook.
type clientSpec struct {
	raw         bool            // --raw: carry the closest API response through
	logger      *logging.Logger // nil silences the client
	maxAttempts int             // total attempts incl. the first; <=0 keeps the default
	refresh401  bool            // refresh an OAuth credential once after HTTP 401
}

// newClient resolves the credential and builds the Cloudflare client described
// by spec.
func (rt *Runtime) newClient(spec clientSpec) (*cloudflare.Client, error) {
	cred, err := rt.Credential()
	if err != nil {
		return nil, err
	}
	rt.ProtectSecret(cred.Token)
	if spec.logger != nil {
		spec.logger.SetToken(cred.Token)
		spec.logger.Infof("profile %q; token source: %s; endpoint: %s",
			rt.ActiveProfileName(), cred.Source, endpointLabel(rt.EndpointURLFlag))
	}
	var refreshHook func(ctx context.Context) (string, error)
	if spec.refresh401 && rt.credentialKind == credentialKindOAuth {
		// Only stored OAuth credentials can be refreshed (docs/oauth.md §9).
		refreshHook = func(ctx context.Context) (string, error) {
			ctx, cancel := context.WithTimeout(ctx, rt.oauthRequestTimeout())
			defer cancel()
			return rt.refreshStoredOAuth(ctx)
		}
	}
	return cloudflare.New(cloudflare.Options{
		Token:        cred.Token,
		Endpoint:     rt.EndpointURLFlag,
		Timeout:      rt.TimeoutFlag,
		MaxAttempts:  spec.maxAttempts,
		RawMode:      spec.raw,
		Policy:       rt.Policy(),
		Logger:       spec.logger,
		RefreshToken: refreshHook,
	})
}

func endpointLabel(endpoint string) string {
	if endpoint == "" {
		return cloudflare.DefaultEndpoint
	}
	return endpoint
}

// ZoneReference resolves the zone for a command: the positional argument
// (if any) and --zone must not both be set; the profile default_zone is the
// fallback.
func (rt *Runtime) ZoneReference(positional string) (string, error) {
	if positional != "" && rt.ZoneFlag != "" {
		return "", errors.Usage("zone given twice: positional %q and --zone %q", positional, rt.ZoneFlag)
	}
	if positional != "" {
		return positional, nil
	}
	if rt.ZoneFlag != "" {
		return rt.ZoneFlag, nil
	}
	eff, err := rt.ActiveProfile()
	if err != nil {
		return "", err
	}
	if eff.Exists && eff.Profile.DefaultZone != "" {
		return eff.Profile.DefaultZone, nil
	}
	return "", errors.Usage("a zone is required: pass a zone argument or --zone <name-or-id>")
}

// ResolveZone resolves the zone reference (--zone or profile default_zone),
// builds the Cloudflare client and returns both plus the resolved zone id.
// Shared by every zone-scoped command group.
func (rt *Runtime) ResolveZone(ctx context.Context) (*cloudflare.Client, string, error) {
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

// ResolveAccount resolves the account id for account-scoped commands
// (flag > profile account_id > FLAREADM_ACCOUNT_ID > single-account
// discovery) and returns the client plus the account id and name.
func (rt *Runtime) ResolveAccount(ctx context.Context) (*cloudflare.Client, resolver.AccountRef, error) {
	client, err := rt.CloudClient()
	if err != nil {
		return nil, resolver.AccountRef{}, err
	}
	prof, err := rt.ActiveProfilePtr()
	if err != nil {
		return nil, resolver.AccountRef{}, err
	}
	ref, err := resolver.Account(ctx, client, rt.AccountIDFlag, prof, rt.Getenv)
	if err != nil {
		return nil, resolver.AccountRef{}, err
	}
	rt.Logger().Infof("resolved account %s (%s)", ref.ID, ref.Source)
	return client, ref, nil
}

// Confirm asks for destructive-operation consent.
func (rt *Runtime) Confirm(question string) error {
	p := &confirm.Prompter{
		Stdin:       rt.In,
		Stdout:      rt.Out,
		Yes:         rt.YesFlag,
		NoInput:     rt.NoInputFlag,
		Interactive: rt.stdinIsTTY,
	}
	return p.Confirm(question)
}

// StdinTTY reports whether stdin is an interactive terminal.
func (rt *Runtime) StdinTTY() bool { return rt.stdinIsTTY }

// StdoutTTY reports whether stdout is an interactive terminal.
func (rt *Runtime) StdoutTTY() bool { return rt.stdoutIsTTY }

// RenderList renders a list service result: raw bytes in --raw mode, a
// table (built from row) in table format, otherwise the normalized data
// payload in the configured machine format.
func RenderList[T any](rt *Runtime, res *cloudflare.ListResult[T], headers []string, row func(T) []string) error {
	if rt.Raw() {
		if res == nil {
			return nil
		}
		return rt.Printer().Raw(res.RawBody)
	}
	if rt.Format() == output.Table {
		rows := make([][]string, 0, len(res.Items))
		for _, it := range res.Items {
			rows = append(rows, row(it))
		}
		return rt.Printer().PrintTable(headers, rows)
	}
	return rt.Printer().Emit(res.Items)
}

// RenderGet renders a single-object service result: raw bytes in --raw
// mode, a one-row table in table format, otherwise the normalized object.
func RenderGet[T any](rt *Runtime, res *cloudflare.GetResult[T], headers []string, row func(T) []string) error {
	if rt.Raw() {
		if res == nil {
			return nil
		}
		return rt.Printer().Raw(res.RawBody)
	}
	if rt.Format() == output.Table {
		return rt.Printer().PrintTable(headers, [][]string{row(res.Item)})
	}
	return rt.Printer().Emit(res.Item)
}

// writerIsTerminal reports whether w is an interactive terminal. Non-file
// writers (pipes, buffers) are never terminals.
func writerIsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return fileIsTTY(f)
}

func readerIsTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	return fileIsTTY(f)
}

// fileIsTTY delegates to the platform check (termios ioctl on unix,
// GetConsoleMode on Windows). os.ModeCharDevice is not enough: /dev/null is a
// character device but not a terminal, and treating it as interactive made
// `auth login </dev/null` wait for the full timeout instead of failing fast.
func fileIsTTY(f *os.File) bool { return isTerminal(f) }
