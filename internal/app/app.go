// Package app wires the per-command runtime: global flag state, the
// configuration file, diagnostics logging, output rendering, credential
// resolution and the Cloudflare client. Command packages depend on Runtime
// but never on each other.
package app

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/hnkNkm/flareadm/internal/auth"
	"github.com/hnkNkm/flareadm/internal/cloudflare"
	"github.com/hnkNkm/flareadm/internal/config"
	"github.com/hnkNkm/flareadm/internal/confirm"
	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/logging"
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

	stdinIsTTY  bool
	stdoutIsTTY bool
}

// NewRuntime creates a Runtime bound to the process streams.
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

// Credential resolves the API token for the active profile.
func (rt *Runtime) Credential() (auth.Credential, error) {
	eff, err := rt.ActiveProfile()
	if err != nil {
		return auth.Credential{}, err
	}
	if eff.Exists {
		return auth.Require(eff.Profile)
	}
	return auth.Require(nil)
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
	cred, err := rt.Credential()
	if err != nil {
		return nil, err
	}
	rt.ProtectSecret(cred.Token)
	if rt.logger != nil {
		rt.logger.SetToken(cred.Token)
		rt.logger.Infof("profile %q; token source: %s; endpoint: %s",
			rt.ActiveProfileName(), cred.Source, endpointLabel(rt.EndpointURLFlag))
	}
	client, err := cloudflare.New(cloudflare.Options{
		Token:    cred.Token,
		Endpoint: rt.EndpointURLFlag,
		Timeout:  rt.TimeoutFlag,
		RawMode:  rt.RawFlag,
		Policy:   rt.Policy(),
		Logger:   rt.logger,
	})
	if err != nil {
		return nil, err
	}
	rt.client = client
	return client, nil
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

// writerIsTerminal reports whether w is a character device (an interactive
// terminal). Non-file writers (pipes, buffers) are not terminals.
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

func fileIsTTY(f *os.File) bool {
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}
