# CLI reference

## Command model

The canonical grammar is:

```text
flareadm <service> [resource] <operation> [options]
```

Examples:

```bash
flareadm account list
flareadm zone get
flareadm dns record list
flareadm r2 bucket create
flareadm zero-trust tunnel list
flareadm waf ruleset get
```

### Standard operations

Where applicable, resources SHALL use:

```text
list
get
create
update
delete
```

Additional verbs are permitted only when CRUD does not accurately represent the action:

```text
import
export
purge
enable
disable
attach
detach
rotate
tail
```

Synonymous verbs such as `show`, `info`, `describe` and `remove` SHALL NOT be introduced when a
standard verb already exists.

### Naming rules

- Commands use lowercase kebab-case.
- Resource names must remain stable after v1.0.
- User-facing names should follow Cloudflare terminology where doing so does not damage
  consistency.
- IDs and human-readable names should both be accepted when safe and unambiguous.

## Initial command tree

```text
flareadm
├── version
├── configure
│   ├── init
│   ├── get
│   ├── set
│   └── list
├── profile
│   ├── list
│   ├── get
│   ├── create
│   ├── update
│   └── delete
├── auth
│   ├── verify
│   ├── scopes
│   ├── login
│   ├── logout
│   └── status
├── account
│   ├── list
│   └── get
├── zone
│   ├── list
│   └── get
├── dns
│   ├── record
│   │   ├── list
│   │   ├── get
│   │   ├── create
│   │   ├── update
│   │   ├── delete
│   │   ├── import
│   │   └── export
│   └── dnssec
│       ├── get
│       ├── enable
│       └── disable
├── ssl
│   ├── setting get|update
│   ├── universal get|enable|disable
│   └── certificate-pack list|get
├── certificate list|get|create|delete
├── ruleset list|get|create|update|delete
├── waf
│   └── ruleset list|get|update
├── redirect
│   └── rule list|get|create|update|delete
├── r2
│   └── bucket list|get|create|delete
├── kv
│   ├── namespace list|get|create|delete
│   └── key list|get|put|delete
├── d1
│   └── database list|get|create|update|delete|query|raw|export|import|bookmark|restore
├── queue
│   ├── list|get|create|update|delete|metrics|purge
│   ├── consumer list|get|create|update|delete
│   └── message push|pull|peek|ack|delete
├── hyperdrive config list|get|create|update|delete
├── vectorize
│   ├── index list|get|create|delete|info
│   │   └── metadata list|create|delete
│   └── vector insert|upsert|query|get|delete|list
├── zero-trust
│   ├── tunnel
│   │   ├── list|get|create|update|delete|token
│   │   ├── connection list|get|delete
│   │   └── configuration get|update
│   ├── route list|get|create|update|delete
│   ├── organization get|update
│   ├── access
│   │   ├── app
│   │   │   ├── list|get|create|update|delete
│   │   │   └── policy list|get|create|update|delete
│   │   ├── policy list|get|create|update|delete
│   │   ├── group list|get|create|update|delete
│   │   ├── identity-provider list|get|create|update|delete
│   │   └── service-token list|get|create|update|delete|rotate
│   ├── gateway
│   │   ├── rule list|get|create|update|delete
│   │   ├── list
│   │   │   ├── list|get|create|update|delete
│   │   │   └── item list|create|delete
│   │   └── location list|get|create|update|delete
│   └── device
│       ├── list|get
│       ├── physical-device list|get|delete|revoke
│       ├── posture list|get|create|update|delete
│       └── settings get|update
├── workers
│   ├── script
│   │   ├── list|update|delete
│   │   ├── content get
│   │   ├── settings get|update
│   │   ├── secret list|get|create|delete
│   │   ├── version list|get|create
│   │   ├── deployment list|get|create|delete
│   │   ├── schedule get|update
│   │   └── subdomain get|enable|disable
│   ├── route list|get|create|update|delete
│   ├── domain list|get|create|delete
│   ├── subdomain get|update|delete
│   └── account-settings get|update
├── pages
│   └── project
│       ├── list|get|create|update|delete
│       ├── deployment list|get|delete
│       └── domain list|get|create|update|delete
├── logpush
│   ├── job list|get|create|update|delete
│   ├── dataset
│   │   ├── field list
│   │   └── job list
│   └── transformer
│       ├── list|get|create|update|delete
│       ├── content get
│       └── version list
├── healthcheck
│   ├── list|get|create|update|delete
│   └── preview create|get|delete
├── load-balancer
│   ├── list|get|create|update|delete
│   ├── pool
│   │   ├── list|get|create|update|delete
│   │   └── health get
│   ├── monitor list|get|create|update|delete
│   └── region list|get
├── notifications
│   ├── policy list|get|create|update|delete
│   ├── webhook list|get|create|update|delete
│   ├── pagerduty list|delete
│   ├── silence list|get|create|update|delete
│   ├── history list
│   └── alert-type list
├── audit-log list
├── analytics
│   ├── summary get DATASET
│   ├── timeseries get DATASET
│   └── top-n get DATASET
├── logs query
├── registrar
│   ├── domain list|get|update
│   └── registration list|get|update
├── page-rule list|get|create|update|delete
├── cache
│   ├── purge
│   └── rule list|get|create|update|delete
└── api
    └── request
```

`api request` is an escape hatch for endpoints not yet modeled as first-class commands:

```bash
flareadm api request GET /zones
```

### Structured DNS record types

`dns record create` and `dns record update` accept structured types (CAA, CERT, DNSKEY, DS,
HTTPS, LOC, NAPTR, SMIMEA, SRV, SSHFP, SVCB, TLSA, URI) through the Cloudflare `data`-field
flags. The authoritative per-type flag list is `flareadm dns record create --help` and
`flareadm dns record update --help`.

`certificate create --private-key` accepts only the `@file` form (see
[configuration.md](configuration.md)).

### Rules engine

Rulesets are the single mechanism behind WAF, cache and redirect rules. The phase-scoped
`cache rule` and `redirect rule` commands edit the phase entrypoint rules array and preserve
existing rules; `--rules @file` takes a Cloudflare rules array.

Page rules are legacy: use `ruleset`, `cache rule` or `redirect rule` for new configuration.
Account-scoped groups (`r2`, `kv`) resolve the account through the standard resolution order.

`d1 database query|raw` print per-statement results (JSON keeps the full statement structure);
`queue message` verbs use the shared confirmation rules for destructive operations.

`hyperdrive config --origin` and `vectorize vector insert|upsert --vectors` are `@file`-only
(the origin object and vector payloads carry credentials); both are registered as protected
secrets and never appear in diagnostics or errors.

`auth login` requests a read-only scope set by default; `--all-scopes` requests the full scope
catalog (see [configuration.md](configuration.md)). `auth scopes` lists the live scope ids the
catalog is built from — the ids to select when registering the OAuth client, and the ones `--scopes`
accepts. `auth logout` revokes and deletes the stored
credential (`--local` skips revocation); `auth status` reports which credential source wins.

## Global options

The following global options are reserved:

```text
--profile <name>
--account-id <id>
--zone <name-or-id>

--output <table|json|yaml|text>
--json
--raw

--page-size <n>
--max-items <n>
--no-paginate

--yes
--dry-run
--no-input

--no-color
--verbose
--debug

--timeout <duration>
--endpoint-url <url>
```

Rules:

- `--json` is a convenience alias for `--output json`.
- `--raw` returns the closest practical representation of the Cloudflare API response and
  bypasses FlareADM's normalized output model.
- `--dry-run` is only advertised on commands where FlareADM can produce a trustworthy preview.

## Output contract

### Human output

Default output for an interactive terminal is a compact table:

```text
ID                                NAME         STATUS
023e105f4ecef8ad9ca31a8372d0c353  example.com  active
```

### JSON output

`--json` is intended for scripts and agents. FlareADM's normalized JSON is a versioned
compatibility surface:

```json
{
  "version": "v1",
  "data": [
    {
      "id": "023e105f4ecef8ad9ca31a8372d0c353",
      "name": "example.com",
      "status": "active"
    }
  ],
  "meta": {
    "count": 1
  }
}
```

### Raw output

For users requiring Cloudflare-native fields:

```bash
flareadm zone list --raw --json
```

The raw representation may change when the upstream Cloudflare API changes. The normalized
representation only changes according to FlareADM's compatibility policy.

### Non-TTY behavior

When stdout is not a TTY:

- no spinner;
- no progress animation;
- no ANSI color unless explicitly requested;
- no prompts when `--no-input` is set;
- machine output is written only to stdout;
- diagnostics are written to stderr.

## Query and filtering

Initial releases SHOULD support server-side filters exposed by the Cloudflare API. A
client-side query language may be added later:

```bash
flareadm zone list --query 'data[].name'
```

The query implementation is not required for v0.1.

## Pagination

Pagination SHALL be implemented centrally. Default behavior for normal list commands:

```text
auto-pagination enabled
```

Options:

```bash
--page-size 100
--max-items 500
--no-paginate
```

Pagination behavior must not differ arbitrarily between services.

### Termination

Auto-pagination stops deterministically at the first of:

- an empty page (the API returned no items);
- a short page (fewer items than `--page-size`);
- `result_info.total_pages` reached (when the API supplies it);
- cursor exhaustion (cursor-paginated endpoints);
- `--max-items` reached;
- `--no-paginate`, which fetches only the first page.

If none of these is reached, a safety cap of 1000 pages bounds the loop. Exceeding it never
hangs or pages forever: the command exits 1 with a diagnostic on stderr
(`pagination safety limit exceeded after 1000 pages …`) advising `--max-items`, `--page-size`
or `--no-paginate`.

## Retry and rate-limit behavior

FlareADM SHALL:

- respect `Retry-After` where available;
- retry eligible requests after HTTP 429;
- use exponential backoff with jitter;
- retry transient 5xx failures where safe;
- avoid automatic retries for unsafe mutations unless idempotency can be guaranteed;
- expose retry information in debug logs.

Retry behavior belongs in the shared HTTP/API layer rather than individual commands.

## Destructive operations

Examples:

```bash
flareadm dns record delete ...
flareadm zone delete ...
flareadm r2 bucket delete ...
```

Interactive terminal:

```text
Delete DNS record api.example.com? [y/N]
```

Automation:

```bash
flareadm dns record delete ... --yes
```

When stdin is non-interactive and confirmation would otherwise be required, FlareADM SHALL
fail rather than hang waiting for input.

## Exit codes

Stable initial exit-code contract:

| Code | Meaning |
| ---: | --- |
| `0` | Success |
| `1` | Unclassified failure |
| `2` | Invalid CLI usage or input |
| `3` | Authentication failure |
| `4` | Permission denied |
| `5` | Resource not found |
| `6` | Conflict / invalid resource state |
| `7` | Rate-limit failure after retries |
| `8` | Network / timeout failure |
| `9` | Partial failure in a multi-resource operation |

Exit-code meanings must remain backwards compatible within a major version.

## Shell completion

FlareADM SHOULD generate completions for:

```text
bash
zsh
fish
PowerShell
```

```bash
flareadm completion zsh
```

`flareadm completion bash|zsh|fish|powershell` all emit a working script. The full command
surface is also generated into `docs/commands.md`.

Completion covers subcommand and flag **names** as well as **values**: enumerated flag values
(output formats, LOC directions, scope categories and the like), profile names, and — best effort —
zone names and ids. Value completion is offline-safe by contract: it never prompts, makes a single
attempt with a short deadline and no retries, and stays silent when there is no credential, no
network or no match.

### Short name

`flareadm` is the canonical name and stays that way: the documented command paths, the generated
reference, the release archives and the Nix package all depend on it. Any short name works as an
alias — `fa` is used as the example here.

| Shell | Alias | Completion |
| --- | --- | --- |
| zsh | `alias fa=flareadm` | nothing more is needed: zsh substitutes the alias before completion unless `COMPLETE_ALIASES` is set, and the generated script handles that case |
| bash | `alias fa=flareadm` | add `complete -o default -F __start_flareadm fa` — the generated bash script keys completions to the literal name |
| fish | `abbr -a fa flareadm` | the abbreviation expands on the command line, so normal completion applies; `complete -c fa -w flareadm` also works |
| PowerShell | — | `Register-ArgumentCompleter -CommandName fa -ScriptBlock ${__flareadmCompleterBlock}` |

In scripts and CI prefer a **function** over an alias: aliases do not expand in non-interactive
bash. `fa() { flareadm "$@"; }` works in bash and zsh; in fish use
`function fa; flareadm $argv; end`.

The Nix package installs a convenience symlink, `fa`, next to `flareadm` in the store output, so a
short name works without any shell configuration once the package is on `PATH`. The symlink is a
second entry point to the same binary: usage lines and `--help` still print `flareadm`, because the
program does not read `argv[0]` — that is deliberate, not a bug.

This mirrors what upstreams do: Kubernetes documents `alias k=kubectl` plus
`complete -o default -F __start_kubectl k`, and none of the comparable CLIs (`kubectl`, `gh`,
`terraform`, `docker`, `op`) ships a second binary for short typing. `fa`, `fadm`, `fl`, `flr` and
`fad` are all free as executable names in nixpkgs, Homebrew and Debian — none of them installs a
`/usr/bin` entry with such a name.

## AI-agent compatibility

AI agents are a first-class consumer, but FlareADM remains a normal CLI. Required
agent-friendly behavior:

- stable command grammar;
- `--json` everywhere meaningful;
- deterministic stdout/stderr separation;
- stable exit codes;
- noninteractive mode;
- no decorative output in machine mode;
- complete `--help`;
- consistent operation names.

Future functionality (deferred until the core command model is stable):

```bash
flareadm schema dns record create
```

or:

```bash
flareadm dns record create --generate-cli-skeleton
```

Example skeleton:

```json
{
  "zone": "",
  "type": "A",
  "name": "",
  "content": "",
  "ttl": 1,
  "proxied": false
}
```
