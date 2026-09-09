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
│   └── verify
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
├── cache
│   └── purge
└── api
    └── request
```

`api request` is an escape hatch for endpoints not yet modeled as first-class commands:

```bash
flareadm api request GET /zones
```

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
