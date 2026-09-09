# Design

## Summary

FlareADM is a single-binary, cross-platform command-line interface for administering
Cloudflare resources.

The project is intentionally **not** a replacement for Wrangler's local-development
workflow. Its role is closer to the AWS CLI:

```text
terminal / script / CI / agent
            |
         flareadm
            |
   Cloudflare REST API
```

The primary objective is to expose Cloudflare account and infrastructure management through
a stable, consistent and automation-friendly command hierarchy.

```bash
flareadm account list

flareadm zone list
flareadm zone get --zone example.com

flareadm dns record list --zone example.com

flareadm dns record create \
  --zone example.com \
  --type A \
  --name api \
  --content 192.0.2.10 \
  --proxied

flareadm r2 bucket list
flareadm zero-trust tunnel list
flareadm waf ruleset list --zone example.com
```

## Background

Cloudflare has several overlapping CLI surfaces.

### Wrangler

Wrangler remains the primary tool for Workers local development, deployment and
product-specific development workflows:

```bash
wrangler dev
wrangler deploy
wrangler tail
wrangler d1 migrations apply
```

FlareADM does not attempt to reproduce the local runtime, bundling, Miniflare, project
configuration or Worker development experience.

### Cloudflare `cf`

Cloudflare announced the unified `cf` CLI on 2026-04-13. Cloudflare states that:

- it has more than 100 products and nearly 3,000 HTTP API operations;
- the current `cf` release is a Technical Preview;
- the public preview covers only a small subset of products;
- broader API coverage is being tested internally;
- the long-term plan combines the new CLI model with Wrangler and local development.

As of 2026-09-09, Cloudflare documentation still describes the unified `cf` CLI as a
Technical Preview. FlareADM therefore targets a narrower problem:

> Remote administration of Cloudflare resources through a small native executable.

### `flarectl`

Cloudflare already ships `flarectl` from the `cloudflare-go` project, including a Homebrew
formula, so the name is unavailable. The existing tool is useful but is not designed as a
comprehensive AWS-CLI-like management interface.

## Positioning

Recommended README positioning:

> FlareADM is a fast, standalone administration CLI for Cloudflare.
>
> It is designed for operators, scripts, CI systems and agents that need to inspect and manage
> Cloudflare resources without a JavaScript runtime.
>
> FlareADM complements Wrangler rather than replacing it: use Wrangler for Workers application
> development and FlareADM for remote account and infrastructure administration.

Avoid positioning based only on "a single-binary alternative to Cloudflare CLI." That
distinction is weak because both existing and emerging tools can also provide standalone
distribution. The durable distinction is:

> **A native, operations-focused Cloudflare management interface with a stable AWS-CLI-like
> contract.**

## Goals

FlareADM SHALL:

1. Ship as a single executable.
2. Run without Node.js, Python or another language runtime.
3. Support Linux, macOS and Windows.
4. Provide a consistent Cloudflare management command hierarchy.
5. Support interactive terminal use, shell scripts, CI/CD and AI agents.
6. Provide deterministic JSON output.
7. Support multiple Cloudflare accounts through profiles.
8. Resolve human-friendly names such as zone names where practical.
9. Handle pagination, rate limits and API errors consistently.
10. Provide a path to broad Cloudflare REST API coverage.
11. Remain useful even if Cloudflare's official `cf` CLI matures.

## Non-goals

FlareADM SHALL NOT initially implement:

- a Workers local runtime;
- Miniflare functionality;
- JavaScript/TypeScript bundling;
- `wrangler dev`;
- framework integrations;
- Vite integration;
- local D1/R2/KV emulation;
- Worker source builds;
- package management;
- a Terraform replacement;
- a general-purpose IaC engine;
- plugin execution inside the FlareADM process.

Wrangler remains the recommended tool for Cloudflare application development.

## Design principles

### Administration first

Every feature must answer the question:

> Is this useful for inspecting, configuring or operating a remote Cloudflare resource?

Development-only features are out of scope.

### Consistency over API mirroring

The Cloudflare REST API shape must not directly dictate the user-facing CLI grammar. The user
interface is a compatibility surface and must be intentionally designed.

### Stable machine interface

JSON output, exit codes and command names are treated as public APIs.

### Safe by default

Destructive commands require explicit intent. Interactive and non-interactive behavior must be
deterministic.

### Native and lightweight

FlareADM is distributed as one native Go executable with no runtime dependency.

### No telemetry by default

The CLI SHALL NOT send FlareADM usage telemetry unless a future version introduces an explicit
opt-in mechanism.

## Naming

Name research was performed on 2026-09-09 against GitHub, general web search and visible
package/tool usage. Candidates rejected because of existing collisions: `cf`, `cfctl`,
`flarectl`, `cloudctl`, `flare`, `cfcli`, `cfman`, `cfops`, `flareops`, `cflare`. Reserved
fallbacks: `flarecm`, `cfcm`. **FlareADM** had no matching CLI/package/Homebrew/GitHub project
in the performed search and was selected.

Reasons for the selected name:

1. Communicates administration rather than application development.
2. Does not collide with Cloudflare's `cf` or `flarectl`.
3. Does not imply that the tool is an official Cloudflare CLI.
4. Is short enough for frequent terminal use.
5. Leaves room to cover DNS, security, storage, Zero Trust and account management without tying
   the name to one product.

Name availability must be checked again immediately before publishing the first public
repository/package.

## Differentiation

At least two third-party projects already target this problem:

- `@agileguy/cf-cli` — a Cloudflare REST API CLI with 50+ resource groups, single-binary
  distribution, profiles, JSON/YAML/CSV/table output, automatic pagination and rate-limit
  retry handling. Single-binary distribution alone is therefore not sufficient
  differentiation.
- `cf-api` — broad API access with human-oriented verbs and a raw API escape hatch, but it
  depends on Node.js/Bun.

FlareADM differentiates around operational quality rather than endpoint count:

- native Go executable;
- no JavaScript runtime;
- administration-only scope;
- deliberately designed and stable command hierarchy;
- predictable normalized machine output;
- stable exit-code contract;
- secure profile/credential handling;
- consistent account and zone resolution;
- safe destructive operations;
- mature pagination and retry semantics;
- raw API fallback for unsupported endpoints;
- explicit compatibility/version policy;
- strong CI and AI-agent ergonomics;
- signed, checksummed releases and a small dependency surface.

## Research references

Checked 2026-09-09:

- Cloudflare: Building a CLI for all of Cloudflare — <https://blog.cloudflare.com/cf-cli-local-explorer/>
- Cloudflare agent setup documentation describing `cf` as Technical Preview — <https://developers.cloudflare.com/agent-setup/opencode/>
- Cloudflare Go SDK — <https://github.com/cloudflare/cloudflare-go>
- Cloudflare `flarectl` Homebrew formula — <https://formulae.brew.sh/formula/flarectl>
- Cloudforet / SpaceONE `cfctl` — <https://github.com/cloudforet-io/cfctl>
- `@agileguy/cf-cli` — <https://github.com/agileguy/cf-cli>
- `cf-api` — <https://github.com/dux/cf-api>
- `flareops` — <https://docs.rs/crate/flareops/latest>
- `cflare` — <https://pypi.org/project/cflare/>
