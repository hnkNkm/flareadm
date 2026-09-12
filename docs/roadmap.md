# Roadmap

## MVP: v0.1

v0.1 should prove the architecture rather than maximize API coverage.

### Required commands

Core:

```text
version
configure
profile
auth verify
```

Accounts:

```text
account list
account get
```

Zones:

```text
zone list
zone get
```

DNS:

```text
dns record list
dns record get
dns record create
dns record update
dns record delete
dns record import
dns record export
```

DNSSEC:

```text
dns dnssec get
dns dnssec enable
dns dnssec disable
```

Cache:

```text
cache purge
```

Escape hatch:

```text
api request
```

### Infrastructure requirements

- profiles;
- API-token auth;
- table/json/yaml output;
- normalized error model;
- stable exit codes;
- central pagination;
- retry handling;
- zone resolution;
- confirmation handling;
- shell completion;
- release builds for Linux/macOS/Windows.

### Known limitations

v0.1 known limitations:

- client-side `--query` is not implemented;
- OS keychain credential storage is not implemented;
- `--output table` is not supported for `dns record export`;
- Windows cross-compilation is exercised in CI but not shipped by the Nix package.

## Later releases

### v0.2 — Zone and security administration

Delivered (slice 1):

- zone SSL/TLS settings `get`/`update`;
- Universal SSL `get`/`enable`/`disable`;
- custom certificates `list`/`get`/`create`/`delete`;
- certificate-pack `list`/`get`.

Delivered (slice 2):

- rulesets `list`/`get`/`create`/`update`/`delete`;
- WAF ruleset view `list`/`get`/`update`;
- cache rules `list`/`get`/`create`/`update`/`delete`;
- redirect rules `list`/`get`/`create`/`update`/`delete`;
- page rules `list`/`get`/`create`/`update`/`delete` (legacy; new configuration should use
  rulesets phases).

Still open:

- advanced certificate ordering / DCV workflows;
- certificate-pack `create`/`edit`/`delete`;
- remaining SSL subresources (analyze, recommendation, verification records);
- mTLS.

### v0.3 — Developer storage/services administration

Shipped as **v0.3.0** (2026-09-10).

Delivered:

- r2 buckets `list`/`get`/`create`/`delete`;
- kv namespaces `list`/`get`/`create`/`delete` and keys `list`/`get`/`put`/`delete`;
- d1 databases (`list`/`get`/`create`/`update`/`delete`, `query`/`raw`, `export`/`import`,
  `bookmark`, `restore`);
- queues (`list`/`get`/`create`/`update`/`delete`, `metrics`, `purge`, consumers, messages);
- hyperdrive configs (`list`/`get`/`create`/`update`/`delete`);
- vectorize indexes (`list`/`get`/`create`/`delete`/`info`, plus metadata and vector operations).

Deferred in v0.3:

- R2 objects and custom domains (S3 API with separate credentials);
- KV bulk operations;
- D1 `--fields` subset selection and read-replication status reads;
- queue consumer typed settings (shipped as `--settings @file`);
- D1 export polling convenience.

The scope is remote administration only.

### v0.4 — Zero Trust

Shipped as **v0.4.0** (2026-09-10).

Delivered:

- tunnels (`list`/`get`/`create`/`update`/`delete`/`token`), tunnel connections
  (`list`/`get`/`delete`) and remote `configuration get`/`update`;
- private network routes `list`/`get`/`create`/`update`/`delete`;
- organization `get`/`update`;
- Access applications (`list`/`get`/`create`/`update`/`delete`) with application-scoped
  policies;
- Access reusable policies, groups, identity providers and service tokens
  (`list`/`get`/`create`/`update`/`delete`/`rotate`);
- Gateway rules, lists (with items) and locations;
- device registrations, the physical-device fleet, posture rules and account device settings.

Deferred in v0.4:

- DEX / device-experience endpoints;
- GraphQL-only surfaces;
- mTLS certificates.

### v0.5 — Workers platform administration

Delivered:

- Workers scripts (`list`/`update`/`delete`), deployed `content get`, `settings get`/`update`
  and `secret list`/`get`/`create`/`delete`;
- script `version list`/`get`/`create`, `deployment list`/`get`/`create`/`delete`,
  `schedule get`/`update` and `subdomain get`/`enable`/`disable`;
- account-scoped `route`, `domain`, `subdomain` and `account-settings` administration;
- Pages projects (`list`/`get`/`create`/`update`/`delete`) with `deployment list`/`get`/`delete`
  and `domain list`/`get`/`create`/`update`/`delete`.

Deferred in v0.5:

- deployment creation via manifests/assets;
- retry/rollback verbs pending a docs amendment;
- tail/streaming;
- Durable Objects internals;
- Workers AI.

Local development remains out of scope.

### v0.6 — Operations and observability

Delivered:

- Logpush `job` CRUD, dataset `field`/`job` discovery and `transformer` CRUD with `content get`
  and `version list`;
- zone `healthcheck` CRUD with `preview create`/`get`/`delete`;
- `load-balancer` CRUD with `pool` (and `health`), `monitor` and `region`;
- `notifications` policies, webhooks, PagerDuty, silences, history and alert types;
- `audit-log list`;
- `analytics summary`/`timeseries`/`top-n get DATASET`;
- `logs query`;
- `registrar domain` and `registrar registration`.

Deferred in v0.6:

- GraphQL-only analytics datasets;
- logpull / real-time streaming;
- notifications PagerDuty connect/link;
- registrar create.

### v1.0

Declared and released as **v1.0.0** (2026-09-11). Every prerequisite is met: command naming
rules and the configuration format are stable, normalized JSON is versioned, the surface
covers 320 commands across v0.1–v0.6, the release/update process is established and verified
(checksums, SBOMs and cosign keyless signatures), Windows/macOS/Linux behavior is validated by
the platform matrix, and complete command discovery ships as `docs/commands.md` with a CI
drift check.

The compatibility policy below is now in effect for post-1.0 releases.

### v1.1

Shipped as **v1.1.0** (2026-09-12).

Patch **v1.1.1** (2026-09-12) fixes the browser handoff — an opener chain with a `$BROWSER`
override, a best-effort fallback that prints the authorize URL once, and no blocking on a hung
opener — and replaces the terminal check with a real terminal test, so `/dev/null`, pipes,
regular files and closed stdin fail fast with exit 2. No API or flag changes.

Patch **v1.1.2** (2026-09-12) always surfaces the authorize URL — printed on stderr before the
browser handoff, and on stdout with `--no-browser` — and prints a one-time diagnostic after about
15 seconds without a callback, naming the client-id, redirect-URI and scope checks to make. No API
or flag changes.

Delivered:

- `auth login` / `auth logout` / `auth status`, plus `auth verify` for OAuth credentials;
- a per-profile OAuth credential store (owner-only `0700`/`0600`, atomic, versioned) beside the
  configuration file;
- environment-first resolution: the stored OAuth credential is the last fallback;
- refresh handling: a proactive expiry window plus a single refresh-and-retry on HTTP 401;
- OAuth identity verification (`GET /user`) and scope-aware 403 guidance;
- actionable `auth login` failure messages (invalid scope, unauthorized client, invalid grant).

Still open:

- Phase 0 live scope verification — the catalog in `cmd/auth/scopes.go` ships as a candidate set
  (`oauth.md` §5 Q5, §13 Q2);
- the public-vs-private OAuth client decision (§13 Q1);
- the default scope set remains read-only (§13 Q3);
- optional device flow and OS keychain storage.

Specification: [oauth.md](oauth.md).

## Compatibility policy

Before v1.0, command changes are permitted but must be documented.

After v1.0:

### Stable

- command paths;
- global flag meanings;
- normalized JSON field names;
- exit-code meanings;
- configuration format.

### May track upstream changes

- `--raw` response fields;
- Cloudflare-specific enum values;
- newly added resources;
- deprecated upstream APIs.

Breaking changes require a new FlareADM major version unless required by an upstream security
issue.

## Open design decisions

To be finalized during implementation of v0.1:

1. Cobra versus a smaller CLI parser.
2. Exact normalized JSON envelope.
3. Whether `--output yaml` is part of v0.1 or v0.2.
4. Whether OS keychain credential storage belongs in v0.x.
5. Exact command naming for services where Cloudflare's API hierarchy is unusually deep.
6. Whether `api request` should permit arbitrary hosts or always restrict requests to configured
   Cloudflare API endpoints.
7. Whether client-side `--query` uses JMESPath or another query language.

## Recommended implementation order

```text
1. root command + global flags
2. config/profile loader
3. token/auth resolver
4. Cloudflare API adapter
5. error normalization
6. output abstraction
7. account list/get
8. zone list/get + zone resolver
9. DNS CRUD
10. pagination/retry hardening
11. api request escape hatch
12. completions
13. release pipeline
```

This sequence validates the cross-cutting architecture before adding a large number of
Cloudflare services.
