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

```text
r2
kv
d1
queues
hyperdrive
vectorize
```

The scope is remote administration only.

### v0.4 — Zero Trust

```text
tunnel
access
gateway
devices
service tokens
zero-trust configuration
```

### v0.5 — Workers platform administration

```text
workers metadata
deployments
routes
domains
secrets
pages projects/deployments
```

Local development remains out of scope.

### v0.6 — Operations and observability

```text
audit logs
logpush
analytics
notifications
health checks
load balancing
registrar/domain administration where API access permits
```

### v1.0

v1.0 should be declared only after:

- command naming rules are stable;
- configuration format is stable;
- normalized JSON is versioned;
- major administration surfaces have broad coverage;
- release/update process is established;
- Windows/macOS/Linux behavior is validated;
- documentation contains complete command discovery.

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
