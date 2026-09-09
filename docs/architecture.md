# Architecture

## API client

FlareADM SHOULD use Cloudflare's official Go SDK:

```text
github.com/cloudflare/cloudflare-go/v7
```

The current SDK is generated from Cloudflare's OpenAPI model by Stainless. This avoids
maintaining a full handwritten HTTP client while keeping the CLI implementation native Go.

The SDK SHALL be isolated behind FlareADM service interfaces:

```text
cmd
 |
application/service
 |
cloudflare adapter
 |
cloudflare-go
 |
Cloudflare REST API
```

Example abstraction:

```go
type ZoneService interface {
    List(ctx context.Context, req ListZonesRequest) ([]Zone, error)
    Get(ctx context.Context, ref ZoneRef) (Zone, error)
}
```

User-facing commands must not directly depend on generated SDK types. This boundary protects
the CLI from upstream SDK breaking changes.

## Raw API fallback

Broad API coverage takes time. To avoid blocking users on missing first-class commands,
FlareADM SHOULD provide:

```bash
flareadm api request <METHOD> <PATH>
```

Examples:

```bash
flareadm api request GET /zones

flareadm api request POST \
  /zones/<zone-id>/purge_cache \
  --body @request.json
```

The command reuses:

- authentication;
- profiles;
- retry handling;
- timeouts;
- logging;
- output handling.

First-class service commands remain preferred because they can provide validation and stable
normalized output.

## Go structure

```text
flareadm/
├── cmd/
│   ├── root.go
│   ├── configure/
│   ├── profile/
│   ├── account/
│   ├── zone/
│   ├── dns/
│   ├── cache/
│   └── api/
│
├── internal/
│   ├── cloudflare/
│   │   ├── client.go
│   │   ├── account.go
│   │   ├── zone.go
│   │   └── dns.go
│   │
│   ├── auth/
│   ├── config/
│   ├── profile/
│   ├── resolver/
│   ├── output/
│   ├── pagination/
│   ├── retry/
│   ├── confirm/
│   ├── errors/
│   └── version/
│
├── docs/
├── completions/
├── main.go
├── go.mod
├── LICENSE
└── README.md
```

Most implementation packages SHOULD remain under `internal/` until a genuine public Go API is
required.

## Dependencies

Dependency count should remain deliberately small. Proposed categories:

- Cloudflare API: `cloudflare-go/v7`
- CLI parser: Cobra or an equivalent mature Go CLI package
- TOML parsing: small dedicated TOML library
- YAML serialization: small YAML library

FlareADM SHOULD avoid a large configuration framework such as Viper unless a concrete
requirement justifies it. Standard-library implementations are preferred where they remain
maintainable.

## Performance targets

For local-only operations:

```text
flareadm --help
flareadm version
```

Target:

- effectively immediate startup;
- no network initialization;
- no configuration discovery requiring network access.

For API operations, FlareADM overhead should remain insignificant compared with Cloudflare
network/API latency.
