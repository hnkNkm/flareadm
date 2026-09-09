# Development

## Toolchain

The repository is a Nix flake. It provides a pinned Go toolchain and all development tools, so
no global Go installation is required.

| Output | Purpose |
| --- | --- |
| `devShells.default` | Go, gopls, gotools, golangci-lint, delve, goreleaser, git, nixfmt |
| `packages.default` | `flareadm` binary (`buildGoModule`) |
| `formatter` | `nixfmt` |

The dev shell sets `GOTOOLCHAIN=local` so builds always use the Go version provided by the
flake.

## Quick start

```bash
nix develop
```

or, with direnv:

```bash
direnv allow
```

Verified tool versions from the pinned nixpkgs revision:

```text
go 1.26.7
gopls 0.23.0
golangci-lint 2.13.2
goreleaser 2.17.1
delve 1.27.1
```

## Build, test, lint

```bash
go build ./...
go test ./...
golangci-lint run
nix fmt
nix flake check
```

## Nix package

`packages.default` builds `flareadm` with `CGO_ENABLED=0`, `-trimpath` and stripped binaries.
The version is derived from the flake revision and injected into
`internal/version.Version`:

```bash
nix build
./result/bin/flareadm version
```

### Bootstrap note

The package definition requires `go.mod` and `go.sum`, which do not exist yet. Until they do,
`nix build` fails with `go.mod file not found`.

`flake.nix` currently pins `vendorHash = lib.fakeHash`. Once `go.mod`/`go.sum` are committed,
run `nix build` and replace `vendorHash` with the hash printed in the error message.

## Release

Initial release targets:

```text
linux/amd64
linux/arm64
darwin/amd64
darwin/arm64
windows/amd64
windows/arm64
```

Build configuration should prefer `CGO_ENABLED=0` where compatible. Cross-platform release
artifacts are produced by GoReleaser (available in the dev shell); the Nix package builds
native binaries for `x86_64-linux`, `aarch64-linux`, `x86_64-darwin` and `aarch64-darwin`.

Distribution plan:

1. GitHub Releases
2. checksums
3. signed release artifacts
4. Homebrew tap
5. Scoop
6. WinGet
7. nixpkgs
8. Chocolatey if useful

No package manager is required to execute a downloaded FlareADM binary.

### Release security

Releases SHOULD include:

- SHA-256 checksums;
- signed release artifacts or attestations;
- SBOM;
- reproducible/minimized build metadata where practical;
- `-trimpath`;
- pinned Go module dependencies;
- Dependabot/Renovate or equivalent dependency update automation;
- vulnerability scanning in CI.
