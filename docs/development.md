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

### Verified local commands

Run Go tooling through the flake dev shell with `nix develop -c <cmd>`. The following command
set is verified against the current tree:

```bash
nix develop -c go build ./...
nix develop -c go vet ./...
nix develop -c go test ./...
nix develop -c golangci-lint run
nix develop -c gofmt -l .
nix fmt
nix flake check
```

`go test ./...` runs fully offline: it exercises `httptest` fakes and makes no live Cloudflare
calls.

## Nix package

`packages.default` builds `flareadm` with `CGO_ENABLED=0`, `-trimpath` and stripped binaries.
The version is derived from the flake revision and injected into
`internal/version.Version`:

```bash
nix build
./result/bin/flareadm version
```

### Bootstrap note

`go.mod` and `go.sum` are now committed, so `nix build` proceeds as far as fetching Go module
dependencies — which is exactly where it stops. `flake.nix` still pins
`vendorHash = pkgs.lib.fakeHash`, a deliberately invalid placeholder.

Run `nix build` once: Nix fails and prints the correct dependency hash in the error message.
Paste that hash into the `vendorHash` attribute in `flake.nix`, then run `nix build` again to
produce `./result/bin/flareadm`.

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

Cross-compilation: release artifacts are produced by GoReleaser; CI additionally runs
`GOOS=windows GOARCH=amd64 go build ./...` to catch Windows-only build breaks before tagging.

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
