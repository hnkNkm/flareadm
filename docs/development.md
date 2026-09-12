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

## Local credentials for live testing

The CLI reads credentials only from the environment (or from a stored OAuth credential), so put a
token in a **gitignored** `.env` at the repository root:

```bash
# .env  (ignored by git — see .gitignore)
CLOUDFLARE_API_TOKEN=<your token>
# or: FLAREADM_API_TOKEN=<your token>
```

`.envrc` loads that file with `dotenv_if_exists .env`, so any shell that direnv sets up — including
the flake dev shell — sees the variable. `.env` must never be committed; keep real secrets out of
`.env.example` and out of the repository generally.

Two things must happen for a change to take effect:

- run `direnv allow` after editing `.envrc` (a new or modified `.envrc` needs approval), and
- re-enter a shell that already loaded the old environment (`cd .` or a new shell).

A program that is **already running** with the old environment — a long-lived editor, a terminal
tab, or an agent session — keeps the environment it started with and must be **restarted** to
inherit the new variable; `direnv reload` only rebuilds the environment for shells that are about
to start (`direnv exec`), it cannot inject a variable into a running process.

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
nix develop -c go test -race ./...
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

`nix build` works today: `flake.nix` pins a real fixed-output hash of the Go module fetch.

Regenerate that hash whenever `go.mod`/`go.sum` change: temporarily set
`vendorHash = pkgs.lib.fakeHash`, run `nix build`, and paste the hash printed in the error
message back into `flake.nix`.

The built binary reports the flake-derived version, which proves the `-ldflags` injection
works end to end:

```bash
./result/bin/flareadm version
# 0.1.0-unstable-<shortrev>
```

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

### Release process

How a release is cut:

1. Confirm `main` is green — CI runs build, vet, tests, race tests, lint, `govulncheck` and a
   Windows cross-compile.
2. Tag and push the tag:

   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

3. The tag triggers the release workflow, which runs GoReleaser to build the six target
   archives and publishes a GitHub release containing those archives, a `checksums.txt`
   SHA-256 file, Syft-generated SBOMs, and a cosign keyless signature and certificate for
   `checksums.txt`. Signing the checksum file covers every archive listed in it.
4. Signing uses cosign keyless (Sigstore Fulcio via the workflow's OIDC token). GitHub
   build-provenance attestations are not available for user-owned private repositories, which
   is why they are not used.

How a consumer verifies a downloaded artifact:

```bash
cosign verify-blob \
  --certificate-identity-regexp '^https://github\.com/hnkNkm/flareadm/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature checksums.txt.sig \
  --certificate checksums.txt.pem \
  checksums.txt
sha256sum --check checksums.txt
```

`cosign` is provided by the flake dev shell; if it is not installed globally, run the
verification as `nix develop -c cosign verify-blob …`.

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
