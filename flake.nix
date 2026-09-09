{
  description = "FlareADM — a fast, standalone administration CLI for Cloudflare";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    {
      self,
      nixpkgs,
    }:
    let
      # Canonical repository and Go module path. Keep in sync with go.mod.
      repo = "github.com/hnkNkm/flareadm";

      version = "0.1.0-unstable-${self.shortRev or "dirty"}";

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: rec {
        default = flareadm;

        flareadm = pkgs.buildGoModule {
          pname = "flareadm";
          inherit version;

          src = self;

          # Fixed-output hash of the go module fetch for the current go.mod/go.sum.
          # Regenerate with `nix build` when the dependency set changes.
          vendorHash = "sha256-MYznkGjhMRnHb5oPn1rO+uPHypndsU8bY6EP/qwGoD0=";

          ldflags = [
            "-s"
            "-w"
            "-X"
            "${repo}/internal/version.Version=${version}"
          ];

          meta = {
            description = "Fast, standalone administration CLI for Cloudflare";
            homepage = "https://${repo}";
            license = pkgs.lib.licenses.asl20;
            mainProgram = "flareadm";
            platforms = pkgs.lib.platforms.unix;
          };
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          name = "flareadm";

          packages = with pkgs; [
            go
            gopls
            gotools
            golangci-lint
            delve
            goreleaser
            git
            nixfmt
          ];

          shellHook = ''
            # Build only with the Go toolchain provided by this flake.
            export GOTOOLCHAIN=local

            echo "flareadm dev shell — $(go version)"
          '';
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
