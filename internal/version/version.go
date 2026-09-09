// Package version holds the FlareADM release version.
//
// The Nix package definition injects the flake-derived version into Version
// via -ldflags "-X github.com/hnkNkm/flareadm/internal/version.Version=...".
package version

// Version is the FlareADM version. It is overridable at build time through
// the linker (see flake.nix); development builds report the next release.
var Version = "0.1.0"

// String returns the version string.
func String() string { return Version }
