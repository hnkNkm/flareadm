// Package profile implements profile selection and the effective profile
// view used by configure/profile commands and credential resolution.
package profile

import "github.com/hnkNkm/flareadm/internal/config"

// DefaultName is the profile used when neither --profile nor
// FLAREADM_PROFILE select one.
const DefaultName = "default"

// ProfileEnvVar selects the active profile through the environment.
const ProfileEnvVar = "FLAREADM_PROFILE"

// ConfigKeys are the supported per-profile configuration keys in
// configuration-file order.
var ConfigKeys = []string{"account_id", "api_token_env", "default_zone"}

// ActiveName resolves the profile name: --profile wins, then
// FLAREADM_PROFILE, then the default profile name.
func ActiveName(flagValue string, env func(string) string) string {
	if flagValue != "" {
		return flagValue
	}
	if v := env(ProfileEnvVar); v != "" {
		return v
	}
	return DefaultName
}

// Effective is the active profile configuration for one command run.
type Effective struct {
	Name    string
	Profile *config.Profile // nil when the profile does not exist
	Exists  bool
}

// Select loads the effective profile for name out of cfg.
func Select(cfg *config.Config, name string) Effective {
	e := Effective{Name: name}
	if p, ok := cfg.Profile(name); ok {
		p := p
		e.Profile = &p
		e.Exists = true
	}
	return e
}
