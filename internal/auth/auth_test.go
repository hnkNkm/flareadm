package auth

import (
	"strings"
	"testing"

	"github.com/hnkNkm/flareadm/internal/config"
	"github.com/hnkNkm/flareadm/internal/errors"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestResolvePrecedence(t *testing.T) {
	cases := []struct {
		name    string
		profile *config.Profile
		env     map[string]string
		want    string // source env var
	}{
		{
			name:    "profile api_token_env wins",
			profile: &config.Profile{APITokenEnv: "CF_PERSONAL_TOKEN"},
			env:     map[string]string{"CF_PERSONAL_TOKEN": "personal", "FLAREADM_API_TOKEN": "flare", "CLOUDFLARE_API_TOKEN": "cf", "CF_API_TOKEN": "cflegacy"},
			want:    "CF_PERSONAL_TOKEN",
		},
		{
			name: "FLAREADM_API_TOKEN second",
			env:  map[string]string{"CLOUDFLARE_API_TOKEN": "cf", "FLAREADM_API_TOKEN": "flare", "CF_API_TOKEN": "cflegacy"},
			want: "FLAREADM_API_TOKEN",
		},
		{
			name: "CLOUDFLARE_API_TOKEN third",
			env:  map[string]string{"CLOUDFLARE_API_TOKEN": "cf", "CF_API_TOKEN": "cflegacy"},
			want: "CLOUDFLARE_API_TOKEN",
		},
		{
			name: "CF_API_TOKEN last",
			env:  map[string]string{"CF_API_TOKEN": "cflegacy"},
			want: "CF_API_TOKEN",
		},
		{
			name:    "missing named env falls through the chain",
			profile: &config.Profile{APITokenEnv: "UNSET_VAR"},
			env:     map[string]string{"CLOUDFLARE_API_TOKEN": "cf"},
			want:    "CLOUDFLARE_API_TOKEN",
		},
		{
			name: "empty env vars are skipped",
			env:  map[string]string{"FLAREADM_API_TOKEN": "", "CLOUDFLARE_API_TOKEN": ""},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cred, ok := resolve(tc.profile, envMap(tc.env))
			if tc.want == "" {
				if ok {
					t.Fatalf("expected no credential, got %+v", cred)
				}
				return
			}
			if !ok {
				t.Fatal("expected a credential")
			}
			if cred.Source != tc.want {
				t.Fatalf("source = %q, want %q", cred.Source, tc.want)
			}
			if cred.Token != tc.env[tc.want] {
				t.Fatalf("token = %q, want %q", cred.Token, tc.env[tc.want])
			}
		})
	}
}

func TestRequireNoToken(t *testing.T) {
	_, err := Require(nil)
	if err == nil {
		t.Fatal("Require should fail without any token")
	}
	if errors.CodeOf(err) != errors.CodeAuth {
		t.Fatalf("exit code = %d, want 3", errors.CodeOf(err))
	}
	if strings.Contains(err.Error(), "token found; set") == false {
		t.Fatalf("error should suggest environment variables: %v", err)
	}
}

func TestRedact(t *testing.T) {
	token := "super-secret-token"
	out := Redact("Authorization: Bearer super-secret-token, token=super-secret-token", token)
	if strings.Contains(out, token) {
		t.Fatalf("token leaked: %q", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("expected redaction markers: %q", out)
	}
}
