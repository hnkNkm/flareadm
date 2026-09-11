package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"runtime"
)

func isWindows() bool { return runtime.GOOS == "windows" }

// PKCE implements RFC 7636 with the S256 challenge method, the only method
// docs/oauth.md §5 Q1 requires (the server also advertises `plain`; it must not
// be used).
type PKCE struct {
	Verifier  string
	Challenge string
}

// randomURLSafe returns n bytes of cryptographic randomness, base64url-encoded
// without padding (RFC 7636 §4.1 alphabet).
func randomURLSafe(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// NewPKCE generates a code verifier (32 random bytes) and its S256 challenge.
func NewPKCE() (PKCE, error) {
	verifier, err := randomURLSafe(32)
	if err != nil {
		return PKCE{}, err
	}
	sum := sha256.Sum256([]byte(verifier))
	return PKCE{
		Verifier:  verifier,
		Challenge: base64.RawURLEncoding.EncodeToString(sum[:]),
	}, nil
}

// NewState generates the CSRF state parameter (22 random bytes).
func NewState() (string, error) {
	return randomURLSafe(22)
}
