# Configuration and credentials

## Configuration paths

### Unix

Preferred:

```text
$XDG_CONFIG_HOME/flareadm/config.toml
```

Fallback:

```text
~/.config/flareadm/config.toml
```

### Windows

```text
%APPDATA%\flareadm\config.toml
```

### Example

```toml
[profile.default]
account_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
api_token_env = "CLOUDFLARE_API_TOKEN"

[profile.personal]
account_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
api_token_env = "CF_PERSONAL_TOKEN"
default_zone = "example.com"
oauth_client_id = "0123456789abcdef0123456789abcdef"

[profile.company]
account_id = "cccccccccccccccccccccccccccccccc"
api_token_env = "CF_COMPANY_TOKEN"
```

Each profile supports four keys: `account_id`, `api_token_env`, `default_zone` and
`oauth_client_id` (the OAuth client used by [`auth login`](#oauth-credentials)). They are read and
written by `configure get`/`set`/`list` and by `profile create`/`update` (`--account-id`,
`--api-token-env`, `--default-zone`, `--oauth-client-id`).

Usage:

```bash
flareadm zone list --profile company
```

or:

```bash
export FLAREADM_PROFILE=company
flareadm zone list
```

## Credential policy

API Tokens are the preferred credential type. FlareADM SHALL NOT recommend storing API tokens
directly in the main configuration file. Profiles should normally reference the environment
variable containing the token.

### Credential resolution

For a selected profile:

1. environment variable named by `api_token_env`;
2. `FLAREADM_API_TOKEN`;
3. `CLOUDFLARE_API_TOKEN`;
4. `CF_API_TOKEN`;
5. the stored OAuth credential for the profile ([OAuth credentials](#oauth-credentials)).

Environment variables always win: a profile with both an environment token and a stored OAuth
credential uses the environment token. Support for OS credential stores may be added later.

### OAuth credentials

`flareadm auth login` obtains a credential from Cloudflare's OAuth server (Authorization Code
with PKCE S256 and a loopback redirect) instead of requiring an API token in the environment.
It is the last step of the resolution order above, so CI that exports a token is unaffected.

Client setup: register a **private** OAuth client in the Cloudflare dashboard and add the
loopback redirect URI

```text
http://127.0.0.1:8976/oauth/callback
```

Provide the client id with `--client-id`, or set `oauth_client_id` in the profile (equivalently
`configure set oauth_client_id …`, or `profile create`/`update --oauth-client-id`).

### Dashboard client setup

Create the client in the dashboard: **Manage Account > OAuth clients > Create client** (requires
the Super Administrator, Administrator or OAuth Client Write role).

| Field | Documented options | Value for FlareADM |
| --- | --- | --- |
| Client name | any human-readable name | any, for example `FlareADM CLI` |
| Response type | `code`, `token`, `id_token` | `code` — only Authorization Code is supported for third-party clients |
| Grant type | `authorization_code` (required), `refresh_token` (optional) | `authorization_code` plus `refresh_token`, because FlareADM stores and uses a refresh token |
| Token authentication method | `none`, `client_secret_basic`, `client_secret_post` | `none` — CLI clients use PKCE (S256) and no client secret is issued |
| Redirect URLs | one or more URIs | `http://127.0.0.1:8976/oauth/callback`, matching the CLI's callback exactly; if the dashboard rejects the `127.0.0.1` form, register `http://localhost:8976/oauth/callback` and run the login with `--callback-host localhost` |
| Client URL (optional) | optional; required for a public client | leave empty for a private client |

Visibility: keep the client **private** — it can then be authorized only by members of the
account. Making it public additionally requires a client name, logo and client URL plus DNS TXT
domain-ownership verification (the `cloudflare_oauth_client_publisher=` prefix), and the change is
permanent.

Scopes: select at least one. Selected scopes are required by default and can be marked optional;
optional scopes may be declined on the consent screen. `openid`, `offline` and `offline_access`
cannot be optional and are added or removed automatically based on the grant and response types.
The authoritative list comes from `GET /oauth/scopes`, and scope names correspond to API token
permission names.

The dashboard extras above — Client URL, logo and DNS verification — are needed only if you ever
want a public client; to use OAuth at all you only need the client id, which the CLI takes from
`--client-id` or the profile key `oauth_client_id`.

Login flags:

```text
--client-id <id>        client id (falls back to the profile oauth_client_id)
--scopes <a,b,c>        explicit scope list
--all-scopes            request every scope in the catalog
--read-only             request only read scopes (the default)
--callback-host <host>  loopback host (default 127.0.0.1)
--callback-port <port>  loopback port (default 8976)
--no-browser            print the authorize URL instead of opening a browser
--timeout <duration>    how long to wait for the callback (default 5m)
```

The default scope set is read-only; write administration needs `--all-scopes`. Scope names are
validated against a candidate catalog; the Phase 0 spike in [oauth.md](oauth.md) reconciles it
with Cloudflare's per-account `GET /oauth/scopes`, so the catalog is not authoritative yet.

Storage: the credential is a per-profile JSON file under the `oauth/` subdirectory of the
configuration directory — `$XDG_CONFIG_HOME/flareadm/oauth/<profile>.json` (falling back to
`~/.config/flareadm/oauth/<profile>.json`) or `%APPDATA%\flareadm\oauth\<profile>.json` on
Windows. The directory is created `0700` and the file `0600` where the platform supports it; the
file is written atomically and records a format version.

Environment overrides (for offline testing and staging/alternate hosts; not needed in normal use):

```text
FLAREADM_OAUTH_AUTH_URL
FLAREADM_OAUTH_TOKEN_URL
FLAREADM_OAUTH_REVOKE_URL
```

`auth logout` revokes the refresh token at the revocation endpoint and then deletes the local
credential. If revocation fails with a network error the credential is kept so logout can be
retried (exit 8); if the endpoint rejects the token the credential is deleted anyway and the
rejection is reported (exit 3). `--local` skips the network call and deletes the local credential
only. API tokens are never touched.

Non-interactive rules: `auth login` never hangs. Without an interactive terminal it fails with
exit 2 and points at `FLAREADM_API_TOKEN`; with `--no-browser` it prints the authorize URL and
waits for the callback only until `--timeout` expires.

#### Headless and SSH

`auth login` opens the authorize URL in a browser and waits for the loopback callback. The opener
can be overridden with `$BROWSER` — a whitespace-separated command plus arguments, never run
through a shell — which is how you point the login at `wslview` or at a custom script, and the way
to complete a login on WSL or another headless box. Without `$BROWSER`, the platform chain is
tried in order: `xdg-open` then `wslview` on Linux/WSL, `open` on macOS, and `rundll32
url.dll,FileProtocolHandler` on Windows.

Whatever opener is used, the authorize URL is printed on **stderr** before it is handed over
(`Opening this URL in your browser …`), so it stays visible even when the browser window ends up
blank; with `--no-browser` it is printed on stdout instead, and stdout is otherwise left clean. If
no callback arrives within about 15 seconds, a one-time diagnostic names the three things to
check: the client id (and that the client belongs to this account), that the redirect URI is
registered on the client exactly as `http://127.0.0.1:<port>/oauth/callback`, and that the
requested scopes are registered on the client — followed by the URL again. Before waiting, the
login also performs a bounded, unauthenticated preflight GET of that same URL: if Cloudflare
rejects the authorization request — for example an unknown client id or an unregistered scope —
the CLI prints the error code, Cloudflare's own description and the concrete fix, instead of
leaving the user with a blank browser tab.

Opening a browser is best effort. If no opener works, the authorize URL is printed once and the
login keeps waiting for the callback until `--timeout` expires (default 5m; exit 8 on timeout); an
opener that starts but does not return is never waited on.

`auth login` requires a real terminal unless `--no-browser` is given. A pipe, `/dev/null`, a
regular file or a closed stdin is not a terminal, so the command fails fast with exit 2 and points
at `--no-browser` or `FLAREADM_API_TOKEN` instead of waiting. Use `--no-browser` to print the URL
once and complete the login elsewhere.

Complete the login either from a browser that can reach the callback, or by forwarding the
loopback port to the machine running the browser:

```bash
ssh -L 8976:127.0.0.1:8976 user@host
# on the remote host:
flareadm auth login --no-browser --client-id <id>
```

The callback listens on `127.0.0.1:8976` by default (`--callback-host` / `--callback-port`); the
registered redirect URI must match it.

The device-authorization flow (the `aws sso login --no-browser` style) is **not implemented**:
Cloudflare documents the device grant as unsupported for third-party OAuth clients
(`docs/oauth.md` §5 Q6), and that remains pending live verification.

### Security rules

FlareADM SHALL:

- redact authorization headers in debug logs;
- never print tokens in normal output;
- avoid token command-line flags because process arguments can be observable;
- create sensitive files with restrictive permissions where supported;
- never include credentials in crash/error reports;
- refuse to write credentials into shell history through generated commands;
- accept `certificate create --private-key` only as `@path`; inline private keys are rejected
  with exit 2 because process arguments are observable;
- redact the resolved API token and any registered secret (private keys) from all error output
  and diagnostics, not only under `--debug`;
- accept credentials and credential-bearing payloads in `@file` form only: `certificate create
  --private-key`, `hyperdrive config --origin`, and `vectorize vector insert|upsert --vectors`;
  inline values are rejected because process arguments are observable.

## Account resolution

Resolution order:

1. `--account-id`;
2. profile `account_id`;
3. `FLAREADM_ACCOUNT_ID`;
4. automatic discovery when exactly one accessible account exists.

If multiple accounts exist and no explicit account can be resolved, the command must fail with
a useful error rather than silently choosing one.

## Zone resolution

Commands accepting a zone SHALL accept either:

```text
zone ID
```

or:

```text
example.com
```

When a zone name is supplied, FlareADM resolves it to the corresponding zone ID. Resolution
should be centralized and reused by all services.
