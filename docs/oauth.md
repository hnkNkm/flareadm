# OAuth login for FlareADM

**Status: implemented (Phases 1-4) in the v1.1 line; Phase 0 (live scope verification) completed 2026-09-13 — the catalog is generated from the live 385-id list. The first live login attempt (2026-09-14) found the authorize endpoint rejecting `openid`/`offline` with `error=invalid_scope`; the flow now requests `offline_access` alone, and every remediation example uses live ids. The login was then verified end to end on 2026-09-14 against a real Cloudflare account: PKCE + loopback consent in a browser, the credential stored under `oauth/default.json` (0600), `auth status` reporting source `oauth:default`, `auth verify` returning the identity from `GET /user`, and `account list`/`zone list` answered through the stored credential with no refresh needed while it is fresh. One wrinkle remains for that account: its client is not registered for `cloudforce-one.read`, which the default read-only catalog includes, so a login without an explicit `--scopes` list is rejected — register that id on the client (dashboard) or pass `--scopes`.** FlareADM
authenticates with Cloudflare API tokens and additionally supports a stored OAuth credential
obtained with `flareadm auth login` (see `docs/configuration.md`); environment variables still take
precedence. The credential store, the resolution-chain fallback, the PKCE loopback flow with
proactive refresh and 401 refresh-and-retry, `auth login`/`logout`/`status`/`verify`, and
scope-aware 403 guidance ship in v1.1.0. The open questions and risks in §13 (Q1, Q3, Q4–Q11)
remain open.

Every factual claim about Cloudflare cites the URL it came from. Claims that the public
documentation does not support are marked `[INFERENCE]` with the reasoning, or listed under
*Open questions* as things that must be verified against a live account.

---

## 1. Evidence base

Primary sources read while preparing this document:

| # | Source | Notes |
| - | ------ | ----- |
| E1 | <https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/> | "Create your OAuth client"; page reports *Last updated Aug 20, 2026* |
| E2 | <https://developers.cloudflare.com/fundamentals/oauth/> | "OAuth Applications on Cloudflare"; *Last updated Aug 14, 2026* |
| E3 | <https://dash.cloudflare.com/.well-known/openid-configuration> | Live OpenID Connect discovery document, fetched during this research |
| E4 | <https://developers.cloudflare.com/workers/wrangler/commands/general/> | `wrangler login` / `logout` reference; *Last updated Sep 2, 2026* |
| E5 | <https://developers.cloudflare.com/changelog/post/2026-08-04-wrangler-login-device-flow/> | Device-flow changelog, August 4, 2026 |
| E6 | <https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/verify/> | "Verify Token" API reference (`GET /user/tokens/verify`) |
| E7 | `cloudflare/workers-sdk` — `packages/workers-auth/src/generate-auth-url.ts` | Authorize-URL construction (PKCE) |
| E8 | `cloudflare/workers-sdk` — `packages/workers-auth/src/token-exchange.ts` | Code exchange and refresh-token exchange |
| E9 | `cloudflare/workers-sdk` — `packages/workers-auth/src/flow.ts` | `login`/`logout`/refresh orchestration, non-interactive reasons |
| E10 | `cloudflare/workers-sdk` — `packages/workers-auth/src/env-vars.ts` | Auth URL overrides, staging switch, keyring override |
| E11 | `cloudflare/workers-sdk` — `packages/workers-auth/src/cf/constants.ts` | `cf` CLI callback URL (port 8877) and consent pages |
| E12 | `cloudflare/workers-sdk` — `packages/workers-auth/src/cf/scopes.ts` | The `cf` CLI's full OAuth scope catalog |
| E13 | `cloudflare/workers-sdk` — `packages/workers-auth/src/cf/paths.ts` | `cf` config directory (`~/.config/cloudflare`) |
| E14 | `cloudflare/workers-sdk` — `packages/wrangler/src/user/whoami.ts` | How wrangler verifies identity/accounts |

Sources E7–E14 are read from the `main` branch of the public repository; they are implementation
sources, not specifications, and they can change without notice. Where a claim rests only on source
code, it is labelled as such.

---

## 2. Summary and recommendation

**Recommendation: implement OAuth as an additive, opt-in login path in v1.1, running after the
API-token path is fully verified and unchanged.**

Why it is worth doing:

- Cloudflare runs a real, currently-live OAuth 2.0 / OIDC authorization server at
  `https://dash.cloudflare.com` (E3). Authorization Code + PKCE is documented for CLI and desktop
  clients, with `token_endpoint_auth_method=none` and `S256` (E1). This is exactly the shape a CLI
  needs.
- OAuth is available on Free, Pro, Business and Enterprise plans (E2) — it is not an
  enterprise-only feature.
- Cloudflare's own CLIs use it: Wrangler (`wrangler login`, E4) and the newer unified `cf` CLI
  (E11–E13), on top of a shared `@cloudflare/workers-auth` package. Third-party CLIs can follow the
  same pattern.
- OAuth breaks the "token to create a token" bootstrap cycle: an OAuth client is created from the
  dashboard by a human with account access (E1), with no API token required.

**What the user must provide before `auth login` can work at all:** a registered OAuth client.
FlareADM cannot invent one; see §5 Q2 and §12 for the two options (per-user private client, or one
public project client).

**The single most important blocker:** FlareADM has no OAuth client registration, and a *public*
client (usable by any Cloudflare user) requires a Client URL whose domain ownership Cloudflare
verifies by DNS TXT record, and is **permanently public** once switched (E1). Shipping a default
client id therefore requires a decision from the project owner (own a verified domain, accept
irreversible public visibility). Until then, `auth login` must take an explicit client id.

**Second, smaller blocker:** the scope names for several command groups are not determinable from
public sources (§5 Q5). They must be read from `GET /oauth/scopes` on a live account before the
scope defaults are frozen.

---

## 3. Goals and non-goals

### Goals

1. `flareadm auth login` obtains an OAuth access token plus refresh token via the browser, without
   the user pasting a token into the environment.
2. Access tokens refresh transparently; expired or revoked credentials fail with exit code 3 and a
   clear remediation message instead of a confusing API error.
3. Credentials are stored per profile with owner-only permissions, never in `argv`, never in
   `--verbose`/`--debug` output, never in error text, never in `--dry-run` previews.
4. Existing API-token behaviour — including CI — is byte-for-byte unchanged: environment
   credentials keep precedence and no command starts a browser unless it is `auth login`.
5. The whole flow is testable offline.

### Non-goals (this proposal)

- Replacing API tokens. OAuth is an additional credential source, never a migration.
- OAuth for Cloudflare Access ("Managed OAuth", where Cloudflare is the *identity provider* for a
  protected application). That is a different product with a per-application issuer; it is not
  usable to administer a Cloudflare account and is out of scope.
- OS keychain storage in the first implementation (see §8.5).
- Device Authorization Grant in the first implementation (§5 Q6; blocked on verification).
- Per-command scope minimisation beyond a coarse `--read-only` switch (§7.1).

---

## 4. Definitions

- **Global OAuth server** — `https://dash.cloudflare.com/oauth2/*`, the authorization server that
  issues tokens for accessing Cloudflare accounts and APIs (E1, E3). This is what FlareADM would
  use.
- **Access Managed OAuth** — the OAuth/OIDC server Cloudflare runs *per Access application*, for
  agents authenticating to protected apps (documented at
  <https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/>).
  Different issuer, different audience, not used by FlareADM.

Conflating the two is the most common trap in this area; §5 Q4 records what each does and does not
document.

---

## 5. Research findings

### Q1. Is there an OAuth 2.0 authorization server a third-party CLI can use?

**Yes.** Discovery document (E3):

```
issuer:                        https://dash.cloudflare.com
authorization_endpoint:        https://dash.cloudflare.com/oauth2/auth
token_endpoint:                https://dash.cloudflare.com/oauth2/token
device_authorization_endpoint: https://dash.cloudflare.com/oauth2/device/auth
userinfo_endpoint:             https://dash.cloudflare.com/oauth2/userinfo
revocation_endpoint:           https://dash.cloudflare.com/oauth2/revoke
jwks_uri:                      https://dash.cloudflare.com/.well-known/jwks.json
end_session_endpoint:          https://dash.cloudflare.com/oauth2/sessions/logout
code_challenge_methods_supported: ["plain", "S256"]
token_endpoint_auth_methods_supported:
  ["client_secret_post", "client_secret_basic", "private_key_jwt", "none"]
```

- **PKCE**: required for CLI/desktop clients — the documented flow table maps "Browser-based,
  mobile, desktop, or CLI app" to Authorization Code with PKCE, token authentication `none`, "PKCE
  Required, S256" (E1). Wrangler always sends `code_challenge_method=S256` (E7). The discovery
  document also advertises `plain`, but FlareADM must use `S256`.
- **Public clients without a secret**: yes for CLI clients (`token_endpoint_auth_method: none`,
  paired with PKCE) (E1). Wrangler's token requests send only `grant_type`, `code`/`refresh_token`,
  `redirect_uri` and `client_id` (plus `code_verifier` for the code exchange) — no secret (E8).
- **Loopback redirect URIs**: Cloudflare's own CLIs use fixed loopback callbacks that are
  registered on their client: Wrangler `http://localhost:8976/oauth/callback` with
  `--callback-host`/`--callback-port` described as the local listener (E4), and `cf`
  `http://localhost:8877/oauth/callback` (E11, described there as "the `redirect_uri` registered on
  cf's OAuth app"). Redirect URLs are a required field when creating a client (E1).
  Whether Cloudflare accepts a *wildcard* loopback URI or any port is **not documented** — every
  observed client pins one host:port:path. → `[INFERENCE]` FlareADM should choose a fixed default
  loopback port, document it, and instruct users to register that exact URI. Making the port
  configurable is still useful (Wrangler allows it), but the user must register each variant.
  *Verification needed*: whether Cloudflare's redirect-URI matching tolerates another port.

Sources: E1, E3, E4, E7, E8, E11.

### Q2. How does one obtain an OAuth client id? Is registration self-serve?

The dashboard path is documented and does not require an API token (E1):

1. Prerequisites: the user needs the **Super Administrator**, **Administrator**, or **OAuth Client
   Write** role on the account (E1).
2. Cloudflare dashboard → select the account → **Manage Account** → **OAuth clients** → **Create
   client** (E1).
3. Provide: client name, response type, grant type, token authentication method, redirect URLs,
   then scopes (all selected scopes are required by default; each can be marked optional) (E1).
4. Save the **Client ID** (and client secret, for confidential clients) (E1).

The same object can be created with an API token holding the `OAuth Clients Write` permission:

```bash
curl -X POST "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/oauth_clients" \
  -H "Authorization: Bearer $API_TOKEN" \
  -d '{"client_name":"...","grant_types":["authorization_code"],
       "redirect_uris":["https://example.com/oauth/callback"],
       "scopes":["zone.read","dns.read","offline_access"],
       "response_types":["code"],"token_endpoint_auth_method":"client_secret_basic"}'
```

(The `scopes` array takes live ids: `flareadm auth scopes --json` prints exactly the set the CLI
validates `--scopes` against, and what is registered here is what the login may request. The ids
above are examples from that list.)

(E1)

**Self-serve for an individual account holder:** yes, with one caveat. The role requirement is
satisfiable by the owner of a personal account (they are the account's administrator), so a single
user can create a **private** client for themselves; private clients "can only be authorized by
members of the parent Cloudflare account" (E1). Becoming a **public** client — authorizable by any
Cloudflare user — additionally requires client name, logo, client URL and scopes, plus **Client URL
domain ownership verification** via a DNS TXT record containing the
`cloudflare_oauth_client_publisher=` prefix; after verification the client URL's domain is frozen,
and public visibility is **permanent** ("You cannot change the visibility back to private") (E1).

`[INFERENCE]` For FlareADM this means: a user running the CLI for their own account registers a
private client and passes its client id; a *bundled* client id implies the project owning a public
client with a verified domain. There is no documented "register yourself as a third-party app
without owning a Cloudflare account" path, and no documented dynamic client registration endpoint.

Sources: E1.

### Q3. What does Wrangler actually do for `wrangler login`?

Documented behaviour (E4) and implementation (E7–E11):

- **Flow**: Authorization Code + PKCE (S256). The authorize URL is
  `https://dash.cloudflare.com/oauth2/auth?response_type=code&client_id=…&redirect_uri=…&scope=…
  &state=…&code_challenge=…&code_challenge_method=S256` (E7). `offline_access` is appended to every
  request by the flow itself (E7).
- **Loopback server**: default `http://localhost:8976/oauth/callback`, configurable with
  `--callback-host` (default `localhost`) and `--callback-port` (default `8976`); both are rejected
  in combination with `--device` (E4).
- **Browser**: opened by default; `--browser=false` prints the URL instead (E4).
- **Scopes**: `--scopes-list` prints available scopes with descriptions; `--scopes` selects a
  whitespace-separated set — the docs' example uses the colon syntax `account:read user:read`, which
  is *not* a live id and is rejected by FlareADM's validator (live ids look like `zone.read,dns.read`);
  **with no flags `wrangler login` requests all available scopes** (E4).
- **Device flow**: `wrangler login --device` uses the RFC 8628 Device Authorization Grant,
  prints `https://dash.cloudflare.com/oauth2/device` plus a user code, opens the URL pre-filled,
  and polls for at most **5 minutes** (or less if the server sets a shorter expiry) (E4, E5).
  Available in Wrangler ≥ 4.119.0 (E5).
- **Storage**: default is a **plaintext TOML file** in the global Wrangler config directory,
  "typically `~/.config/.wrangler/config/default.toml`", holding the access and refresh tokens
  (E4). `--use-keyring` opts into an AES-256-GCM encrypted file (`default.enc`) whose 32-byte key
  lives in the OS keychain — macOS Keychain via `/usr/bin/security`, Linux libsecret via
  `secret-tool`, Windows Credential Manager via `@napi-rs/keyring` (E4). The preference persists
  across invocations; `CLOUDFLARE_AUTH_USE_KEYRING` overrides it per process; with the persistent
  preference set but no keychain available, Wrangler falls back to the plaintext file with a
  warning, while an explicit `=true` errors instead of falling back (E4). Opting back out
  **deletes** the encrypted file and keychain entry and does not decrypt to plaintext (E4).
- **Profiles**: the shared flow stores tokens under a named auth profile; the default profile file
  is `default.toml`, and `auth create <name>` / `auth delete <name>` manage additional profiles
  (E9).
- **Refresh**: the refresh grant sends `grant_type=refresh_token`, `refresh_token`, `client_id`
  (no secret) to the same token endpoint; the refresh token is re-read from disk on every call "so
  we always pick up the latest rotation written by a sibling Wrangler process", and if the server
  omits `refresh_token` in a successful refresh the previously stored value is kept (RFC 6749 §6)
  (E8). A rejected refresh leads the flow to attempt a fresh interactive login (E9).
- **Logout**: "Revoke the stored refresh token at the Cloudflare OAuth endpoint and delete the
  on-disk auth config file"; it is a no-op when environment credentials are in use (E9).
- **Env precedence**: `login` refuses to start when environment credentials are present, telling
  the user to unset `CLOUDFLARE_API_TOKEN`; the docs state that env API tokens continue to take
  priority over stored OAuth credentials (E4, E9).
- **Never hangs in CI**: the flow distinguishes `no-credentials-non-interactive` and
  `token-expired-non-interactive` outcomes, i.e. in a non-interactive environment it does not
  attempt a browser login (E9).
- **Staging/testing knobs**: `WRANGLER_AUTH_DOMAIN` (default `dash.cloudflare.com`, staging via
  `WRANGLER_API_ENVIRONMENT=staging`), `WRANGLER_AUTH_URL`, `WRANGLER_TOKEN_URL`,
  `WRANGLER_REVOKE_URL`; the device authorization URL is deliberately **not** overridable (E10).
- **Client id**: the flow takes `clientId` from its consumer (E9); the constant itself lives in the
  consumer registration, and for `cf` the callback URL/keyring service are in E11. The concrete
  Wrangler client id string was not located in the files read during this research.

Sources: E4, E5, E7, E8, E9, E10, E11.

### Q4. Token lifecycle, revocation, API compatibility, and verification

- **Token response**: `{access_token, expires_in, refresh_token, scope}`; `expires_in` is seconds
  and is used to compute the stored expiry timestamp; `scope` is a **space-delimited** string (E8).
- **Access-token lifetime**: **not documented** for the global OAuth server (E1–E3). The 15-minute
  default that Cloudflare documents belongs to *Access Managed OAuth / OIDC SaaS* applications
  where Cloudflare acts as the identity provider
  (<https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/>),
  a different server. → `[INFERENCE]` FlareADM must treat `expires_in` as authoritative and add a
  safety window (for example refresh when less than five minutes remain) rather than hardcoding a
  lifetime.
- **Refresh tokens**: `refresh_token` is included in the discovery document's
  `grant_types_supported` (E3), requested via the `offline_access` scope (E7), and used by Wrangler
  (E8). E12 (the `cf` scope catalog) claims the server also needs the non-standard `offline` alias
  alongside `offline_access`. **Measured 2026-09-14 against the live authorize endpoint: that claim
  is false for this client type** — a request carrying `openid` or `offline` is answered with HTTP
  303 to the loopback callback and `error=invalid_scope` ("The OAuth 2.0 Client is not allowed to
  request scope 'openid'"), while the same request with `offline_access` alone is accepted (302 to
  the login hand-off). FlareADM therefore requests `offline_access` only
  (`oauth.RequiredScopes`, `internal/oauth/flow.go`).
- **Rotation**: rotation is possible and handled: Wrangler re-reads the stored refresh token before
  every refresh, treats a returned `refresh_token` as a replacement, and keeps the old one when the
  server omits it (E8). `[INFERENCE]` rotation is server-policy, not client-chosen; FlareADM must
  implement the same "replace if present, otherwise keep" rule.
- **Revocation**: `revocation_endpoint` = `https://dash.cloudflare.com/oauth2/revoke` (E3);
  Wrangler's `logout` revokes the stored **refresh token** there and then deletes local state (E9).
  The exact request format (which token types the endpoint accepts, whether it is form-encoded) is
  not shown in the sources read → verify at implementation.
- **Do OAuth tokens work against the v4 REST API?** The OAuth client is created with **scopes that
  "correspond to Cloudflare API token permission names"** (E1), and Cloudflare's own CLIs use the
  OAuth access token as the bearer credential for the ordinary API endpoints (E4, E8, E14). →
  `[INFERENCE]` (strong): OAuth access tokens are accepted by `https://api.cloudflare.com/client/v4`
  as `Authorization: Bearer …`. It is not stated as a general guarantee in E1–E3, and no list of
  exceptions was found.
- **`flareadm auth verify` for an OAuth token**: `GET /user/tokens/verify` is documented under the
  **API Token** security scheme and returns `{id, status, expires_on, not_before}` — i.e. it
  verifies an API *token object* (E6). OAuth access tokens have no such object. → `[INFERENCE]`
  `auth verify` must not rely on it for OAuth; use the calls Wrangler's `whoami` uses: fetch the
  user (email; the docs note the "User → User Details → Read" permission gap when the email is
  unavailable) and list accounts/memberships (E14). Concretely: `GET /user` (+ `GET /accounts`).
  Whether `/user/tokens/verify` happens to accept OAuth tokens is undocumented; it must not be
  depended on either way.

Sources: E1, E3, E6, E7, E8, E9, E12, E14.

### Q5. Scopes

Two layers exist:

1. **What Cloudflare's own unified CLI registers**: `cf`'s scope catalog is a flat list of ~80
   scopes (E12). It is the most complete public list found and is a reliable naming reference. It
   includes, among others: `openid`, `offline`, `user:read`, `account:read`, `zone:read`,
   `dns_records:read`, `dns_records:edit`, `ssl_certs:write`, `d1:write`, `workers_kv:write`,
   `workers:read`, `workers:write`, `workers_scripts:write`, `workers_routes:write`,
   `workers_deployments:read`, `workers_builds:read`, `workers_builds:write`,
   `workers_observability:read`, `workers_observability:write`, `workers_tail:read`, `pages:read`,
   `pages:write`, `queues:write`, `lb:read`, `lb:edit`, `vectorize:write`, `logpush:read`,
   `logpush:write`, `notification:read`, `notification:write`, `auditlogs:read`, `registrar:read`,
   `registrar:write`, `teams:read`, `teams:write`, `teams:secure_location`, `teams:pii`,
   `access:read`, `access:write`, `cfone:read`, `cfone:write`, `dex:read`, `dex:write`,
   `dns_analytics:read`, `r2_catalog:write`, `secrets_store:read`, `secrets_store:write`,
   `email_routing:write`.
2. **The authoritative account-specific list** is fetched from the API:
   `GET /oauth/scopes` (with an API token) returns the scope list to use when creating a client,
   and scope names "correspond to Cloudflare API token permission names" (E1). The public
   permission list is <https://developers.cloudflare.com/fundamentals/api/reference/permissions/>.

**Resolved (Phase 0, 2026-09-13).** `GET /oauth/scopes` was read on the live account and recorded in
`cmd/auth/scopes_generated.go`: **385 ids in 13 categories**, all dot-delimited (`zone.read`,
`dns.read`, `workers-scripts.write`, …). The colon-delimited `cf` names in layer 1 above are **not**
live ids and cannot be requested; the shipped catalog maps each command group onto live ids
(`scopeGroups` in `cmd/auth/scopes.go`) and `--scopes` validates against the generated list.
Regenerate with `go run ./tools/scopegen -in <scopes.json> -out cmd/auth/scopes_generated.go`;
`flareadm auth scopes` prints the same list.

Scope properties:

- Scopes are selected **when the client is created**; each is required by default and can be
  marked optional, and optional scopes may be declined by the user on the consent screen (E1).
- The `cf` catalog claims the server needs the non-standard `offline` alias next to
  `offline_access` (E12). **Rebutted by measurement (2026-09-14):** the live authorize endpoint
  rejects both `offline` and `openid` with `error=invalid_scope` for a client that is registered for
  `offline_access`, and accepts `offline_access` on its own.
- Whether the authorize request may ask for a **subset** of the registered scopes, or for scopes
  that were never registered, is **not documented**. Wrangler passes a caller-chosen scope list to
  the authorize URL (E7, E9), and its docs describe choosing scopes at login (E4) → `[INFERENCE]`
  subsetting registered scopes works; asking for unregistered scopes is unlikely to be granted.
  Verify before promising `--scopes`.

The per-group mapping is **not duplicated here** — it ships as `scopeGroups` in
`cmd/auth/scopes.go`, where every id is checked against the live list
(`TestScopeCatalogIDsExistLive`), and `flareadm auth scopes` prints it (`--read-only`, `--all`,
`--category`, `--json`). The pre-0.4 colon-delimited candidate table that used to be here is
superseded: those names are not live ids and cannot be requested.

**Consequence for the design (resolved).** The scope set cannot be frozen from public sources, so
Phase 0 recorded the authoritative list from `GET /oauth/scopes` (§5 Q5, 385 ids) and the CLI
requests **live ids only, plus `offline_access`**. `openid` and `offline` must not be sent: the live
authorize endpoint answers `error=invalid_scope` for them (measured 2026-09-14). `--scopes` accepts
any live id.

Whether scopes are per-account: the consent grant is made to a client by a user, and private
clients are limited to members of the parent account (E1); scope names themselves are global. →
`[INFERENCE]` a token's effective permissions are the intersection of the granted scopes and the
user's own account permissions.

Sources: E1, E4, E7, E9, E12; permissions reference URL as listed.

### Q6. Device authorization grant and headless flows

The evidence is contradictory and this must be resolved before it is promised:

- The OAuth server advertises a device endpoint and grant: discovery lists
  `device_authorization_endpoint: https://dash.cloudflare.com/oauth2/device/auth` and
  `urn:ietf:params:oauth:grant-type:device_code` among `grant_types_supported` (E3).
- Wrangler implements it and the docs describe it in detail: `wrangler login --device`, a printed
  verification URL plus user code, polling for up to 5 minutes (E4, E5).
- But the OAuth client documentation says the opposite for third-party clients: "Cloudflare does
  not support Client Credentials, Implicit, Resource Owner Password Credentials, **Device
  Authorization**, or other OAuth grant types for third-party clients" (E1). The discovery
  document similarly advertises `implicit` and `client_credentials` although E1 rules them out for
  third-party clients.

→ `[INFERENCE]` The device grant is plausibly enabled for Cloudflare's own/first-party clients
(Wrangler) and for allow-listed partners, and disabled for ordinary third-party client
registrations. **This must be verified against a live account** (attempt the device grant with a
freshly created third-party client) before FlareADM offers `--device`.

Realistic headless options, in order of preference:

1. **API token in the environment** — the documented, supported path for CI (E4 recommends exactly
   this for CI/CD). FlareADM keeps it as the default for non-interactive use.
2. **Print-the-URL login** (`--no-browser`): the user completes the login in any browser on any
   machine and the callback is delivered to the loopback listener they can reach — Wrangler
   documents fetching the loopback URL with `curl` from a second terminal, or forwarding the port
   (`docker run -p 8976:8976`, `--callback-host 0.0.0.0`) (E4). This works for SSH sessions with
   `-L` forwarding but requires the user to do that forwarding.
3. **Device flow** — if it turns out to be available to third-party clients (E3 vs E1).

Sources: E1, E3, E4, E5.

### Q7. Alternatives comparison

| Mechanism | Bootstrap | Scope granularity | Revocation | Auditability |
| --------- | --------- | ----------------- | ---------- | ------------ |
| **API token** (current) | User creates it in the dashboard, or via API with an `API Tokens Write` token (E1 documents the analogous OAuth-client API) | Per-permission and per-resource, chosen at creation (E1 permission model) | Dashboard/API delete; immediate | Token id visible; per-request actor is the token, not the user |
| **OAuth (this proposal)** | One-time client registration (dashboard, no token needed); then browser login | Registered scope set; optional scopes declinable (E1); effective access is the intersection with the user's role `[INFERENCE]` | Revocation endpoint (E3) + local delete; refresh-token rotation (E8) | Actions attributed to the *user* (Wrangler's `whoami` reports the user's email, E4/E14) |
| **Global API key + email** | Legacy `X-Auth-Key`/`X-Auth-Email`; Cloudflare recommends API tokens over global keys (E6 shows the API Token scheme as "the preferred authorization scheme") | None — full account access | Rotate key; no per-scope control | Weakest |
| **Access service tokens** | Machine credentials for Access-protected resources (`CLOUDFLARE_ACCESS_CLIENT_ID`/`_SECRET`, E10) | Only for reaching Access-protected endpoints | Delete the service token | Not an API-administration credential |

Bootstrap conclusion: OAuth does **not** fully remove the chicken-and-egg problem — creating an
OAuth client is easiest from the dashboard (E1), and creating one by API needs a token with
`OAuth Clients Write`. But the dashboard path is available to any account administrator, so a user
with no API token at all can bootstrap OAuth. `[INFERENCE]` For FlareADM the practical gain is
"no more long-lived token copies in shell profiles or CI secrets on developer machines", not
"zero-setup".

Sources: E1, E3, E4, E6, E8, E10, E14.

### Q8. Recent Cloudflare statements that affect third-party CLIs

Observed from the public repository and changelog (dated evidence only):

- Cloudflare now ships a **shared auth package** (`@cloudflare/workers-auth`) used by Wrangler and
  by a `cf`-specific layer that carries its own OAuth app registration — a distinct callback
  (`http://localhost:8877/oauth/callback`), a distinct keyring service name (`cloudflare`), and a
  platform-wide scope catalog (E11, E12, E13). The comment in that layer states explicitly that the
  catalog is "the exact scope set the `cf` CLI registers" and that it "requests the full Cloudflare
  product surface" (E12).
- Wrangler added `--device` on August 4, 2026 (v4.119.0+) specifically for containers/SSH (E5).
- Wrangler `--use-keyring` was added with plaintext remaining the default (E4).

→ `[INFERENCE]` Cloudflare's direction is Authorization Code + PKCE with a loopback callback and
refresh tokens, plus an optional device flow and optional keychain storage. A third-party CLI that
follows that pattern is aligned with the platform's own tooling. No statement was found that
promises *new* third-party OAuth capabilities (for example self-service public client registration
without domain ownership), so this proposal assumes the constraints in E1 hold.

Sources: E4, E5, E11, E12, E13.

---

## 6. Proposed CLI surface

### 6.1 `auth login`

```
flareadm auth login [--profile NAME] [--client-id ID]
                    [--scopes a,b,c | --all-scopes | --read-only]
                    [--callback-host HOST] [--callback-port PORT]
                    [--no-browser] [--timeout DURATION] [--device]
```

| Flag | Semantics | Default |
| ---- | --------- | ------- |
| `--profile` | store the credential under this profile; the active profile when omitted | active profile |
| `--client-id` | OAuth client id; falls back to the profile key `oauth_client_id` | none — required (see §2) |
| `--scopes` | comma-separated scope list to request; must be a subset of the client's registered scopes (E1/E4) | `--read-only` set |
| `--all-scopes` | request the 39-id catalog this CLI maps onto its command groups (§5 Q5) | off |
| `--read-only` | request only the read half of that catalog; a write command then fails with exit 4 | on by default `[INFERENCE — see §13 Q3]` |
| `--callback-host`, `--callback-port` | loopback listener; the resulting `redirect_uri` must be registered on the client (E4, E11) | `127.0.0.1`, `8976` |
| `--no-browser` | print the authorize URL instead of opening a browser (E4) | browser opens |
| `--timeout` | how long to wait for the callback before giving up | 5 min (same as Wrangler's device polling, E4) |
| `--device` | RFC 8628 device grant | **hidden/undocumented until verified** (§5 Q6) |

Behaviour: refuses to start when environment credentials are present (mirroring Wrangler's
documented behaviour, E4) — printing which variable to unset, exit 2. Refuses when stdin is not a
terminal **unless** `--no-browser` is given (see §10). On success: writes the credential store,
prints the verified account/email via `GET /user` (E14), and exits 0.

### 6.2 `auth logout`

```
flareadm auth logout [--profile NAME] [--local] [--yes]
```

Revokes the stored refresh token at the revocation endpoint (E3, E9) and deletes local credentials;
`--local` skips the network call; `--yes` skips confirmation for the non-interactive rules in
`docs/cli.md`. Exit 0 on success, 3 when the revocation call is rejected (credentials are still
deleted locally, and the message says so), 8 on network failure — with credentials left in place so
the user can retry.

### 6.3 `auth status`

```
flareadm auth status [--json]
```

Reports: credential source (`env:FLAREADM_API_TOKEN`, `env:CLOUDFLARE_API_TOKEN`, `oauth:<profile>`,
`none`), profile, client id, granted scopes, access-token expiry, store path, and — for OAuth —
the account/email resolved with `GET /user` (E14). Never prints token material. Exit 0 when a
credential is present (even if unverified), 3 when none is found.

### 6.4 `auth verify` (existing command, extended)

Today `auth verify` validates an API token. With OAuth it must use `GET /user` (+ `GET /accounts`)
rather than `GET /user/tokens/verify` (E6, §5 Q4), and report the user's email and account list.
Exit codes unchanged: 0 valid, 3 authentication failure, 8 network failure.

**Implemented (Phase 4):** `auth verify` checks an API token with `GET /user/tokens/verify` and an
OAuth credential with `GET /user`, reporting the user id, email and name. Exit codes are unchanged.

### 6.5 Exit-code contract (consistent with `docs/cli.md`)

| Situation | Code |
| --------- | ---- |
| login succeeds; status/verify succeed | 0 |
| usage: missing `--client-id`, conflicting flags (`--device` with callback flags, `--all-scopes` with `--scopes`), non-interactive login without `--no-browser` | 2 |
| login failed (user denied consent, state mismatch, `invalid_grant`), refresh rejected, verify rejects the credential, none stored for `status` | 3 |
| token valid but the command's scope was not granted (the API answers 403) | 4 |
| local store cannot be written (permissions, read-only HOME) | 1 |
| authorize/token/revoke/user endpoints unreachable or timed out | 8 |

---

## 7. Credential storage design

### 7.1 Location and format

Per profile, separate from `config.toml` so that config sync/backup tools can treat them
differently:

| Platform | Path |
| -------- | ---- |
| Unix | `$XDG_CONFIG_HOME/flareadm/oauth/<profile>.json` (fallback `~/.config/flareadm/oauth/<profile>.json`) |
| Windows | `%APPDATA%\flareadm\oauth\<profile>.json` |

This mirrors the project's existing `config.DefaultPath()` rules
(`internal/config/config.go`), so the directory resolution question already answered for the config
file (and fixed for Windows) applies unchanged.

JSON object (versioned so the shape can evolve):

```json
{
  "version": 1,
  "client_id": "…",
  "account_id": "…",
  "token_type": "Bearer",
  "access_token": "…",
  "refresh_token": "…",
  "expires_at": "2026-09-11T12:34:56Z",
  "scopes": ["zone.read", "dns.read", "…"],
  "obtained_at": "2026-09-11T11:34:56Z"
}
```

`expires_at` is computed from `expires_in` (E8) so that clock skew and short lifetimes are
tolerated without trusting the local clock for anything but the refresh decision.

### 7.2 Permissions and atomicity

- Directory `0o700`, file `0o600`, created with the same pattern the config writer already uses:
  `os.MkdirAll(parent, 0o700)` → `os.CreateTemp(dir, …)` → chmod `0o600` (ignoring the chmod error
  on Windows, where it is a no-op) → `os.Rename` over the target. This is the code path fixed for
  Windows in `internal/config/config.go` and must be reused rather than re-implemented.
- On Windows, POSIX modes do not apply; the file inherits the user profile ACL, which is the same
  guarantee the existing config file has.
- Writes happen on login, on every rotation, and never on read.

### 7.3 Rotation

After a successful refresh, write the new access token and `expires_at`; replace `refresh_token`
only when the response contains one (E8), and update `scopes` from the response's space-delimited
`scope` (E8). Writes are atomic and take a lock-free approach: the last writer wins, which matches
Wrangler's documented behaviour of re-reading the file before each refresh so concurrent processes
do not lose a rotation (E8).

### 7.4 Redaction

The access token, refresh token, client secret (if a confidential client is ever supported) and
`authorization`/`code_verifier` values are registered with `rt.ProtectSecret` before any use, which
routes them through the existing `Redact` pipeline. That pipeline already covers error text,
`--verbose`/`--debug` diagnostics and `--dry-run` previews; the v1.0 audit verified all three.

### 7.5 OS keychain assessment

Wrangler offers keychain storage as an opt-in and explains the moving parts (E4): macOS
`/usr/bin/security`, Linux libsecret/`secret-tool`, Windows `@napi-rs/keyring`. For FlareADM:

- The Nix-first distribution makes an external `secret-tool` dependency a packaging problem, and
  the "no new dependencies" rule rules out a Go keyring library.
- The default in Cloudflare's own CLI is a plaintext file with `0600` (E4), which the existing
  config precedent already matches.
- → Recommendation: plaintext `0600` file for v1.1, documented as such in `docs/configuration.md`
  and in `auth status`. A keychain backend is a separate later proposal; if it ever happens it must
  keep the file store as the fallback, exactly like Wrangler (E4).

### 7.6 Fallback when no writable store exists

`auth login` fails with exit 1 and a message naming the directory and the underlying error; it does
**not** keep a token only in memory (that would silently produce a session that vanishes and breaks
the next command). CI should use an API token instead (§10).

---

## 8. Resolution-chain change

Current chain (`internal/auth`, unchanged by this proposal):

1. profile `api_token_env` (named environment variable);
2. `FLAREADM_API_TOKEN`;
3. `CLOUDFLARE_API_TOKEN`;
4. `CF_API_TOKEN`.

Proposed chain — **environment first, then the store**, per profile:

1. profile `api_token_env`;
2. `FLAREADM_API_TOKEN`;
3. `CLOUDFLARE_API_TOKEN`;
4. `CF_API_TOKEN`;
5. **new:** OAuth credential for the active profile (refreshed when expired).

Rationale, with evidence: Wrangler documents that API tokens in the environment "continue to take
priority over any stored OAuth credentials" (E4) and refuses to start a login while they are set
(E9). Keeping the environment first means every CI pipeline, every existing script and every test
behaves identically after the change, and a developer with a stale OAuth credential cannot
accidentally override the token their CI exported. The cost is that a user who has both must unset
the environment variable to use OAuth — the same trade-off Wrangler documents (E4).

Profiles select between the two implicitly: a profile with neither `api_token_env` nor a stored
OAuth credential falls through to the next step of the chain, and `auth status` reports which of
the five sources won. A profile-level `auth_method = "oauth" | "env"` pin is **not** proposed: it
would create a second source of truth for the same decision `[INFERENCE]`.

---

## 9. Security model

- **No tokens in `argv`**: the authorize URL (which contains the client id, state and PKCE
  challenge but no secret) may be printed; the code, code verifier, access token and refresh token
  never appear on a command line, and the callback URL printed for `--no-browser` is safe to copy.
- **PKCE S256** only; `plain` is advertised by discovery (E3) but must not be used.
- **State/CSRF**: a random `state` is generated per login and compared on callback; mismatch aborts
  the login (Wrangler treats a mismatch as possible malicious activity, E8).
- **Callback server**: binds the loopback address only by default; `--callback-host` follows
  Wrangler's model for containers (E4) but is documented as a deliberate trust expansion. The
  server accepts exactly one request to the registered path, then shuts down; unexpected requests
  are rejected and logged to stderr.
- **Redaction**: §7.4.
- **Refresh-token handling**: re-read from disk before each refresh (E8); never logged; only the
  value that the server returns replaces the stored one.
- **Logout**: revoke first, then delete (E9). If revocation fails, keep the local credential and
  report exit 8 so the user can retry — deleting locally without revoking would leave a live token
  on the server.
- **Clock skew / expiry**: refresh when `expires_at` is inside a five-minute window; on a 401/403
  from any API call, one refresh-and-retry is attempted before surfacing the error; a rejected
  refresh (exit 3) tells the user to run `auth login` again.
- **Compliance regions**: Wrangler refuses OAuth login in the `fedramp_high` compliance region and
  requires an API token there (E9). `[INFERENCE]` FlareADM has no compliance-region concept today;
  the implementation should detect the documented `CLOUDFLARE_COMPLIANCE_REGION`-style signal only
  if/when the project adopts one, and must not silently attempt OAuth in a region that forbids it.
- **Scopes are a ceiling, not a grant**: the token's effective access is the intersection of the
  granted scopes and the user's account permissions `[INFERENCE]`, so scope-minimised tokens still
  need the user's own role (E1 private-client rule).

---

## 10. CI and non-interactive behaviour

Rules, all testable offline:

1. `auth login` **never hangs**: if stdin is not a terminal and `--no-browser` is absent, it exits
   2 immediately with the message "login requires a terminal; use --no-browser to print the URL, or
   set FLAREADM_API_TOKEN for CI" (mirrors Wrangler's `no-credentials-non-interactive` outcome, E9).
2. With `--no-browser`, the flow prints the authorize URL, waits at most `--timeout`, and exits 8 on
   timeout with the URL repeated on stderr so a second terminal can complete it (Wrangler documents
   exactly this workaround, E4).
3. No command other than `auth login` ever opens a browser or starts a listener. Every API command
   that finds an expired credential attempts a refresh; if the refresh is rejected, it exits 3 with
   `run 'flareadm auth login' to renew` — never a prompt.
4. `--no-input` is honoured: destructive commands keep their existing exit-2 behaviour, and
   `auth logout` requires `--yes` when stdin is not a terminal (consistent with `docs/cli.md`).
5. CI guidance: keep using an API token (E4 recommends the same for Wrangler).

---

## 11. Test strategy (fully offline)

The flow's endpoints must be overridable exactly as Wrangler's are (E10), with FlareADM-named
variables so nothing collides with Wrangler:

- `FLAREADM_OAUTH_AUTH_URL` (default `https://dash.cloudflare.com/oauth2/auth`)
- `FLAREADM_OAUTH_TOKEN_URL` (default `https://dash.cloudflare.com/oauth2/token`)
- `FLAREADM_OAUTH_REVOKE_URL` (default `https://dash.cloudflare.com/oauth2/revoke`)
- `FLAREADM_OAUTH_DEVICE_URL` (only if `--device` ships; Wrangler deliberately does not allow
  overriding its device endpoint, E10 — FlareADM should follow that precedent unless tests require
  otherwise)

Offline test matrix (httptest against those overrides; no live Cloudflare calls):

| Test | Mechanism | Assertion |
| ---- | --------- | --------- |
| authorize URL | render the URL for fixed inputs | exact query string: `response_type=code`, `code_challenge_method=S256`, `scope` contains `offline_access` and `offline` (E7, E12), `state` echoed |
| full login | fake authorize page that redirects to the loopback callback with `code`+`state` | token endpoint receives `grant_type=authorization_code`, `code_verifier`, `client_id`, `redirect_uri` with **no** client secret (E8); store contains access+refresh token, scopes, expiry |
| state mismatch | callback with the wrong `state` | login fails with exit 3, no store write |
| denial | callback with `error=access_denied` | exit 3, message names the denial, no store write |
| refresh | stored credential with `expires_at` in the past | exactly one refresh request; new access token used; `refresh_token` replaced only when the response includes one (E8) |
| refresh rejected | token endpoint answers `invalid_grant` | exit 3 for the command, message points at `auth login`, stored credential deleted or marked unusable per §9 |
| rotation concurrency | two processes refresh against a stub that rotates | no lost rotation; last writer wins with a valid token (E8 semantics) |
| revocation | `auth logout` | revoke request carries the refresh token; local file removed; revoke failure exits 8 and keeps the file |
| expiry window | `expires_at` 3 minutes away | proactive refresh happens before the API call |
| non-interactive | stdin closed, no `--no-browser` | exit 2, no listener bound, message mentions `FLAREADM_API_TOKEN` |
| timeout | `--no-browser --timeout 1s` with no callback | exit 8, URL printed once, listener closed |
| redaction | login error and API error containing token material | the token never appears in stderr/`--debug`/`--dry-run` output (reuse the v1.0 hygiene assertions) |
| precedence | OAuth stored **and** `FLAREADM_API_TOKEN` set | the environment token wins and no refresh call is made (E4) |
| resolution | no env credential, valid stored OAuth | the API call carries the OAuth access token as the bearer credential |
| store failure | config dir made unwritable | exit 1, message names the directory |
| Windows paths | `APPDATA` pointed at a temp dir (the v1.0 harness pattern) | store lands under `%APPDATA%\flareadm\oauth` and login succeeds |

No test may perform a live network call: the loopback listener is the only socket, and the OAuth
endpoints are always the overridden httptest URLs.

---

## 12. Migration and compatibility

- **Additive**: no existing command changes behaviour; the resolution chain only gains a final
  fallback (§8). CI that exports a token is unaffected.
- **Docs to update** (owned elsewhere; listed here because this proposal depends on them):
  `docs/configuration.md` (new credential store, paths, permissions, env overrides),
  `docs/cli.md` (the `auth` group gains `login`/`logout`/`status`; exit-code table unchanged),
  `docs/oauth.md` (this file, once implemented: flip the status line and record the verified
  facts), `docs/roadmap.md` (v1.1 entry).
- **`docs/commands.md`** is generated by `tools/docgen`; the new commands appear automatically after
  `nix develop -c go run ./tools/docgen > docs/commands.md`. The docgen test asserts one section per
  leaf, so the reference cannot drift.
- **Store versioning**: `version: 1` in the file; a future format change must keep reading v1.

---

## 13. Open questions and risks

Things the documentation does not answer, and which the *user* must decide or which must be verified
against a live account before implementation is claimed complete:

- **Q1 (decision, blocking): which client id does FlareADM use?** Options: (a) each user registers a
  private client and passes `--client-id` (works today, more setup); (b) the project registers one
  public client (needs a verified Client URL, is permanently public, E1) so login works out of the
  box. (b) is the better user experience and the worse governance decision; it needs an owner.
- **Q2 (verification): the authoritative scope list — resolved 2026-09-13.** `GET /oauth/scopes` was
  read on the live account and recorded in `cmd/auth/scopes_generated.go` (**385 dot-delimited ids
  in 13 categories**, regenerated with `tools/scopegen`). The pre-0.4 colon-delimited names are not
  live ids; every id the CLI requests is checked against the generated list
  (`TestScopeCatalogIDsExistLive`) and `--scopes` accepts any live id.
- **Q3 (decision): default scope set.** `--read-only` by default is safer but means every write
  command fails until the user logs in again with more scopes. Wrangler's default is the opposite
  (all scopes, E4). The proposal above defaults to read-only and documents the re-login; the user
  may prefer Wrangler's behaviour.
- **Q4 (verification): loopback redirect matching.** Does Cloudflare accept a redirect URI with a
  different port than registered, or a wildcard loopback URI? Not documented (E1, E4, E11). Test
  with a live client before advertising configurable ports.
- **Q5 (verification): device grant for third-party clients.** E1 says unsupported, E3/E4/E5 show it
  working for Wrangler. Verify before implementing `--device`.
- **Q6 (verification): revocation request format** — which token types
  `https://dash.cloudflare.com/oauth2/revoke` accepts and the required parameters (E3, E9).
- **Q7 (verification): `/user/tokens/verify` with an OAuth token** — undocumented (E6). The design
  avoids depending on it; confirm the negative to be able to document `auth verify` confidently.
- **Q8 (risk): scope gaps.** If no scope exists for a group such as `ruleset`, `waf`, `r2 bucket`,
  `hyperdrive`, `analytics` or `logs query`, OAuth cannot be used for those commands at all and the
  CLI must say so (exit 4 with an explanatory message) instead of issuing a request that always
  403s. This is the largest functional risk in the proposal.
- **Q9 (risk): user-permission intersection.** `[INFERENCE]` A granted scope never exceeds the
  user's own role; commands may therefore fail with 403 for reasons unrelated to the token. The
  error message must distinguish "scope not granted" (re-login with more scopes) from "your account
  role lacks this permission". **Implemented (Phase 4):** Cloudflare's 403 body does not say which
  is at fault, so FlareADM does not guess. When the request used an OAuth credential it appends a
  note naming both possibilities and how to check: `flareadm auth status` shows the granted scopes,
  and `flareadm auth login --all-scopes` re-logs in with more. API-token credentials get no note.
  **Still open:** the ambiguity itself is unresolved — this is a documented risk with better
  messaging, not a closed question, and it cannot be closed without the Phase 0 live verification.
- **Q10 (risk): public-client irreversibility.** If the project ever registers a client, the
  public/private choice is a one-way door (E1) — decide deliberately.
- **Q11 (risk): plaintext store.** Same exposure as Wrangler's default (E4), but users may expect
  keychain-grade protection from an OAuth feature. Document it loudly in `auth login` output and in
  `auth status`.

---

## 14. Implementation phases (proposed, with acceptance criteria)

**Phase 0 — verification spike (no shipped commands).**
Register a private OAuth client on a scratch account, then record: the `GET /oauth/scopes` list,
which of the §5 Q5 unknowns exist, whether the device grant works for a third-party client, the
revocation request format, and the `expires_in` value. *Acceptance:* a checked-in appendix (this
file) replacing every `unknown` marker with a verified fact or a definitive "does not exist".

**Phase 1 — credential store + resolution chain.**
Store read/write with atomic 0o600 writes and the Windows path rules; chain extension per §8; `auth
status`. *Acceptance:* existing tests unchanged; new tests for store permissions, Windows path
resolution, precedence, and redaction; `auth status` reports the winning source.

**Phase 2 — `auth login` (PKCE + loopback) and `auth logout`.**
Authorize URL, callback server, code exchange, refresh, revocation, non-interactive rules.
*Acceptance:* the §11 matrix passes offline; `--no-browser` prints a working URL; login under a
non-TTY exits 2 without binding a port.

**Phase 3 — refresh, expiry and failure semantics.**
Proactive refresh window, 401/403 refresh-and-retry, exit-3 messaging, rotation handling.
*Acceptance:* expiry, rotation, rejection and skew tests from §11; no command ever hangs.

**Phase 4 — `auth verify`/`auth status` integration and scope reporting.**
Identity via `GET /user`; scope listing from the store; scope-insufficient errors distinguish
re-login from role. *Acceptance:* verify works for both credential types with the same exit codes;
a 403 caused by a missing scope names the scope and the fix.

**Phase 5 — documentation and release.**
`docs/configuration.md`, `docs/cli.md`, `docs/roadmap.md`, regenerated `docs/commands.md`,
`--help` text. *Acceptance:* the v1.0 conformance audit items (discovery, global flags, exit codes,
non-TTY, determinism, `--dry-run`, `--no-input`) all still pass with the new commands included.

Optional later phases, each gated on Phase 0 evidence: `--device`, keychain storage, project-owned
public client id, per-account scope minimisation.
