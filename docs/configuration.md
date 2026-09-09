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

[profile.company]
account_id = "cccccccccccccccccccccccccccccccc"
api_token_env = "CF_COMPANY_TOKEN"
```

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
4. `CF_API_TOKEN`.

Support for OS credential stores may be added later.

### Security rules

FlareADM SHALL:

- redact authorization headers in debug logs;
- never print tokens in normal output;
- avoid token command-line flags because process arguments can be observable;
- create sensitive files with restrictive permissions where supported;
- never include credentials in crash/error reports;
- refuse to write credentials into shell history through generated commands.

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
