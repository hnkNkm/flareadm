# FlareADM documentation

> FlareADM is an independent open-source project and is not affiliated with or endorsed by
> Cloudflare, Inc. Cloudflare product and service names are used only to describe compatibility.

FlareADM is a fast, standalone administration CLI for Cloudflare: a single native Go
executable for inspecting, configuring and operating remote Cloudflare resources from a
terminal, a script, a CI pipeline or an AI agent.

It complements Wrangler rather than replacing it. Use Wrangler for Workers application
development; use FlareADM for remote account and infrastructure administration.

**Status:** v0.1–v0.3 complete (unreleased). Command surface, exit codes and normalized output are usable; releases are not yet published. See the [roadmap](roadmap.md).

## At a glance

| Decision | Value |
| --- | --- |
| Name | FlareADM |
| Binary | `flareadm` |
| Language | Go |
| Distribution | Single native executable |
| Primary role | Cloudflare remote administration |
| Design reference | AWS CLI |
| API layer | Official Cloudflare Go SDK behind internal adapters |
| Local development | Out of scope (Wrangler) |
| Wrangler clone | No |
| Machine output | Stable normalized JSON + `--raw` mode |
| Profiles | Yes |
| CI/agent support | First-class |
| Telemetry | None by default |
| License | Apache-2.0 |

## Index

| Document | Contents |
| --- | --- |
| [design.md](design.md) | Positioning, background, goals, non-goals, principles, naming |
| [cli.md](cli.md) | Command model, global options, output contract, exit codes |
| [configuration.md](configuration.md) | Profiles, credential policy, account and zone resolution |
| [architecture.md](architecture.md) | API client layering, Go structure, dependencies, performance |
| [development.md](development.md) | Nix dev shell, build, test, lint, release |
| [roadmap.md](roadmap.md) | v0.1 scope, roadmap, compatibility policy, open decisions |
