# FlareADM

A fast, standalone administration CLI for Cloudflare.

FlareADM is a single native Go executable for inspecting, configuring and operating
remote Cloudflare resources from a terminal, a script, a CI pipeline or an AI agent.
It is designed for operators who need Cloudflare account and infrastructure
management without a JavaScript runtime.

It complements Wrangler rather than replacing it. Use Wrangler for Workers
application development; use FlareADM for remote account and infrastructure
administration.

> FlareADM is an independent open-source project and is not affiliated with or endorsed by
> Cloudflare, Inc. Cloudflare product and service names are used only to describe compatibility.

**Status:** v0.1 implemented, unreleased.

## Quickstart

Build the binary:

```bash
nix build
./result/bin/flareadm
```

Set up the development environment:

```bash
nix develop
```

or, with `direnv` installed:

```bash
direnv allow
```

## Usage

The command model follows a stable, AWS-CLI-like hierarchy. Here is a short example
of the intended interface (see [design](docs/design.md) for the full model):

```bash
flareadm account list

flareadm zone list
flareadm zone get --zone example.com

flareadm dns record list --zone example.com

flareadm dns record create \
  --zone example.com \
  --type A \
  --name api \
  --content 192.0.2.10 \
  --proxied
```

## Documentation

- [Documentation index](docs/README.md)
- [CLI reference](docs/cli.md)
- [Roadmap](docs/roadmap.md)

## License

[Apache-2.0](LICENSE)
