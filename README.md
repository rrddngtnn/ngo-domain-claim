# ngo-domain-claim (Track Alpha)

Configurable public charity registry website-surface OSINT scanner, authoritative IANA RDAP verifier, Wayback CDX profiler, and research state tracker.

Paired with [`ngo-mail-catch`](https://github.com/rrddngtnn/ngo-mail-catch) (Track Beta: registry contact-domain parser and unified correlation dashboard) via the `ngo-recon-bridge/v1` contract.

## Install

```bash
python3 -m pip install -e ".[dev]"
cp alpha.example.toml private/alpha.toml
```

## Quickstart

```bash
export PYTHONPATH=packages

# Inspect resolved config and SQLite readiness
python3 -m ngo_domain_claim.cli --config private/alpha.toml doctor

# Run automated scan (source -> DNS A/MX/NS -> IANA RDAP -> SQLite)
python3 -m ngo_domain_claim.cli --config private/alpha.toml scan

# Check a single domain against authoritative IANA RDAP bootstrap
python3 -m ngo_domain_claim.cli --config private/alpha.toml rdap-check --domain example.org

# Probe Wayback Machine CDX snapshots & extract archived org metadata
python3 -m ngo_domain_claim.cli --config private/alpha.toml wayback-probe --limit 5
python3 -m ngo_domain_claim.cli --config private/alpha.toml snapshot-pull --limit 5
python3 -m ngo_domain_claim.cli --config private/alpha.toml taint-audit
python3 -m ngo_domain_claim.cli --config private/alpha.toml wayback-mirror --target example.org

# Run multi-signal resurrection / twin / rebrand watch
python3 -m ngo_domain_claim.cli --config private/alpha.toml watch --target example.org --rebrand-web

# Verify live DNS (A/MX/SPF/DMARC) + HTTPS/About readiness, rank, and track stages
python3 -m ngo_domain_claim.cli --config private/alpha.toml preflight --domain example.org --email contact@example.org
python3 -m ngo_domain_claim.cli --config private/alpha.toml rank --limit 20
python3 -m ngo_domain_claim.cli --config private/alpha.toml status

# Export bridge snapshot for Track Beta correlation
python3 -m ngo_domain_claim.cli --config private/alpha.toml export-bridge
```

## Tests & hygiene gate

```bash
make test
make hygiene
```
