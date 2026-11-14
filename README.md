# ngo-domain-claim (Track Alpha)

Public registry website surface telemetry, DNS/RDAP availability tracking, Wayback CDX snapshot indexing, and candidate scoring for LMIC nonprofit research.

Paired with [`ngo-mail-catch`](../ngo-mail-catch) (Track Beta: registry contact-domain analysis and unified cross-track correlation) via the `ngo-recon-bridge/v1` JSON handoff schema.

## Quickstart

```bash
export PYTHONPATH=packages

# Import verified scan results
python3 -m ngo_domain_claim.cli import-scan --file ../final.json

# View pipeline summary and top-ranked candidates
python3 -m ngo_domain_claim.cli status
python3 -m ngo_domain_claim.cli rank --limit 15

# Probe Wayback Machine CDX snapshots for top candidates
python3 -m ngo_domain_claim.cli wayback-probe --limit 5

# Export bridge snapshot for Track Beta correlation
python3 -m ngo_domain_claim.cli export-bridge --out private/alpha_bridge.json
```
