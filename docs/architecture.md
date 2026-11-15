# Architecture and operational boundaries

## Configuration precedence

Configuration resolves as: `CLI flags > environment variables > TOML file > defaults`. No directory URLs, API tokens, or country lists are hardcoded in source modules.

## Discovery pipeline (`scanner`)

1. **Source adapters (`scanner/sources.py`)**: `rest_directory`, `json_file`, `csv_file`, plus third-party `ngo_domain_claim.sources` entry points.
2. **DNS probing (`scanner/dns_probe.py`)**: Checks system `getaddrinfo` and optional DNS-over-HTTPS (`A`, `MX`, `NS`) so domains with active mail exchangers are not misclassified as dead.
3. **Authoritative RDAP (`scanner/rdap.py`)**: Resolves TLDs through the IANA RDAP DNS bootstrap (`data.iana.org/rdap/dns.json`) with local caching. TLDs absent from the bootstrap return `unsupported_tld` instead of false-positive availability.

## Bridge contract (`ngo-recon-bridge/v1`)

`export-bridge` serializes scored targets into JSON consumed by `ngo-mail-catch` for cross-track deduplication and unified status reporting.
