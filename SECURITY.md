# Security policy

`ngo-domain-claim` queries public charity directory APIs, DNS resolvers, IANA RDAP servers, and web archives, storing research metadata locally in SQLite.

## Reporting a vulnerability

Report security issues privately via GitHub Security Advisories or the maintainer profile contact rather than public issues.

## Handling of secrets and private state

- `private/`, `*.sqlite`, `*.db`, `*.csv`, and `.env` are gitignored by default.
- Never commit live API tokens, private registry dumps, or operational notes.
- Run `python3 scripts/public-hygiene-gate.py --repo-root .` before pushing to any public remote.
