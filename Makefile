export PYTHONPATH := packages

.PHONY: test hygiene doctor status scan rdap-check preflight rank snapshot-pull export-bridge

test:
	python3 -m pytest

hygiene:
	python3 scripts/public-hygiene-gate.py --repo-root .

doctor:
	python3 -m ngo_domain_claim.cli doctor

status:
	python3 -m ngo_domain_claim.cli status

scan:
	python3 -m ngo_domain_claim.cli scan

rdap-check:
	python3 -m ngo_domain_claim.cli rdap-check --domain $(DOMAIN)

preflight:
	python3 -m ngo_domain_claim.cli preflight --domain $(DOMAIN)

rank:
	python3 -m ngo_domain_claim.cli rank --limit $${N:-20}

snapshot-pull:
	python3 -m ngo_domain_claim.cli snapshot-pull --limit $${N:-5}

export-bridge:
	python3 -m ngo_domain_claim.cli export-bridge
