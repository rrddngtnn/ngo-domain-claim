export PYTHONPATH := packages

.PHONY: test hygiene doctor status rank import-scan export-handoff

test:
	python3 -m pytest

hygiene:
	python3 scripts/public-hygiene-gate.py --repo-root .

doctor:
	python3 -m ngo_domain_claim.cli doctor

status:
	python3 -m ngo_domain_claim.cli status

rank:
	python3 -m ngo_domain_claim.cli rank --limit $${N:-20}
