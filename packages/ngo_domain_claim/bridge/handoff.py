"""Shared JSON handoff contract between Track Alpha (website recon) and Track Beta (registry contact recon)."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from typing import Any

from ngo_domain_claim.core.store import utcnow

SCHEMA_VERSION = "ngo-recon-bridge/v1"


def export_bridge_snapshot(db: sqlite3.Connection, out_path: str | Path) -> dict[str, Any]:
    rows = [
        dict(r)
        for r in db.execute(
            """SELECT gs_id, iso3, country, name, registry_name, registry_code,
                      registry_id, website_url, root_domain, rdap_status,
                      confidence, stage, score, wayback_snapshots,
                      wayback_first_ts, wayback_last_ts, updated_at
               FROM targets
               ORDER BY score DESC, id ASC"""
        ).fetchall()
    ]
    payload = {
        "schema": SCHEMA_VERSION,
        "source_repo": "ngo-domain-claim",
        "track": "alpha_website_surface",
        "exported_at": utcnow(),
        "total": len(rows),
        "records": rows,
    }
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return payload
