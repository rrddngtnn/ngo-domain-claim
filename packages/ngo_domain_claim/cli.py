"""CLI for Track Alpha: public registry website telemetry and research state tracking."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from ngo_domain_claim.bridge.handoff import export_bridge_snapshot
from ngo_domain_claim.core.store import (
    STAGES,
    advance_stage,
    open_db,
    status_summary,
    update_wayback,
    upsert_target,
)
from ngo_domain_claim.recon.wayback import fetch_cdx_summary


def default_db_path() -> str:
    return os.environ.get("ALPHA_RECON_DB", "private/alpha_claims.sqlite")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ngo-domain-claim")
    ap.add_argument("--db", default=default_db_path(), help="SQLite inventory path")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor", help="Check SQLite schema and environment readiness")
    sub.add_parser("status", help="Show summary counts by stage and country")

    p_imp = sub.add_parser("import-scan", help="Import JSON scan output into SQLite")
    p_imp.add_argument("--file", required=True, help="Path to final.json or cands.json")

    p_rank = sub.add_parser("rank", help="List top-scored research candidates")
    p_rank.add_argument("--limit", type=int, default=20)
    p_rank.add_argument("--iso", default=None, help="Filter by ISO3 country code")
    p_rank.add_argument("--stage", default=None, help="Filter by stage")

    p_wb = sub.add_parser("wayback-probe", help="Check Wayback CDX snapshot count for top candidates")
    p_wb.add_argument("--limit", type=int, default=5)
    p_wb.add_argument("--target", default=None, help="Specific root_domain or gs_id")

    p_adv = sub.add_parser("set-stage", help="Update research stage for a candidate")
    p_adv.add_argument("--target", required=True, help="root_domain or gs_id")
    p_adv.add_argument("--stage", required=True, choices=STAGES)
    p_adv.add_argument("--notes", default=None)

    p_exp = sub.add_parser("export-bridge", help="Export shared bridge JSON for Track Beta correlation")
    p_exp.add_argument("--out", default="private/alpha_bridge.json")

    args = ap.parse_args(argv)
    db = open_db(args.db)

    if args.cmd == "doctor":
        summary = status_summary(db)
        print(json.dumps({"ok": True, "db": args.db, "total_targets": summary["total_targets"]}, indent=2))
        return 0

    if args.cmd == "status":
        print(json.dumps(status_summary(db), indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "import-scan":
        items = json.loads(Path(args.file).read_text(encoding="utf-8"))
        added = 0
        updated = 0
        for item in items:
            if upsert_target(db, item):
                added += 1
            else:
                updated += 1
        print(json.dumps({"imported_file": args.file, "added": added, "updated": updated}, indent=2))
        return 0

    if args.cmd == "rank":
        clauses = ["1=1"]
        params: list[object] = []
        if args.iso:
            clauses.append("iso3=?")
            params.append(args.iso.upper())
        if args.stage:
            clauses.append("stage=?")
            params.append(args.stage)
        params.append(args.limit)
        sql = f"""
            SELECT gs_id, iso3, country, name, registry_code, registry_id,
                   root_domain, confidence, stage, score, wayback_snapshots,
                   wayback_first_ts, wayback_last_ts
            FROM targets
            WHERE {' AND '.join(clauses)}
            ORDER BY score DESC, wayback_snapshots DESC, id ASC
            LIMIT ?
        """
        rows = [dict(r) for r in db.execute(sql, params).fetchall()]
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "wayback-probe":
        if args.target:
            targets = [
                dict(r)
                for r in db.execute(
                    "SELECT gs_id, root_domain FROM targets WHERE gs_id=? OR root_domain=?",
                    (args.target, args.target.lower()),
                ).fetchall()
            ]
        else:
            targets = [
                dict(r)
                for r in db.execute(
                    "SELECT gs_id, root_domain FROM targets WHERE stage='discovered' ORDER BY score DESC LIMIT ?",
                    (args.limit,),
                ).fetchall()
            ]
        results = []
        for t in targets:
            info = fetch_cdx_summary(t["root_domain"])
            updated_row = update_wayback(
                db,
                t["gs_id"],
                int(info.get("snapshots") or 0),
                info.get("first_ts"),
                info.get("last_ts"),
            )
            results.append({
                "root_domain": t["root_domain"],
                "snapshots": updated_row["wayback_snapshots"],
                "first_ts": updated_row["wayback_first_ts"],
                "last_ts": updated_row["wayback_last_ts"],
                "score": updated_row["score"],
            })
        print(json.dumps(results, indent=2))
        return 0

    if args.cmd == "set-stage":
        updated = advance_stage(db, args.target, args.stage, notes=args.notes)
        print(json.dumps({
            "gs_id": updated["gs_id"],
            "root_domain": updated["root_domain"],
            "stage": updated["stage"],
            "score": updated["score"],
            "notes": updated["notes"],
        }, indent=2))
        return 0

    if args.cmd == "export-bridge":
        payload = export_bridge_snapshot(db, args.out)
        print(json.dumps({"out": args.out, "total": payload["total"], "exported_at": payload["exported_at"]}, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
