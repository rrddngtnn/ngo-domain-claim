"""CLI for Track Alpha: configurable public registry website-surface OSINT scanner."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from ngo_domain_claim.bridge.handoff import export_bridge_snapshot
from ngo_domain_claim.core.config import load_config
from ngo_domain_claim.core.store import (
    STAGES,
    advance_stage,
    get_snapshot_meta,
    open_db,
    save_snapshot_meta,
    status_summary,
    update_wayback,
    upsert_target,
)
from ngo_domain_claim.recon.mirror import mirror_clean_wayback_site
from ngo_domain_claim.recon.snapshot import extract_org_metadata, fetch_latest_snapshot
from ngo_domain_claim.recon.taint import analyze_snapshot_taint
from ngo_domain_claim.recon.wayback import fetch_cdx_summary
from ngo_domain_claim.scanner.pipeline import run_scan
from ngo_domain_claim.scanner.preflight import check_domain_preflight
from ngo_domain_claim.scanner.rdap import RdapResolver


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ngo-domain-claim")
    ap.add_argument("--config", default=None, help="Path to TOML config (overrides ALPHA_CONFIG)")
    ap.add_argument("--db", default=None, help="SQLite inventory path (overrides ALPHA_RECON_DB / TOML)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor", help="Check SQLite schema and resolved configuration")
    sub.add_parser("status", help="Show summary counts by stage and country")

    p_scan = sub.add_parser("scan", help="Run automated OSINT scan via configured source + DNS + IANA RDAP")
    p_scan.add_argument("--source-kind", default=None, choices=["rest_directory", "json_file", "csv_file", "text_urls"])
    p_scan.add_argument("--base-url", default=None)
    p_scan.add_argument("--file", default=None)
    p_scan.add_argument("--countries", default=None, help="Comma-separated ISO3 codes")
    p_scan.add_argument("--max-pages", type=int, default=None)
    p_scan.add_argument("--no-doh", action="store_true", help="Disable DoH MX/NS verification")
    p_scan.add_argument("--dry-run", action="store_true")

    p_rdap = sub.add_parser("rdap-check", help="Check one domain via authoritative IANA RDAP bootstrap")
    p_rdap.add_argument("--domain", required=True)

    p_pre = sub.add_parser("preflight", help="Verify live DNS (A/MX/SPF/DMARC) and HTTPS/About readiness")
    p_pre.add_argument("--domain", required=True)
    p_pre.add_argument("--email", default=None)
    p_pre.add_argument("--name", default=None)

    p_imp = sub.add_parser("import-scan", help="Import normalized JSON scan output into SQLite")
    p_imp.add_argument("--file", required=True, help="Path to JSON array file")

    p_rank = sub.add_parser("rank", help="List top-scored candidates")
    p_rank.add_argument("--limit", type=int, default=20)
    p_rank.add_argument("--iso", default=None, help="Filter by ISO3 country code")
    p_rank.add_argument("--stage", default=None, help="Filter by stage")

    p_wb = sub.add_parser("wayback-probe", help="Check Wayback CDX snapshot count for top candidates")
    p_wb.add_argument("--limit", type=int, default=5)
    p_wb.add_argument("--target", default=None, help="Specific root_domain or gs_id")

    p_snap = sub.add_parser("snapshot-pull", help="Pull latest archived HTML and extract org metadata")
    p_snap.add_argument("--limit", type=int, default=5)
    p_snap.add_argument("--target", default=None, help="root_domain or gs_id")

    p_meta = sub.add_parser("show-meta", help="Show extracted snapshot metadata for a target")
    p_meta.add_argument("--target", required=True)

    sub.add_parser("taint-audit", help="Re-evaluate stored snapshot_meta rows and demote tainted targets")

    p_mir = sub.add_parser("wayback-mirror", help="Pull clean pre-taint archived HTML pages into a local folder")
    p_mir.add_argument("--target", required=True, help="root_domain or gs_id")
    p_mir.add_argument("--out-dir", default=None, help="Output directory (default: private/mirror/<domain>)")
    p_mir.add_argument("--before-ts", default=None, help="Optional max Wayback timestamp e.g. 20241231235959")
    p_mir.add_argument("--max-pages", type=int, default=8)

    p_adv = sub.add_parser("set-stage", help="Update lifecycle stage for a candidate")
    p_adv.add_argument("--target", required=True, help="root_domain or gs_id")
    p_adv.add_argument("--stage", required=True, choices=STAGES)
    p_adv.add_argument("--notes", default=None)

    p_exp = sub.add_parser("export-bridge", help="Export shared bridge JSON for Track Beta correlation")
    p_exp.add_argument("--out", default=None)

    args = ap.parse_args(argv)
    overrides: dict[str, object] = {}
    if args.db:
        overrides["db"] = args.db
    if args.cmd == "scan":
        if args.source_kind:
            overrides["source_kind"] = args.source_kind
        if args.base_url:
            overrides["base_url"] = args.base_url
        if args.file:
            overrides["file"] = args.file
        if args.countries:
            overrides["countries"] = [c.strip().upper() for c in args.countries.split(",") if c.strip()]
        if args.max_pages is not None:
            overrides["max_pages"] = args.max_pages
        if args.no_doh:
            overrides["enable_doh"] = False

    cfg = load_config(args.config, cli_overrides=overrides)
    db = open_db(cfg.db_path)

    if args.cmd == "doctor":
        summary = status_summary(db)
        print(json.dumps({
            "ok": True,
            "db_path": cfg.db_path,
            "bridge_out": cfg.bridge_out,
            "source_kind": cfg.source.kind,
            "source_configured": bool(cfg.source.base_url or cfg.source.file_path),
            "doh_enabled": cfg.probe.enable_doh,
            "iana_bootstrap_url": cfg.probe.iana_bootstrap_url,
            "total_targets": summary["total_targets"],
        }, indent=2))
        return 0

    if args.cmd == "status":
        print(json.dumps(status_summary(db), indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "scan":
        report = run_scan(cfg, db, dry_run=args.dry_run)
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "preflight":
        rep = check_domain_preflight(
            args.domain,
            doh_url=cfg.probe.doh_url,
            expected_email=args.email,
            expected_name=args.name,
            timeout_s=cfg.probe.timeout_s,
            user_agent=cfg.user_agent,
        )
        print(json.dumps(rep, indent=2))
        return 0

    if args.cmd == "rdap-check":
        resolver = RdapResolver(
            bootstrap_url=cfg.probe.iana_bootstrap_url,
            cache_path=cfg.probe.rdap_cache_path,
            cache_ttl_s=cfg.probe.rdap_cache_ttl_s,
            extra_servers=cfg.probe.extra_rdap_servers,
            timeout_s=cfg.probe.timeout_s,
            user_agent=cfg.user_agent,
        )
        print(json.dumps(resolver.check_domain(args.domain), indent=2))
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

    if args.cmd == "snapshot-pull":
        if args.target:
            targets = [
                dict(r)
                for r in db.execute(
                    "SELECT gs_id, iso3, root_domain, name FROM targets WHERE gs_id=? OR root_domain=?",
                    (args.target, args.target.lower()),
                ).fetchall()
            ]
        else:
            targets = [
                dict(r)
                for r in db.execute(
                    "SELECT gs_id, iso3, root_domain, name FROM targets "
                    "WHERE wayback_snapshots > 0 AND stage IN ('discovered','wayback_checked') "
                    "ORDER BY score DESC, wayback_snapshots DESC LIMIT ?",
                    (args.limit,),
                ).fetchall()
            ]
        results = []
        for t in targets:
            snap = fetch_latest_snapshot(t["root_domain"])
            if snap.get("error"):
                results.append({"root_domain": t["root_domain"], "error": snap["error"]})
                continue
            meta = extract_org_metadata(snap, iso3=t.get("iso3") or "UNK", root_domain=t["root_domain"])
            save_snapshot_meta(db, t["gs_id"], meta)
            results.append({
                "root_domain": t["root_domain"],
                "snapshot_ts": meta.get("snapshot_ts"),
                "taint_verdict": (meta.get("taint") or {}).get("verdict"),
                "taint_reasons": (meta.get("taint") or {}).get("reasons"),
                "director_name": meta.get("director_name"),
                "emails": (meta.get("emails_on_page") or [])[:3],
                "page_title": meta.get("page_title"),
                "mission": (meta.get("mission_excerpt") or "")[:120],
            })
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "taint-audit":
        rows = db.execute(
            """SELECT sm.gs_id, sm.page_title, sm.mission_excerpt, t.iso3, t.root_domain
               FROM snapshot_meta sm
               JOIN targets t ON t.gs_id = sm.gs_id"""
        ).fetchall()
        flagged = []
        for r in rows:
            res = analyze_snapshot_taint(
                r["page_title"] or "",
                r["mission_excerpt"] or "",
                iso3=r["iso3"],
                root_domain=r["root_domain"],
                page_title=r["page_title"],
            )
            db.execute(
                "UPDATE snapshot_meta SET taint_verdict=?, taint_reasons=? WHERE gs_id=?",
                (res["verdict"], json.dumps(res["reasons"]), r["gs_id"]),
            )
            if res["is_tainted"]:
                db.execute(
                    "UPDATE targets SET stage='tainted_history', score=0, notes=? WHERE gs_id=?",
                    (f"taint:{res['verdict']} {','.join(res['reasons'])}", r["gs_id"]),
                )
                flagged.append({"root_domain": r["root_domain"], "verdict": res["verdict"], "reasons": res["reasons"]})
        db.commit()
        print(json.dumps({"audited": len(rows), "flagged": flagged}, indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "wayback-mirror":
        row = db.execute(
            "SELECT gs_id, iso3, root_domain FROM targets WHERE gs_id=? OR root_domain=?",
            (args.target, args.target.lower()),
        ).fetchone()
        dom = row["root_domain"] if row else args.target.lower()
        iso = row["iso3"] if row else "UNK"
        out_dir = args.out_dir or f"private/mirror/{dom}"
        manifest = mirror_clean_wayback_site(
            dom,
            out_dir,
            iso3=iso,
            before_ts=args.before_ts,
            max_pages=args.max_pages,
            timeout=cfg.probe.timeout_s,
            user_agent=cfg.user_agent,
        )
        print(json.dumps(manifest, indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "show-meta":
        meta = get_snapshot_meta(db, args.target)
        print(json.dumps(meta, indent=2, ensure_ascii=False) if meta else json.dumps({"error": "not found"}))
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
        out_path = args.out or cfg.bridge_out
        payload = export_bridge_snapshot(db, out_path)
        print(json.dumps({"out": out_path, "total": payload["total"], "exported_at": payload["exported_at"]}, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
