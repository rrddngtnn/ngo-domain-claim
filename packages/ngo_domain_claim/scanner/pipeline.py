"""Automated OSINT scanning pipeline: source -> domain filter -> DNS -> IANA RDAP -> SQLite."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import sqlite3
from typing import Any
import urllib.parse

from ngo_domain_claim.core.config import AlphaConfig
from ngo_domain_claim.core.store import upsert_target
from ngo_domain_claim.scanner.dns_probe import probe_domain_dns
from ngo_domain_claim.scanner.rdap import RdapResolver
from ngo_domain_claim.scanner.sources import build_source


def extract_root_domain(website: str, skip_hosts: list[str]) -> str | None:
    if not website:
        return None
    u = website if "://" in website else f"http://{website}"
    host = (urllib.parse.urlparse(u).hostname or "").lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    if not host or "." not in host:
        return None
    if any(host == s or host.endswith("." + s) for s in skip_hosts):
        return None
    return host


def run_scan(
    cfg: AlphaConfig,
    db: sqlite3.Connection,
    *,
    dry_run: bool = False,
    use_system_dns: bool = True,
) -> dict[str, Any]:
    source = build_source(cfg.source, user_agent=cfg.user_agent)
    resolver = RdapResolver(
        bootstrap_url=cfg.probe.iana_bootstrap_url,
        cache_path=cfg.probe.rdap_cache_path,
        cache_ttl_s=cfg.probe.rdap_cache_ttl_s,
        extra_servers=cfg.probe.extra_rdap_servers,
        timeout_s=cfg.probe.timeout_s,
        user_agent=cfg.user_agent,
    )

    scanned_records = 0
    candidates: dict[str, dict[str, Any]] = {}
    for rec in source.iter_records():
        scanned_records += 1
        if cfg.source.type_filter and rec["type"] != cfg.source.type_filter.lower():
            continue
        if cfg.source.require_unclaimed and rec.get("claimedAt"):
            continue
        if cfg.source.require_registry and not rec.get("has_registry"):
            continue
        rdom = extract_root_domain(rec.get("website") or "", cfg.probe.skip_hosts)
        if not rdom:
            continue
        rec["rdom"] = rdom
        candidates.setdefault(rdom, rec)

    dns_dead: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, cfg.probe.workers)) as pool:
        futs = {
            pool.submit(
                probe_domain_dns,
                dom,
                enable_doh=cfg.probe.enable_doh,
                doh_url=cfg.probe.doh_url,
                timeout_s=cfg.probe.timeout_s,
                user_agent=cfg.user_agent,
                use_system_dns=use_system_dns,
            ): cand
            for dom, cand in candidates.items()
        }
        for fut in as_completed(futs):
            cand = futs[fut]
            res = fut.result()
            if not res["alive"]:
                dns_dead.append(cand)

    available_hits: list[dict[str, Any]] = []
    unsupported_count = 0
    taken_count = 0
    with ThreadPoolExecutor(max_workers=max(1, min(4, cfg.probe.workers))) as pool:
        futs = {pool.submit(resolver.check_domain, cand["rdom"]): cand for cand in dns_dead}
        for fut in as_completed(futs):
            cand = futs[fut]
            rd = fut.result()
            if rd["status"] == "unsupported_tld":
                unsupported_count += 1
            elif rd["status"] == "taken":
                taken_count += 1
            elif rd["available"]:
                item = {
                    **cand,
                    "rdap": rd["label"],
                    "conf": rd["confidence"],
                }
                available_hits.append(item)

    added = 0
    updated = 0
    if not dry_run:
        for item in available_hits:
            if upsert_target(db, item):
                added += 1
            else:
                updated += 1

    return {
        "source_kind": cfg.source.kind,
        "scanned_records": scanned_records,
        "unique_candidate_domains": len(candidates),
        "dns_dead": len(dns_dead),
        "rdap_available": len(available_hits),
        "rdap_taken": taken_count,
        "rdap_unsupported_tld": unsupported_count,
        "added": added,
        "updated": updated,
        "dry_run": dry_run,
        "hits": [
            {"iso": h["iso"], "domain": h["rdom"], "name": h["name"], "conf": h["conf"]}
            for h in available_hits
        ],
    }
