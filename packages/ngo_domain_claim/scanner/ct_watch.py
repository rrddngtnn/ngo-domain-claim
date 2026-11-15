"""Certificate Transparency (crt.sh) & multi-signal target resurrection / claim guard."""
from __future__ import annotations

import datetime
import json
import os
import sqlite3
from typing import Any
import urllib.parse
import urllib.request

from ngo_domain_claim.core.config import AlphaConfig
from ngo_domain_claim.core.store import record_event, utcnow
from ngo_domain_claim.scanner.dns_probe import probe_domain_dns
from ngo_domain_claim.scanner.rdap import RdapResolver

FARM_ISSUER_KEYWORDS = (
    "trustasia",
    "dnspod",
    "tencent",
    "aliyun",
    "digicert_cn",
    "woTrus",
)


def query_crtsh_history(
    domain: str,
    *,
    recent_days: int = 120,
    timeout_s: int = 15,
    user_agent: str = "ngo-domain-claim/0.2",
) -> dict[str, Any]:
    """Query crt.sh JSON API for TLS certificate issuance history on a domain."""
    dom = domain.lower().strip(".")
    q = urllib.parse.quote(dom)
    url = f"https://crt.sh/?q={q}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": user_agent, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            rows = json.loads(resp.read().decode("utf-8", "ignore"))
    except Exception as exc:
        return {
            "domain": dom,
            "ok": False,
            "error": str(exc),
            "total_certs": 0,
            "latest_not_before": None,
            "recent_cert_issued": False,
            "farm_ca_detected": False,
            "issuers": [],
        }

    if not isinstance(rows, list) or not rows:
        return {
            "domain": dom,
            "ok": True,
            "total_certs": 0,
            "latest_not_before": None,
            "recent_cert_issued": False,
            "farm_ca_detected": False,
            "issuers": [],
        }

    dates = sorted({str(r.get("not_before", ""))[:10] for r in rows if r.get("not_before")}, reverse=True)
    issuers = sorted({str(r.get("issuer_name", "")) for r in rows if r.get("issuer_name")})
    latest = dates[0] if dates else None

    recent_issued = False
    if latest:
        try:
            dt = datetime.date.fromisoformat(latest)
            age_days = (datetime.datetime.now(datetime.timezone.utc).date() - dt).days
            recent_issued = age_days <= recent_days
        except ValueError:
            recent_issued = False

    farm_ca = any(
        any(kw.lower() in iss.lower() for kw in FARM_ISSUER_KEYWORDS)
        for iss in issuers
    )

    return {
        "domain": dom,
        "ok": True,
        "total_certs": len(rows),
        "latest_not_before": latest,
        "recent_dates": dates[:5],
        "recent_cert_issued": recent_issued,
        "farm_ca_detected": farm_ca,
        "issuers": [i[:80] for i in issuers[:4]],
    }


def fetch_directory_org_state(
    gs_id: str,
    cfg: AlphaConfig,
) -> dict[str, Any] | None:
    """Query directory single-organisation endpoint for live claimedAt and registrationActive."""
    if not cfg.source.base_url or not gs_id or gs_id.startswith("texturl_"):
        return None
    base = cfg.source.base_url.rstrip("/")
    url = f"{base}/{urllib.parse.quote(gs_id)}"
    hdrs = {"User-Agent": cfg.user_agent, "Accept": "application/json"}
    token = os.environ.get(cfg.source.token_env, "").strip()
    if token:
        val = f"{cfg.source.auth_prefix}{token}" if cfg.source.auth_prefix else token
        hdrs[cfg.source.auth_header] = val
    if cfg.source.origin:
        hdrs["Origin"] = cfg.source.origin
    if cfg.source.referer:
        hdrs["Referer"] = cfg.source.referer

    proxy_url = os.environ.get(cfg.source.proxy_env, "").strip()
    req = urllib.request.Request(url, headers=hdrs)
    try:
        if proxy_url:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
            ctx = opener.open(req, timeout=cfg.probe.timeout_s)
        else:
            ctx = urllib.request.urlopen(req, timeout=cfg.probe.timeout_s)
        with ctx as resp:
            payload = json.loads(resp.read().decode("utf-8", "ignore"))
        data = payload.get("data") if isinstance(payload, dict) else None
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def watch_target(
    db: sqlite3.Connection,
    cfg: AlphaConfig,
    row: dict[str, Any],
    *,
    resolver: RdapResolver | None = None,
    check_ct: bool = True,
    check_directory: bool = True,
    recent_cert_days: int = 120,
    use_system_dns: bool = True,
) -> dict[str, Any]:
    """Run 4-signal OSINT watch on one target and update SQLite if burned or resurrected."""
    dom = row["root_domain"]
    gs_id = row["gs_id"]
    rdap = resolver or RdapResolver(
        bootstrap_url=cfg.probe.iana_bootstrap_url,
        cache_path=cfg.probe.rdap_cache_path,
        cache_ttl_s=cfg.probe.rdap_cache_ttl_s,
        extra_servers=cfg.probe.extra_rdap_servers,
        timeout_s=cfg.probe.timeout_s,
        user_agent=cfg.user_agent,
    )

    reasons: list[str] = []

    # Signal 1: Live DNS (A/AAAA/MX/NS) resurrection
    dns_res = probe_domain_dns(
        dom,
        enable_doh=cfg.probe.enable_doh,
        doh_url=cfg.probe.doh_url,
        timeout_s=cfg.probe.timeout_s,
        user_agent=cfg.user_agent,
        use_system_dns=use_system_dns,
    )
    if dns_res["alive"]:
        reasons.append(f"dns_resurrected:{dns_res['reason']}")

    # Signal 2: Authoritative RDAP re-registration
    rdap_res = rdap.check_domain(dom)
    if rdap_res["status"] == "taken":
        reasons.append(f"rdap_re_registered:{rdap_res['label']}")

    # Signal 3: Certificate Transparency (crt.sh) recent cert or farm CA
    ct_res: dict[str, Any] = {"ok": False}
    if check_ct:
        ct_res = query_crtsh_history(
            dom,
            recent_days=recent_cert_days,
            timeout_s=cfg.probe.timeout_s,
            user_agent=cfg.user_agent,
        )
        if ct_res.get("farm_ca_detected"):
            reasons.append(f"ct_farm_ca:{ct_res.get('latest_not_before')}")
        elif ct_res.get("recent_cert_issued"):
            reasons.append(f"ct_recent_cert:{ct_res.get('latest_not_before')}")

    # Signal 4: Directory claimedAt / registrationActive / website change
    dir_state = fetch_directory_org_state(gs_id, cfg) if check_directory else None
    if dir_state:
        if dir_state.get("claimedAt"):
            reasons.append(f"directory_already_claimed:{dir_state['claimedAt']}")
        if dir_state.get("registrationActive") is False:
            reasons.append("regulator_registration_inactive")

    verdict = "burned_or_resurrected" if reasons else "clean_available"
    now = utcnow()
    if reasons:
        new_stage = "tainted_history" if any(r.startswith("ct_farm_ca") for r in reasons) else "rejected"
        db.execute(
            "UPDATE targets SET stage=?, score=0, notes=?, updated_at=? WHERE gs_id=?",
            (new_stage, "watch:" + ";".join(reasons), now, gs_id),
        )
        record_event(db, gs_id, "watch_flagged", ";".join(reasons), row.get("stage"), new_stage)
        db.commit()

    return {
        "gs_id": gs_id,
        "root_domain": dom,
        "iso3": row.get("iso3"),
        "verdict": verdict,
        "reasons": reasons,
        "dns_alive": dns_res["alive"],
        "rdap_status": rdap_res["label"],
        "ct_latest_cert": ct_res.get("latest_not_before"),
        "ct_farm_ca": ct_res.get("farm_ca_detected", False),
        "directory_claimed_at": dir_state.get("claimedAt") if dir_state else None,
        "registration_active": dir_state.get("registrationActive") if dir_state else None,
    }
