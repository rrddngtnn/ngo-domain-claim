"""Certificate Transparency & multi-signal target resurrection / rebrand / claim guard."""
from __future__ import annotations

import datetime
import json
import os
import re
import sqlite3
from typing import Any, Sequence
import urllib.error
import urllib.parse
import urllib.request

from ngo_domain_claim.core.config import (
    DEFAULT_FARM_ISSUERS,
    DEFAULT_REBRAND_PHRASES,
    AlphaConfig,
)
from ngo_domain_claim.core.store import record_event, utcnow
from ngo_domain_claim.scanner.dns_probe import probe_domain_dns
from ngo_domain_claim.scanner.rdap import RdapResolver

FARM_ISSUER_KEYWORDS = tuple(DEFAULT_FARM_ISSUERS)
REBRAND_PHRASES = tuple(DEFAULT_REBRAND_PHRASES)

GENERIC_ORG_WORDS = {
    "association", "foundation", "fondation", "organization", "organisation",
    "charity", "trust", "society", "initiative", "project", "program", "action",
    "development", "international", "global", "national", "center", "centre",
    "group", "committee", "council", "network", "welfare", "relief", "help",
    "community",
}

GENERIC_ADDR_STOPWORDS = {
    "registered", "office", "street", "avenue", "road", "lane", "drive",
    "box", "po", "postal", "commune", "zone", "province", "district",
    "city", "town", "village", "region", "country", "quartier", "secteur",
}


def _open_url(
    url: str,
    *,
    headers: dict[str, str],
    timeout_s: int,
    proxy_url: str | None = None,
):
    req = urllib.request.Request(url, headers=headers)
    if proxy_url:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        )
        return opener.open(req, timeout=timeout_s)
    return urllib.request.urlopen(req, timeout=timeout_s)


def _directory_headers(cfg: AlphaConfig) -> dict[str, str]:
    hdrs = {"User-Agent": cfg.user_agent, "Accept": "application/json"}
    token = os.environ.get(cfg.source.token_env, "").strip()
    if token:
        val = f"{cfg.source.auth_prefix}{token}" if cfg.source.auth_prefix else token
        hdrs[cfg.source.auth_header] = val
    if cfg.source.origin:
        hdrs["Origin"] = cfg.source.origin
    if cfg.source.referer:
        hdrs["Referer"] = cfg.source.referer
    return hdrs


def query_crtsh_history(
    domain: str,
    *,
    ct_url_template: str = "https://crt.sh/?q={domain}&output=json",
    farm_issuer_keywords: Sequence[str] = FARM_ISSUER_KEYWORDS,
    recent_days: int = 120,
    timeout_s: int = 15,
    user_agent: str = "ngo-domain-claim/0.2",
    proxy_url: str | None = None,
) -> dict[str, Any]:
    """Query Certificate Transparency JSON endpoint for TLS certificate issuance history."""
    dom = domain.lower().strip(".")
    q = urllib.parse.quote(dom)
    url = ct_url_template.format(domain=q)
    try:
        with _open_url(
            url,
            headers={"User-Agent": user_agent, "Accept": "application/json"},
            timeout_s=timeout_s,
            proxy_url=proxy_url,
        ) as resp:
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
        any(kw.lower() in iss.lower() for kw in farm_issuer_keywords)
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
    *,
    proxy_url: str | None = None,
) -> dict[str, Any] | None:
    """Query directory single-organisation endpoint for live claimedAt and registrationActive."""
    if not cfg.source.base_url or not gs_id or gs_id.startswith("texturl_"):
        return None
    base = cfg.source.base_url.rstrip("/")
    url = f"{base}/{urllib.parse.quote(gs_id)}"
    hdrs = _directory_headers(cfg)
    px = proxy_url if proxy_url is not None else (os.environ.get(cfg.source.proxy_env, "").strip() or None)
    try:
        with _open_url(url, headers=hdrs, timeout_s=cfg.probe.timeout_s, proxy_url=px) as resp:
            payload = json.loads(resp.read().decode("utf-8", "ignore"))
        data = payload.get("data") if isinstance(payload, dict) else None
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _norm_addr(val: str | None) -> str:
    return re.sub(r"[^a-z0-9]", "", (val or "").lower())


def check_directory_twins(
    row: dict[str, Any],
    cfg: AlphaConfig,
    *,
    proxy_url: str | None = None,
) -> dict[str, Any]:
    """Query directory search by distinctive org-name & address tokens to spot claimed twins/rebrands."""
    if not cfg.source.base_url:
        return {"checked": False, "status": "skipped_no_base_url", "claimed_twins": []}
    iso = (row.get("iso3") or "").upper()
    name = (row.get("name") or "").strip()
    gs_id = row.get("gs_id") or ""
    if not iso or not name:
        return {"checked": False, "status": "skipped_missing_fields", "claimed_twins": []}

    name_tokens = [w for w in re.split(r"[^A-Za-z0-9]+", name) if len(w) >= 4 and w.lower() not in GENERIC_ORG_WORDS]
    queries: list[str] = []
    if name_tokens:
        queries.append(" ".join(name_tokens[:2]))
    else:
        queries.append(name)

    country_tokens = {w.lower() for w in re.split(r"[^A-Za-z0-9]+", row.get("country") or "") if len(w) >= 3}
    stop_words = GENERIC_ADDR_STOPWORDS | country_tokens

    raw_addr = row.get("address") or ""
    addr_tokens = [
        w for w in re.split(r"[^A-Za-z0-9]+", raw_addr)
        if len(w) >= 5 and w.lower() not in stop_words
    ]
    if addr_tokens:
        queries.append(addr_tokens[0])

    base = cfg.source.base_url.rstrip("/")
    hdrs = _directory_headers(cfg)
    px = proxy_url if proxy_url is not None else (os.environ.get(cfg.source.proxy_env, "").strip() or None)

    country_param = cfg.source.country_param or "countryCode"
    search_param = cfg.source.search_param or "query"

    seen_ids: set[str] = set()
    all_rows: list[dict[str, Any]] = []
    errors: list[str] = []
    for q_str in queries[:2]:
        url = f"{base}?{urllib.parse.urlencode({country_param: iso, search_param: q_str})}"
        try:
            with _open_url(url, headers=hdrs, timeout_s=cfg.probe.timeout_s, proxy_url=px) as resp:
                rows = json.loads(resp.read().decode("utf-8", "ignore")).get("data") or []
            for r in rows:
                rid = r.get("id")
                if rid and rid not in seen_ids:
                    seen_ids.add(rid)
                    all_rows.append(r)
        except Exception as exc:
            errors.append(str(exc))
            continue

    if errors and not all_rows:
        return {"checked": False, "status": f"error:{errors[0]}", "claimed_twins": []}

    row_addr = _norm_addr(raw_addr)
    addr_words = {w.lower() for w in addr_tokens}
    claimed_twins: list[dict[str, Any]] = []
    for cand in all_rows:
        if cand.get("id") == gs_id or not cand.get("claimedAt"):
            continue
        cand_addr_raw = cand.get("address") or ""
        cand_addr = _norm_addr(cand_addr_raw)
        cand_words = {w.lower() for w in re.split(r"[^A-Za-z0-9]+", cand_addr_raw) if len(w) >= 5}
        addr_match = bool(
            (row_addr and cand_addr and (row_addr[:12] in cand_addr or cand_addr[:12] in row_addr))
            or (addr_words and cand_words and (addr_words & cand_words))
        )
        cand_name_low = (cand.get("name") or "").lower()
        name_overlap = any(t.lower() in cand_name_low for t in name_tokens[:2])
        if addr_match or name_overlap:
            claimed_twins.append({
                "id": cand.get("id"),
                "name": cand.get("name"),
                "website": cand.get("website"),
                "claimedAt": cand.get("claimedAt"),
                "address_match": addr_match,
            })
    return {"checked": True, "status": "ok", "claimed_twins": claimed_twins}


def _extract_search_plain_text(raw_body: str, content_type: str, query_text: str) -> tuple[str, bool]:
    """Return normalized lowercase text from JSON API or HTML SERP, plus bot-challenge flag."""
    ct_low = content_type.lower()
    stripped = raw_body.lstrip()
    if "application/json" in ct_low or stripped.startswith("{") or stripped.startswith("["):
        try:
            payload = json.loads(raw_body)
            items: list[Any] = []
            if isinstance(payload, dict):
                data_obj = payload.get("data")
                items = (
                    payload.get("results")
                    or payload.get("organic")
                    or payload.get("items")
                    or (data_obj.get("web") if isinstance(data_obj, dict) else None)
                    or []
                )
            elif isinstance(payload, list):
                items = payload
            parts: list[str] = []
            for item in items:
                if isinstance(item, dict):
                    for key in ("title", "content", "snippet", "description", "url"):
                        val = item.get(key)
                        if isinstance(val, str):
                            parts.append(val)
            return re.sub(r"\s+", " ", " ".join(parts)).lower(), False
        except json.JSONDecodeError:
            pass

    low_raw = raw_body.lower()
    if (
        "anomaly-modal" in low_raw
        or "please complete the following challenge" in low_raw
        or "cf-turnstile" in low_raw
        or "unusual traffic from your computer" in low_raw
    ):
        return "", True

    cleaned_html = re.sub(
        r"<(?:form|script|style|title)[^>]*>.*?</(?:form|script|style|title)>",
        " ",
        raw_body,
        flags=re.I | re.S,
    )
    cleaned_html = re.sub(r"<input[^>]*>", " ", cleaned_html, flags=re.I)
    plain = re.sub(r"<[^>]+>", " ", cleaned_html)
    plain = re.sub(r"\s+", " ", plain).lower()
    if query_text.lower() in plain:
        plain = plain.replace(query_text.lower(), " ")
    return plain, False


def check_rebrand_signals(
    db: sqlite3.Connection,
    row: dict[str, Any],
    *,
    search_url_template: str = "https://html.duckduckgo.com/html/?q={query}",
    rebrand_phrases: Sequence[str] = REBRAND_PHRASES,
    check_web: bool = False,
    timeout_s: int = 10,
    user_agent: str = "ngo-domain-claim/0.2",
    proxy_url: str | None = None,
) -> dict[str, Any]:
    """Detect rebrand phrases in stored snapshot_meta or optional web search results (org + director)."""
    gs_id = row.get("gs_id") or ""
    name = (row.get("name") or "").strip()
    director = (row.get("director_name") or "").strip()
    reasons: list[str] = []

    snap = db.execute(
        "SELECT page_title, meta_description, mission_excerpt, director_name FROM snapshot_meta WHERE gs_id=?",
        (gs_id,),
    ).fetchone()
    if snap:
        if not director and snap["director_name"]:
            director = str(snap["director_name"]).strip()
        blob = " ".join(str(snap[k] or "") for k in ("page_title", "meta_description", "mission_excerpt")).lower()
        for ph in rebrand_phrases:
            if ph.lower() in blob:
                reasons.append(f"snapshot_rebrand_phrase:{ph}")

    web_hits: list[str] = []
    web_statuses: list[str] = []
    queries_run: list[str] = []

    if check_web and name:
        raw_queries = [f'"{name}" (formerly OR rebranded OR "changed our name")']
        if director:
            raw_queries.append(f'"{director}" ("{name}" OR rebranded OR "changed our name" OR formerly)')

        low_name = name.lower()
        low_dir = director.lower()
        for raw_q in raw_queries:
            queries_run.append(raw_q)
            url = search_url_template.format(query=urllib.parse.quote(raw_q))
            try:
                with _open_url(
                    url,
                    headers={"User-Agent": user_agent, "Accept": "text/html,application/json"},
                    timeout_s=timeout_s,
                    proxy_url=proxy_url,
                ) as resp:
                    if resp.status != 200:
                        web_statuses.append(f"challenge_http_{resp.status}")
                        continue
                    ctype = resp.headers.get("Content-Type", "")
                    raw_body = resp.read().decode("utf-8", "ignore")
                    plain, challenged = _extract_search_plain_text(raw_body, ctype, raw_q)
                    if challenged:
                        web_statuses.append("bot_challenge")
                        continue
                    web_statuses.append("ok")
                    if f"formerly {low_name}" in plain or f"formerly known as {low_name}" in plain:
                        if f"web_formerly_named:{name}" not in reasons:
                            reasons.append(f"web_formerly_named:{name}")
                        if url not in web_hits:
                            web_hits.append(url)
                    for ph in rebrand_phrases:
                        ph_low = ph.lower()
                        if ph_low in plain:
                            tag = f"web_rebrand_phrase:{ph}"
                            if tag not in reasons:
                                reasons.append(tag)
                            if url not in web_hits:
                                web_hits.append(url)
                    if low_dir and low_dir in plain and any(
                        tok in plain for tok in ("changed our name", "rebrand", "new name", "now known as", "formerly")
                    ):
                        tag = f"web_director_rebrand:{director}"
                        if tag not in reasons:
                            reasons.append(tag)
                        if url not in web_hits:
                            web_hits.append(url)
            except urllib.error.HTTPError as exc:
                web_statuses.append(f"challenge_http_{exc.code}")
            except Exception as exc:
                web_statuses.append(f"error:{exc}")

    if not web_statuses:
        web_status = "skipped"
    elif all(s == "ok" for s in web_statuses):
        web_status = "ok"
    elif any(s == "ok" for s in web_statuses):
        web_status = "partial:" + ",".join(sorted(set(web_statuses)))
    else:
        web_status = web_statuses[0]

    return {
        "rebrand_detected": bool(reasons),
        "reasons": reasons,
        "web_hits": web_hits,
        "web_status": web_status,
        "queries_run": queries_run,
        "director_checked": director or None,
    }


def watch_target(
    db: sqlite3.Connection,
    cfg: AlphaConfig,
    row: dict[str, Any],
    *,
    resolver: RdapResolver | None = None,
    check_ct: bool = True,
    check_directory: bool = True,
    check_rebrand: bool | None = None,
    rebrand_search_template: str | None = None,
    recent_cert_days: int | None = None,
    use_system_dns: bool = True,
) -> dict[str, Any]:
    """Run multi-signal OSINT watch on one target and update SQLite if burned or resurrected."""
    dom = row["root_domain"]
    gs_id = row["gs_id"]
    proxy_url = os.environ.get(cfg.source.proxy_env, "").strip() or None
    cert_days = recent_cert_days if recent_cert_days is not None else cfg.probe.recent_cert_days
    do_web_rebrand = cfg.probe.rebrand_check_web if check_rebrand is None else check_rebrand
    search_tpl = rebrand_search_template or cfg.probe.rebrand_search_url_template

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
            ct_url_template=cfg.probe.ct_api_url_template,
            farm_issuer_keywords=cfg.probe.farm_issuer_keywords,
            recent_days=cert_days,
            timeout_s=cfg.probe.timeout_s,
            user_agent=cfg.user_agent,
            proxy_url=proxy_url,
        )
        if ct_res.get("farm_ca_detected"):
            reasons.append(f"ct_farm_ca:{ct_res.get('latest_not_before')}")
        elif ct_res.get("recent_cert_issued"):
            reasons.append(f"ct_recent_cert:{ct_res.get('latest_not_before')}")

    # Signal 4: Directory claimedAt / registrationActive
    dir_state = fetch_directory_org_state(gs_id, cfg, proxy_url=proxy_url) if check_directory else None
    if dir_state:
        if dir_state.get("claimedAt"):
            reasons.append(f"directory_already_claimed:{dir_state['claimedAt']}")
        if dir_state.get("registrationActive") is False:
            reasons.append("regulator_registration_inactive")

    # Signal 5: Directory claimed twins + Rebrand footprint check
    twin_res = (
        check_directory_twins(row, cfg, proxy_url=proxy_url)
        if check_directory
        else {"checked": False, "status": "skipped", "claimed_twins": []}
    )
    for tw in twin_res.get("claimed_twins") or []:
        reasons.append(f"directory_claimed_twin:{tw['name']}({tw.get('website')})")

    reb_res = check_rebrand_signals(
        db,
        row,
        search_url_template=search_tpl,
        rebrand_phrases=cfg.probe.rebrand_phrases,
        check_web=do_web_rebrand,
        timeout_s=cfg.probe.timeout_s,
        user_agent=cfg.user_agent,
        proxy_url=proxy_url,
    )
    reasons.extend(reb_res["reasons"])

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
        "twin_check_status": twin_res.get("status"),
        "claimed_twins": twin_res.get("claimed_twins", []),
        "director_checked": reb_res.get("director_checked"),
        "rebrand_reasons": reb_res["reasons"],
        "rebrand_web_status": reb_res["web_status"],
    }
