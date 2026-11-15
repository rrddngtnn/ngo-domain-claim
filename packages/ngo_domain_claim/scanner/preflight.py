"""Pre-flight domain readiness check: live A, MX, SPF, DMARC, HTTPS, and About page presence."""
from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Any


def _doh_answers(name: str, rtype: str, doh_url: str, timeout_s: int, user_agent: str) -> list[str]:
    q = urllib.parse.urlencode({"name": name, "type": rtype})
    req = urllib.request.Request(f"{doh_url}?{q}", headers={"Accept": "application/dns-json", "User-Agent": user_agent})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            data = json.loads(resp.read().decode("utf-8", "ignore"))
        return [str(a.get("data", "")) for a in (data.get("Answer") or []) if a.get("data")]
    except Exception:
        return []


def _http_check(url: str, timeout_s: int, user_agent: str) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            body = resp.read(20000).decode("utf-8", "ignore")
        return {"ok": 200 <= resp.status < 400, "status": resp.status, "body": body}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "status": exc.code, "body": ""}
    except Exception as exc:
        return {"ok": False, "status": None, "error": str(exc), "body": ""}


def check_domain_preflight(
    domain: str,
    *,
    doh_url: str = "https://dns.google/resolve",
    base_scheme: str = "https",
    port: int | None = None,
    expected_email: str | None = None,
    expected_name: str | None = None,
    timeout_s: int = 8,
    user_agent: str = "ngo-domain-claim/0.2",
) -> dict[str, Any]:
    dom = domain.lower().strip(".")
    a_recs = _doh_answers(dom, "A", doh_url, timeout_s, user_agent)
    mx_recs = _doh_answers(dom, "MX", doh_url, timeout_s, user_agent)
    txt_recs = _doh_answers(dom, "TXT", doh_url, timeout_s, user_agent)
    dmarc_recs = _doh_answers(f"_dmarc.{dom}", "TXT", doh_url, timeout_s, user_agent)

    spf_ok = any("v=spf1" in t.lower() for t in txt_recs)
    dmarc_ok = any("v=dmarc1" in t.lower() for t in dmarc_recs)

    host_part = f"{dom}:{port}" if port else dom
    home = _http_check(f"{base_scheme}://{host_part}/", timeout_s, user_agent)
    about_hit = None
    for path in ("/about-us", "/about", "/about-us/", "/about/"):
        probe = _http_check(f"{base_scheme}://{host_part}{path}", timeout_s, user_agent)
        if probe["ok"]:
            about_hit = {"path": path, **probe}
            break

    combined_html = (home.get("body", "") + "\n" + (about_hit.get("body", "") if about_hit else "")).lower()
    email_found = bool(expected_email and expected_email.lower() in combined_html)
    name_found = bool(expected_name and expected_name.lower() in combined_html)

    checks = {
        "dns_a_live": bool(a_recs),
        "dns_mx_live": bool(mx_recs),
        "spf_present": spf_ok,
        "dmarc_present": dmarc_ok,
        "web_home_ok": bool(home["ok"]),
        "web_about_ok": bool(about_hit and about_hit["ok"]),
    }
    if expected_email:
        checks["email_on_site"] = email_found
    if expected_name:
        checks["director_on_site"] = name_found

    return {
        "domain": dom,
        "ready": all(checks.values()),
        "checks": checks,
        "records": {"a": a_recs, "mx": mx_recs, "spf_txt": [t for t in txt_recs if "spf" in t.lower()], "dmarc": dmarc_recs},
        "about_path": about_hit["path"] if about_hit else None,
    }
