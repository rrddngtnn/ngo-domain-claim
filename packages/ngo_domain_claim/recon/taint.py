"""Deterministic snapshot taint, domain-parking, and script-hijack analyzer."""
from __future__ import annotations

import html as html_lib
import re
from typing import Any
import urllib.parse

CJK_COUNTRIES = {"CHN", "TWN", "HKG", "MAC", "JPN", "KOR", "SGP", "MYS"}
CYRILLIC_COUNTRIES = {"RUS", "UKR", "BLR", "KAZ", "KGZ", "TJK", "UZB", "MNG", "SRB", "BGR", "MKD"}

PARKING_SIGNATURES = (
    "sedoparking.com",
    "bodis.com",
    "dan.com/buy-domain",
    "afternic.com",
    "hugedomains.com",
    "this domain is for sale",
    "buy this domain",
    "domain parking",
    "parked free, courtesy of",
    "parkingcrew.net",
)

SPAM_KEYWORDS = (
    "slot88",
    "slot gacor",
    "situs judi",
    "judi online",
    "casino online",
    "poker online",
    "sbobet",
    "togel",
    "viagra",
    "cialis",
    "bc.game",
    "1xbet",
    "bet365",
)

HREF_RE = re.compile(r"""<a[^>]+href=['"](https?://[^'">\s]+)['"]""", re.I)


def _count_script_chars(text: str) -> tuple[int, int, int]:
    total_alpha = 0
    cjk = 0
    cyr = 0
    for ch in text:
        cp = ord(ch)
        if (
            0x4E00 <= cp <= 0x9FFF
            or 0x3400 <= cp <= 0x4DBF
            or 0x3040 <= cp <= 0x30FF
            or 0xAC00 <= cp <= 0xD7AF
        ):
            cjk += 1
            total_alpha += 1
        elif 0x0400 <= cp <= 0x04FF:
            cyr += 1
            total_alpha += 1
        elif ch.isalpha():
            total_alpha += 1
    return total_alpha, cjk, cyr


def analyze_snapshot_taint(
    html: str,
    text: str,
    *,
    iso3: str = "UNK",
    root_domain: str = "",
    page_title: str | None = None,
) -> dict[str, Any]:
    """Deterministically classify a snapshot as clean, parked, or tainted_spam."""
    decoded_html = html_lib.unescape(html or "")
    decoded_text = html_lib.unescape(text or "")
    decoded_title = html_lib.unescape(page_title or "")
    combined_sample = f"{decoded_title} {decoded_text[:15000]}"
    low_html = decoded_html.lower()
    low_sample = combined_sample.lower()

    reasons: list[str] = []

    # Rule 1: Explicit domain parking signatures
    for sig in PARKING_SIGNATURES:
        if sig in low_html or sig in low_sample:
            reasons.append(f"parking_signature:{sig}")

    # Rule 2: Explicit gambling / adult / pharma spam keywords
    for kw in SPAM_KEYWORDS:
        if kw in low_sample:
            reasons.append(f"spam_keyword:{kw}")

    # Rule 3: Foreign script hijack (e.g., CJK or Cyrillic on an African/Latin NGO domain)
    iso = (iso3 or "UNK").upper()
    total_alpha, cjk_count, cyr_count = _count_script_chars(combined_sample)
    cjk_ratio = round(cjk_count / total_alpha, 4) if total_alpha >= 10 else 0.0
    cyr_ratio = round(cyr_count / total_alpha, 4) if total_alpha >= 10 else 0.0

    # Also check title specifically (many hijacked pages have a short CJK title)
    title_alpha, title_cjk, title_cyr = _count_script_chars(decoded_title)
    if iso not in CJK_COUNTRIES and (cjk_ratio >= 0.15 or (title_alpha >= 4 and title_cjk >= 3)):
        reasons.append(f"cjk_script_hijack:ratio={cjk_ratio},title_cjk={title_cjk}")
    if iso not in CYRILLIC_COUNTRIES and (cyr_ratio >= 0.20 or (title_alpha >= 4 and title_cyr >= 3)):
        reasons.append(f"cyrillic_script_hijack:ratio={cyr_ratio},title_cyr={title_cyr}")

    # Rule 4: Outbound external domain stuffing (PBN / link farm)
    rdom = root_domain.lower().strip(".")
    ext_hosts: set[str] = set()
    for m in HREF_RE.finditer(decoded_html[:60000]):
        host = (urllib.parse.urlparse(m.group(1)).hostname or "").lower().strip(".")
        if host.startswith("www."):
            host = host[4:]
        if not host or host.endswith("archive.org"):
            continue
        if rdom and (host == rdom or host.endswith("." + rdom)):
            continue
        ext_hosts.add(host)

    if len(ext_hosts) >= 60:
        reasons.append(f"external_link_stuffing:unique_hosts={len(ext_hosts)}")

    if any(r.startswith("parking_signature:") for r in reasons):
        verdict = "domain_parked"
    elif reasons:
        verdict = "tainted_spam"
    else:
        verdict = "clean"

    return {
        "verdict": verdict,
        "is_tainted": verdict != "clean",
        "reasons": reasons,
        "metrics": {
            "total_alpha_chars": total_alpha,
            "cjk_ratio": cjk_ratio,
            "cyrillic_ratio": cyr_ratio,
            "unique_external_hosts": len(ext_hosts),
        },
    }
