"""Fetch archived HTML snapshots (homepage + about/team/contact subpages) from web.archive.org."""
from __future__ import annotations

import gzip
from html.parser import HTMLParser
import io
import json
import re
from typing import Any
import urllib.parse

from ngo_domain_claim.recon.taint import analyze_snapshot_taint
import urllib.request

ARCHIVE_PREFIX = "https://web.archive.org/web/"
SUBPAGE_HINTS = re.compile(r"/(?:about|about-us|team|staff|leadership|board|contact|a-propos|equipe)/?$", re.I)


class _TextExtractor(HTMLParser):
    _SKIP = {"script", "style", "noscript", "svg", "head"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._buf: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self._SKIP:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth == 0 and data.strip():
            self._buf.append(data.strip())

    @property
    def text(self) -> str:
        return " ".join(self._buf)


# Role keywords are case-insensitive; captured person name MUST be Proper-Cased!
_ROLE = r"(?i:executive\s+director|managing\s+director|founder(?:\s*&?\s*ceo)?|program(?:me)?\s+(?:director|manager)|board\s+chair|chairperson|chairman|president|ceo|director)"
_WORD = r"(?:[A-Z]\.|[A-Z][a-z.'\-]+(?:-[A-Z][a-z.'\-]+)?)"
_PERSON = rf"({_WORD}(?:\s+(?!Email\b|Phone\b|Tel\b){_WORD}){{1,3}})"

NAME_PATTERNS = [
    re.compile(rf"{_ROLE}\s*[:\u2013\-,]?\s*{_PERSON}"),
    re.compile(rf"{_PERSON}\s*[,\u2013\-]\s*{_ROLE}"),
]
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}")
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
META_DESC_RE = re.compile(r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']', re.I | re.S)


def _http_get(url: str, timeout: int = 20) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "ngo-domain-claim/0.2 (research)"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
        if resp.headers.get("Content-Encoding") == "gzip":
            data = gzip.GzipFile(fileobj=io.BytesIO(data)).read()
        return data


def _extract_text(html: str) -> str:
    parser = _TextExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass
    return parser.text[:25000]


def fetch_latest_snapshot(domain: str, timeout: int = 20, include_subpages: bool = True) -> dict[str, Any]:
    """Return latest 200 HTML capture plus optional about/team/contact subpage text."""
    q = urllib.parse.quote(f"{domain}/*")
    cdx = (
        f"https://web.archive.org/cdx/search/cdx?url={q}"
        "&output=json&fl=timestamp,original,statuscode,mimetype"
        "&filter=statuscode:200&filter=mimetype:text/html&collapse=urlkey&limit=30"
    )
    try:
        raw = _http_get(cdx, timeout=timeout)
        rows = json.loads(raw.decode("utf-8", "ignore"))
    except Exception as exc:
        return {"error": f"cdx: {exc}"}
    if not rows or len(rows) < 2:
        return {"error": "no html snapshots"}

    header = rows[0]
    ts_idx = header.index("timestamp")
    orig_idx = header.index("original")
    valid = [r for r in rows[1:] if len(r) > max(ts_idx, orig_idx) and r[ts_idx]]
    if not valid:
        return {"error": "no html snapshots"}

    # Prefer homepage or newest overall capture, plus up to 2 about/team subpages
    sorted_rows = sorted(valid, key=lambda r: r[ts_idx], reverse=True)
    primary = next((r for r in sorted_rows if r[orig_idx].rstrip("/").endswith(domain)), sorted_rows[0])
    ts = primary[ts_idx]
    snap_url = f"{ARCHIVE_PREFIX}{ts}id_/{primary[orig_idx]}"
    try:
        html = _http_get(snap_url, timeout=timeout).decode("utf-8", "ignore")
    except Exception as exc:
        return {"error": f"snapshot: {exc}"}

    combined_html = [html]
    combined_text = [_extract_text(html)]
    if include_subpages:
        sub_cands = [r for r in sorted_rows if r is not primary and SUBPAGE_HINTS.search(urllib.parse.urlparse(r[orig_idx]).path)]
        for sub in sub_cands[:2]:
            sub_url = f"{ARCHIVE_PREFIX}{sub[ts_idx]}id_/{sub[orig_idx]}"
            try:
                sub_html = _http_get(sub_url, timeout=timeout).decode("utf-8", "ignore")
                combined_html.append(sub_html)
                combined_text.append(_extract_text(sub_html))
            except Exception:
                continue

    return {
        "ts": ts,
        "url": snap_url,
        "html": "\n".join(combined_html),
        "text": "\n".join(combined_text)[:35000],
    }


def extract_org_metadata(snapshot: dict[str, Any], *, iso3: str = 'UNK', root_domain: str = '') -> dict[str, Any]:
    """Extract Proper-Cased director names, emails, title, and mission excerpt."""
    html = snapshot.get("html") or ""
    text = snapshot.get("text") or ""
    if not html:
        return {}

    names: list[str] = []
    stop = ("foundation", "organization", "ministry", "about", "privacy", "terms", "contact", "charity", "trust")
    for pat in NAME_PATTERNS:
        for m in pat.finditer(text[:15000]):
            cand = " ".join(m.group(1).split())
            if 6 <= len(cand) <= 55 and not any(k in cand.lower() for k in stop):
                if cand not in names:
                    names.append(cand)
        if len(names) >= 4:
            break

    emails = sorted(set(m.group(0).lower() for m in EMAIL_RE.finditer(html)))

    title_m = TITLE_RE.search(html)
    title = " ".join(title_m.group(1).split())[:200] if title_m else None
    desc_m = META_DESC_RE.search(html)
    desc = " ".join(desc_m.group(1).split())[:300] if desc_m else None

    mission = None
    miss_m = re.search(r"(?:about\s+us|our\s+mission|mission)\s*[:\u2013-]?\s*(.{40,400}?)(?:\.|\n\n)", text, re.I)
    if miss_m:
        mission = " ".join(miss_m.group(1).split())[:400]

    taint = analyze_snapshot_taint(
        html,
        text,
        iso3=iso3,
        root_domain=root_domain,
        page_title=title,
    )
    return {
        "snapshot_ts": snapshot.get("ts"),
        "snapshot_url": snapshot.get("url"),
        "director_name": names[0] if names else None,
        "other_names": names[1:4],
        "emails_on_page": emails,
        "page_title": title,
        "meta_description": desc,
        "mission_excerpt": mission,
        "taint": taint,
    }
