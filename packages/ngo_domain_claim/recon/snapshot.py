"""Fetch the latest archived HTML snapshot from web.archive.org and extract organization metadata."""
from __future__ import annotations

import gzip
import io
import re
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from typing import Any

ARCHIVE_PREFIX = "https://web.archive.org/web/"
FALLBACK_TS = "2024"

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

NAME_PATTERNS = [
    re.compile(r"(?:executive\s+director|founder(?:\s*&?\s*ceo)?|program(?:me)?\s+(?:director|manager)|chairman|chairperson|director)\s*[:\u2013-]?\s*([A-Z][A-Za-z.'\-]+(?:\s+[A-Z][A-Za-z.'\-]+){1,3})", re.I),
    re.compile(r"([A-Z][A-Za-z.'\-]+(?:\s+[A-Z][A-Za-z.'\-]+){1,3})\s*[,\u2013-]?\s*(?:executive\s+director|founder|program(?:me)?\s+director|chairman)", re.I),
]
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}")
URL_FQDN_RE = re.compile(r"https?://(?:web\.archive\.org)?/?(?:web/\d+(?:[a-z_]*)?/)?(?:[a-z]+://)?(?:www\.)?([a-z0-9.-]+\.[a-z]{2,24})", re.I)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
META_DESC_RE = re.compile(r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']', re.I | re.S)

def _strip_wayback_attrs(html: str) -> str:
    return html

def _http_get(url: str, timeout: int = 20) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (research)"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
        if resp.headers.get("Content-Encoding") == "gzip":
            data = gzip.GzipFile(fileobj=io.BytesIO(data)).read()
        return data

def fetch_latest_snapshot(domain: str, timeout: int = 20) -> dict[str, Any]:
    """Return {ts, url, html, text} for the newest 200 HTML capture, or {error}."""
    q = urllib.parse.quote(f"{domain}/*")
    cdx = (
        f"https://web.archive.org/cdx/search/cdx?url={q}"
        "&output=json&fl=timestamp,original,statuscode,mimetype"
        "&filter=statuscode:200&filter=mimetype:text/html&limit=-3"
    )
    try:
        req = urllib.request.Request(cdx, headers={"User-Agent": "Mozilla/5.0 (research)"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except Exception as exc:
        return {"error": f"cdx: {exc}"}
    try:
        rows = json_loads(raw)
    except Exception as exc:
        return {"error": f"cdx parse: {exc}"}
    if not rows or len(rows) < 2:
        return {"error": "no html snapshots"}
    header, data_rows = rows[0], rows[1:]
    ts_idx = header.index("timestamp")
    valid = [r for r in data_rows if len(r) > ts_idx and r[ts_idx]]
    if not valid:
        return {"error": "no html snapshots"}
    ts = sorted(r[ts_idx] for r in valid)[-1]
    snap_url = f"{ARCHIVE_PREFIX}{ts}/{domain}"
    try:
        html = _http_get(snap_url, timeout=timeout).decode("utf-8", "ignore")
    except Exception as exc:
        return {"error": f"snapshot: {exc}"}
    parser = _TextExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass
    return {"ts": ts, "url": snap_url, "html": html, "text": parser.text[:20000]}

def json_loads(raw: bytes):
    import json
    return json.loads(raw.decode("utf-8", "ignore"))

def extract_org_metadata(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Best-effort extraction of director names, emails, title, and mission-ish text."""
    html = snapshot.get("html") or ""
    text = snapshot.get("text") or ""
    if not html:
        return {}

    names: list[str] = []
    for pat in NAME_PATTERNS:
        for m in pat.finditer(text[:6000]):
            cand = " ".join(m.group(1).split())
            if 8 <= len(cand) <= 60 and not any(k in cand.lower() for k in ("foundation", "organization", "ministry")):
                if cand not in names:
                    names.append(cand)
        if len(names) >= 3:
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

    return {
        "snapshot_ts": snapshot.get("ts"),
        "snapshot_url": snapshot.get("url"),
        "director_name": names[0] if names else None,
        "other_names": names[1:4],
        "emails_on_page": emails,
        "page_title": title,
        "meta_description": desc,
        "mission_excerpt": mission,
    }
