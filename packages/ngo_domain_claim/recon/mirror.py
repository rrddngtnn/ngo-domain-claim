"""Wayback Clean-Dump Archiver: pull pre-taint archived HTML pages and strip Wayback wrappers."""
from __future__ import annotations

import gzip
import io
import json
from pathlib import Path
import re
from typing import Any
import urllib.parse
import urllib.request

from ngo_domain_claim.recon.taint import analyze_snapshot_taint

ARCHIVE_WEB = "https://web.archive.org/web/"

WB_TOOLBAR_RE = re.compile(
    r"<!-- BEGIN WAYBACK TOOLBAR INSERT -->.*?<!-- END WAYBACK TOOLBAR INSERT -->",
    re.I | re.S,
)
WB_SCRIPTS_RE = re.compile(
    r'<script[^>]+(?:web-static\.archive\.org|archive\.org/includes/|wombat\.js)[^>]*>.*?</script>',
    re.I | re.S,
)
WB_LINK_CSS_RE = re.compile(
    r'<link[^>]+web-static\.archive\.org[^>]*>',
    re.I,
)
WB_URL_REWRITE_RE = re.compile(
    r"""https?://web\.archive\.org/web/\d+(?:[a-z_]+)?/(https?://[^\s"'<>]+)""",
    re.I,
)


def clean_wayback_html(html: str, root_domain: str = "") -> str:
    """Strip Wayback Machine toolbar/scripts and restore original URLs and relative internal links."""
    cleaned = WB_TOOLBAR_RE.sub("", html)
    cleaned = WB_SCRIPTS_RE.sub("", cleaned)
    cleaned = WB_LINK_CSS_RE.sub("", cleaned)
    cleaned = WB_URL_REWRITE_RE.sub(r"\1", cleaned)
    if root_domain:
        dom_pat = re.compile(rf"""https?://(?:www\.)?{re.escape(root_domain)}(/[^\s"'<>]*)?""", re.I)
        cleaned = dom_pat.sub(lambda m: m.group(1) or "/", cleaned)
    return cleaned


def _http_get(url: str, timeout: int = 20, user_agent: str = "ngo-domain-claim/0.2") -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
        if resp.headers.get("Content-Encoding") == "gzip":
            data = gzip.GzipFile(fileobj=io.BytesIO(data)).read()
        return data


def _url_to_relpath(original_url: str) -> str:
    parsed = urllib.parse.urlparse(original_url)
    path = (parsed.path or "/").strip("/")
    if not path:
        return "index.html"
    safe = re.sub(r"[^A-Za-z0-9._/-]", "_", path)
    if safe.endswith((".html", ".htm")):
        return safe
    return f"{safe}/index.html"


def mirror_clean_wayback_site(
    domain: str,
    out_dir: str | Path,
    *,
    iso3: str = "UNK",
    before_ts: str | None = None,
    max_pages: int = 8,
    timeout: int = 20,
    user_agent: str = "ngo-domain-claim/0.2",
) -> dict[str, Any]:
    """Fetch up to max_pages clean HTML pages from Wayback Machine into out_dir."""
    dom = domain.lower().strip(".")
    q = urllib.parse.quote(f"{dom}/*")
    to_filter = f"&to={before_ts}" if before_ts else ""
    cdx_url = (
        f"https://web.archive.org/cdx/search/cdx?url={q}"
        "&output=json&fl=timestamp,original,statuscode,mimetype"
        f"&filter=statuscode:200&filter=mimetype:text/html&collapse=urlkey&limit=40{to_filter}"
    )
    raw = _http_get(cdx_url, timeout=timeout, user_agent=user_agent)
    rows = json.loads(raw.decode("utf-8", "ignore"))
    if not rows or len(rows) < 2:
        return {"domain": dom, "saved_pages": 0, "error": "no_cdx_snapshots"}

    header, data_rows = rows[0], rows[1:]
    ts_idx = header.index("timestamp")
    orig_idx = header.index("original")

    # Prioritize homepage + about/team/contact/program pages, newest clean first
    def _rank_key(r: list[str]) -> tuple[int, str]:
        p = (urllib.parse.urlparse(r[orig_idx]).path or "/").rstrip("/")
        if p == "":
            prio = 3
        elif re.search(r"about|team|staff|board|contact|mission|program|project|a-propos|equipe", p, re.I):
            prio = 2
        else:
            prio = 1
        return (prio, r[ts_idx])

    def _is_junk_url(u: str) -> bool:
        parsed = urllib.parse.urlparse(u)
        p = (parsed.path or "").lower()
        q = (parsed.query or "").lower()
        if "/.well-known/" in p or "/wp-json/" in p or "/feed" in p:
            return True
        if "give-embed=" in q or "replytocom=" in q:
            return True
        return False

    filtered_rows = [r for r in data_rows if not _is_junk_url(r[orig_idx])]
    ordered = sorted(filtered_rows, key=_rank_key, reverse=True)
    target_dir = Path(out_dir)
    if target_dir.is_symlink():
        raise ValueError(f"Refusing symlink mirror destination: {target_dir}")
    target_dir.mkdir(parents=True, exist_ok=True)

    saved: list[dict[str, Any]] = []
    skipped_tainted = 0
    seen_rel: set[str] = set()

    for row in ordered:
        if len(saved) >= max_pages:
            break
        ts, orig = row[ts_idx], row[orig_idx]
        rel = _url_to_relpath(orig)
        if rel in seen_rel:
            continue
        snap_url = f"{ARCHIVE_WEB}{ts}id_/{orig}"
        try:
            html_raw = _http_get(snap_url, timeout=timeout, user_agent=user_agent).decode("utf-8", "ignore")
        except Exception:
            continue

        taint = analyze_snapshot_taint(html_raw, html_raw, iso3=iso3, root_domain=dom)
        if taint["is_tainted"]:
            skipped_tainted += 1
            continue

        low_raw = html_raw.lower()
        if "wsidchk" in low_raw or "one moment, please" in low_raw or "just a moment..." in low_raw:
            skipped_tainted += 1
            continue
        if len(html_raw) < 3500:
            continue
        cleaned = clean_wayback_html(html_raw, root_domain=dom)
        dest_file = target_dir / rel
        dest_file.parent.mkdir(parents=True, exist_ok=True)
        dest_file.write_text(cleaned, encoding="utf-8")
        seen_rel.add(rel)
        saved.append({
            "rel_path": rel,
            "timestamp": ts,
            "original_url": orig,
            "bytes": len(cleaned.encode("utf-8")),
        })

    manifest = {
        "domain": dom,
        "iso3": iso3,
        "saved_pages": len(saved),
        "skipped_tainted": skipped_tainted,
        "out_dir": str(target_dir),
        "pages": saved,
    }
    (target_dir / "mirror_manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return manifest
