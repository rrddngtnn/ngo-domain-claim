"""Wayback Machine CDX API snapshot counter and metadata parser."""
from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Any


def parse_cdx_rows(rows: list[list[str]]) -> dict[str, Any]:
    """Parse CDX JSON array rows (header + data rows) into summary metrics."""
    if not rows or len(rows) <= 1:
        return {"snapshots": 0, "first_ts": None, "last_ts": None}
    header = rows[0]
    ts_idx = header.index("timestamp") if "timestamp" in header else 1
    timestamps = sorted(r[ts_idx] for r in rows[1:] if len(r) > ts_idx and r[ts_idx])
    if not timestamps:
        return {"snapshots": 0, "first_ts": None, "last_ts": None}
    return {
        "snapshots": len(timestamps),
        "first_ts": timestamps[0],
        "last_ts": timestamps[-1],
    }


def fetch_cdx_summary(domain: str, timeout: int = 10) -> dict[str, Any]:
    """Query web.archive.org CDX API for historical 200-status HTML snapshots."""
    q = urllib.parse.quote(f"{domain}/*")
    url = (
        f"https://web.archive.org/cdx/search/cdx?url={q}"
        "&output=json&fl=timestamp,original,statuscode,mimetype"
        "&filter=statuscode:200&collapse=timestamp:6&limit=100"
    )
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            rows = json.loads(resp.read().decode("utf-8", "ignore"))
            return parse_cdx_rows(rows)
    except Exception as exc:
        return {"snapshots": 0, "first_ts": None, "last_ts": None, "error": str(exc)}
