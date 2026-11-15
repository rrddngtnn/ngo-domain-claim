"""Pluggable directory source adapters with entry-point extensibility."""
from __future__ import annotations

import csv
from importlib import metadata
import json
import os
from pathlib import Path
import time
from typing import Any, Iterator, Protocol
import urllib.error
import urllib.parse
import urllib.request

from ngo_domain_claim.core.config import SourceConfig


class DirectorySource(Protocol):
    def iter_records(self) -> Iterator[dict[str, Any]]: ...


def _extract_nested(row: dict[str, Any], path: str) -> Any:
    cur: Any = row
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def normalize_record(row: dict[str, Any], field_map: dict[str, str] | None = None) -> dict[str, Any]:
    fmap = field_map or {}

    def pick(canonical: str, *fallbacks: str) -> Any:
        if canonical in fmap:
            val = _extract_nested(row, fmap[canonical])
            if val is not None:
                return val
        for key in (canonical, *fallbacks):
            val = _extract_nested(row, key) if "." in key else row.get(key)
            if val is not None:
                return val
        return None

    reg_details = pick("registryDetails", "registry_details")
    reg_name = pick("registry_name", "reg", "registryDetails.englishName", "registryDetails.name")
    reg_code = pick("registry_code", "regcode", "registryDetails.code")

    return {
        "id": str(pick("id", "gs_id") or ""),
        "iso": str(pick("iso3", "iso", "countryCode") or "UNK").upper(),
        "country": str(pick("country") or pick("iso3", "iso", "countryCode") or "Unknown"),
        "name": str(pick("name", "displayName") or "").strip(),
        "type": str(pick("type") or "nonprofit").lower(),
        "reg": str(reg_name or "Official Registry"),
        "regcode": str(reg_code or ("NONE" if reg_details is None else "REG")),
        "has_registry": bool(reg_details) or bool(reg_name and reg_code),
        "registryId": str(pick("registryId", "registry_id") or ""),
        "website": str(pick("website", "website_url") or "").strip(),
        "claimedAt": pick("claimedAt", "claimed_at"),
    }


class RestDirectorySource:
    """Paginated REST JSON directory adapter configured completely via SourceConfig."""

    def __init__(self, cfg: SourceConfig, user_agent: str = "ngo-domain-claim/0.2") -> None:
        self.cfg = cfg
        self.user_agent = user_agent

    def _headers(self) -> dict[str, str]:
        hdrs = {"User-Agent": self.user_agent, "Accept": "application/json"}
        token = os.environ.get(self.cfg.token_env, "").strip()
        if token:
            val = f"{self.cfg.auth_prefix}{token}" if self.cfg.auth_prefix else token
            hdrs[self.cfg.auth_header] = val
        if self.cfg.origin:
            hdrs["Origin"] = self.cfg.origin
        if self.cfg.referer:
            hdrs["Referer"] = self.cfg.referer
        return hdrs

    def _fetch_page(self, country: str, page: int) -> list[dict[str, Any]]:
        params: dict[str, Any] = {
            self.cfg.page_param: page,
            self.cfg.page_size_param: self.cfg.page_size,
        }
        if country:
            params[self.cfg.country_param] = country
        sep = "&" if "?" in self.cfg.base_url else "?"
        url = f"{self.cfg.base_url}{sep}{urllib.parse.urlencode(params)}"

        for attempt in range(4):
            req = urllib.request.Request(url, headers=self._headers())
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    payload = json.loads(resp.read().decode("utf-8", "ignore"))
                if isinstance(payload, list):
                    return payload
                return list(payload.get("data") or payload.get("results") or [])
            except urllib.error.HTTPError as exc:
                if exc.code == 429 and attempt < 3:
                    retry_after = exc.headers.get("Retry-After")
                    wait_s = float(retry_after) if retry_after and retry_after.isdigit() else (2 ** attempt) * 1.5
                    time.sleep(min(wait_s, 15.0))
                    continue
                raise

        return []

    def iter_records(self) -> Iterator[dict[str, Any]]:
        if not self.cfg.base_url:
            raise ValueError("source.base_url is required for rest_directory source")
        targets = self.cfg.countries or [""]
        for cc in targets:
            for page in range(1, self.cfg.max_pages + 1):
                rows = self._fetch_page(cc, page)
                if not rows:
                    break
                for row in rows:
                    norm = normalize_record(row, self.cfg.field_map)
                    if not norm.get("country") or norm["country"] == "Unknown":
                        norm["country"] = cc or "Unknown"
                    yield norm
                if len(rows) < self.cfg.page_size:
                    break
                if self.cfg.request_delay_s > 0:
                    time.sleep(self.cfg.request_delay_s)


class JsonFileSource:
    def __init__(self, cfg: SourceConfig) -> None:
        self.cfg = cfg

    def iter_records(self) -> Iterator[dict[str, Any]]:
        if not self.cfg.file_path:
            raise ValueError("source.file_path is required for json_file source")
        items = json.loads(Path(self.cfg.file_path).read_text(encoding="utf-8"))
        for row in items:
            yield normalize_record(row, self.cfg.field_map)


class CsvFileSource:
    def __init__(self, cfg: SourceConfig) -> None:
        self.cfg = cfg

    def iter_records(self) -> Iterator[dict[str, Any]]:
        if not self.cfg.file_path:
            raise ValueError("source.file_path is required for csv_file source")
        with Path(self.cfg.file_path).open("r", encoding="utf-8-sig", newline="") as fh:
            for row in csv.DictReader(fh):
                yield normalize_record(dict(row), self.cfg.field_map)


def build_source(cfg: SourceConfig, user_agent: str = "ngo-domain-claim/0.2") -> DirectorySource:
    eps = {ep.name: ep for ep in metadata.entry_points(group="ngo_domain_claim.sources")}
    if cfg.kind in eps:
        factory = eps[cfg.kind].load()
        return factory(cfg, user_agent=user_agent)
    if cfg.kind == "rest_directory":
        return RestDirectorySource(cfg, user_agent=user_agent)
    if cfg.kind == "json_file":
        return JsonFileSource(cfg)
    if cfg.kind == "csv_file":
        return CsvFileSource(cfg)
    raise ValueError(f"Unsupported source kind: {cfg.kind}")
