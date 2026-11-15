"""Authoritative IANA RDAP Bootstrap resolver and availability verifier."""
from __future__ import annotations

import json
from pathlib import Path
import time
import urllib.error
import urllib.request
from typing import Any

HIGH_CONFIDENCE_TLDS = {"com", "net", "org", "info", "biz", "uk", "nl", "au", "ca", "fr", "de"}


class RdapResolver:
    def __init__(
        self,
        *,
        bootstrap_url: str = "https://data.iana.org/rdap/dns.json",
        cache_path: str | Path = "private/iana_rdap_dns.json",
        cache_ttl_s: int = 86400 * 7,
        extra_servers: dict[str, str] | None = None,
        timeout_s: int = 10,
        user_agent: str = "ngo-domain-claim/0.2",
    ) -> None:
        self.bootstrap_url = bootstrap_url
        self.cache_path = Path(cache_path)
        self.cache_ttl_s = cache_ttl_s
        self.extra_servers = {k.lower().lstrip("."): v.rstrip("/") + "/" for k, v in (extra_servers or {}).items()}
        self.timeout_s = timeout_s
        self.user_agent = user_agent
        self._tld_map: dict[str, str] | None = None

    @staticmethod
    def parse_bootstrap(payload: dict[str, Any]) -> dict[str, str]:
        mapping: dict[str, str] = {}
        for entry in payload.get("services", []):
            if not isinstance(entry, list) or len(entry) < 2:
                continue
            tlds, urls = entry[0], entry[1]
            if not urls:
                continue
            base = str(urls[0]).rstrip("/") + "/"
            for tld in tlds:
                mapping[str(tld).lower().lstrip(".")] = base
        return mapping

    def _load_map(self) -> dict[str, str]:
        if self._tld_map is not None:
            return self._tld_map

        if self.cache_path.exists():
            age = time.time() - self.cache_path.stat().st_mtime
            if age <= self.cache_ttl_s:
                try:
                    raw = json.loads(self.cache_path.read_text(encoding="utf-8"))
                    self._tld_map = self.parse_bootstrap(raw)
                    return self._tld_map
                except Exception:
                    pass

        req = urllib.request.Request(self.bootstrap_url, headers={"User-Agent": self.user_agent})
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
            raw_bytes = resp.read()
        raw = json.loads(raw_bytes.decode("utf-8", "ignore"))
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_bytes(raw_bytes)
        self._tld_map = self.parse_bootstrap(raw)
        return self._tld_map

    def server_for_domain(self, domain: str) -> tuple[str | None, str]:
        dom = domain.lower().strip(".")
        if "." not in dom:
            return None, ""
        tld = dom.rsplit(".", 1)[-1]
        if tld in self.extra_servers:
            return self.extra_servers[tld], tld
        tld_map = self._load_map()
        return tld_map.get(tld), tld

    def check_domain(self, domain: str) -> dict[str, Any]:
        dom = domain.lower().strip(".")
        server, tld = self.server_for_domain(dom)
        if not server:
            return {
                "domain": dom,
                "tld": tld,
                "status": "unsupported_tld",
                "available": False,
                "confidence": "unsupported",
                "rdap_server": None,
                "label": "UNSUPPORTED_TLD",
            }

        query_url = f"{server}domain/{dom}"
        req = urllib.request.Request(query_url, headers={"User-Agent": self.user_agent, "Accept": "application/rdap+json, application/json"})
        conf = "strong" if tld in HIGH_CONFIDENCE_TLDS else "medium"
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                return {
                    "domain": dom,
                    "tld": tld,
                    "status": "taken",
                    "available": False,
                    "confidence": conf,
                    "rdap_server": server,
                    "http_status": resp.status,
                    "label": f"TAKEN({resp.status})",
                }
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return {
                    "domain": dom,
                    "tld": tld,
                    "status": "available",
                    "available": True,
                    "confidence": conf,
                    "rdap_server": server,
                    "http_status": 404,
                    "label": "AVAILABLE(404)",
                }
            return {
                "domain": dom,
                "tld": tld,
                "status": "error",
                "available": False,
                "confidence": "unknown",
                "rdap_server": server,
                "http_status": exc.code,
                "label": f"ERR({exc.code})",
            }
        except Exception as exc:
            return {
                "domain": dom,
                "tld": tld,
                "status": "error",
                "available": False,
                "confidence": "unknown",
                "rdap_server": server,
                "error": str(exc),
                "label": "ERR(NET)",
            }
