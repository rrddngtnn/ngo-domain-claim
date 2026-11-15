"""DNS liveliness probing via local resolver and optional DoH (A, MX, NS)."""
from __future__ import annotations

import json
import socket
import urllib.parse
import urllib.request
from typing import Any


def _doh_has_records(domain: str, rtype: str, doh_url: str, timeout_s: int, user_agent: str) -> bool | None:
    q = urllib.parse.urlencode({"name": domain, "type": rtype})
    url = f"{doh_url}?{q}"
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": user_agent})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            data = json.loads(resp.read().decode("utf-8", "ignore"))
        status = data.get("Status")
        answers = data.get("Answer") or []
        if answers:
            return True
        # Status 3 = NXDOMAIN, Status 0 with empty Answer = NODATA
        if status == 3:
            return False
        return False
    except Exception:
        return None


def probe_domain_dns(
    domain: str,
    *,
    enable_doh: bool = True,
    doh_url: str = "https://dns.google/resolve",
    timeout_s: int = 8,
    user_agent: str = "ngo-domain-claim/0.2",
    use_system_dns: bool = True,
) -> dict[str, Any]:
    """Check whether domain has live A/AAAA, MX, or NS records."""
    dom = domain.lower().strip(".")
    a_alive = False
    if use_system_dns:
        try:
            socket.getaddrinfo(dom, None)
            a_alive = True
        except socket.gaierror:
            a_alive = False
    if a_alive:
        return {"domain": dom, "alive": True, "reason": "system_a_aaaa"}

    if enable_doh and doh_url:
        for rtype in ("A", "MX", "NS"):
            res = _doh_has_records(dom, rtype, doh_url, timeout_s, user_agent)
            if res is True:
                return {"domain": dom, "alive": True, "reason": f"doh_{rtype.lower()}"}

    return {"domain": dom, "alive": False, "reason": "nxdomain_no_mx_ns"}
