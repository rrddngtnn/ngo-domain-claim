"""Layered configuration loader: CLI flags > Environment > TOML > Defaults."""
from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Any

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]


DEFAULT_SKIP_HOSTS = [
    "facebook.com",
    "instagram.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "tiktok.com",
    "youtube.com",
    "example.com",
    "example.org",
    "example.test",
    "webs.com",
    "blogspot.com",
    "wordpress.com",
    "sites.google.com",
    "linktr.ee",
    "wixsite.com",
]


@dataclass
class SourceConfig:
    kind: str = "json_file"
    base_url: str = ""
    auth_header: str = "Authorization"
    auth_prefix: str = ""
    token_env: str = "DIRECTORY_API_TOKEN"
    origin: str = ""
    referer: str = ""
    country_param: str = "countryCode"
    page_param: str = "page"
    page_size_param: str = "pageSize"
    page_size: int = 100
    max_pages: int = 3
    request_delay_s: float = 0.35
    countries: list[str] = field(default_factory=list)
    file_path: str = ""
    type_filter: str = "nonprofit"
    require_registry: bool = True
    require_unclaimed: bool = True
    field_map: dict[str, str] = field(default_factory=dict)


@dataclass
class ProbeConfig:
    doh_url: str = "https://dns.google/resolve"
    enable_doh: bool = True
    iana_bootstrap_url: str = "https://data.iana.org/rdap/dns.json"
    rdap_cache_path: str = "private/iana_rdap_dns.json"
    rdap_cache_ttl_s: int = 86400 * 7
    extra_rdap_servers: dict[str, str] = field(default_factory=dict)
    timeout_s: int = 10
    workers: int = 8
    skip_hosts: list[str] = field(default_factory=lambda: list(DEFAULT_SKIP_HOSTS))


@dataclass
class AlphaConfig:
    db_path: str = "private/alpha_claims.sqlite"
    bridge_out: str = "private/alpha_bridge.json"
    user_agent: str = "ngo-domain-claim/0.2 (public-registry-research)"
    source: SourceConfig = field(default_factory=SourceConfig)
    probe: ProbeConfig = field(default_factory=ProbeConfig)


def _load_toml(path: str | Path | None) -> dict[str, Any]:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {p}")
    return tomllib.loads(p.read_text(encoding="utf-8"))


def load_config(
    config_path: str | Path | None = None,
    cli_overrides: dict[str, Any] | None = None,
) -> AlphaConfig:
    cfg_file = config_path or os.environ.get("ALPHA_CONFIG")
    raw = _load_toml(cfg_file)
    cli = cli_overrides or {}

    core_sec = raw.get("core", {})
    src_sec = raw.get("source", {})
    prb_sec = raw.get("probe", {})

    db_path = (
        cli.get("db")
        or os.environ.get("ALPHA_RECON_DB")
        or core_sec.get("db_path")
        or "private/alpha_claims.sqlite"
    )
    bridge_out = (
        cli.get("bridge_out")
        or os.environ.get("ALPHA_BRIDGE_OUT")
        or core_sec.get("bridge_out")
        or "private/alpha_bridge.json"
    )
    user_agent = (
        os.environ.get("ALPHA_USER_AGENT")
        or core_sec.get("user_agent")
        or "ngo-domain-claim/0.2 (public-registry-research)"
    )

    countries_env = os.environ.get("ALPHA_COUNTRIES")
    countries = (
        cli.get("countries")
        or ([c.strip().upper() for c in countries_env.split(",") if c.strip()] if countries_env else None)
        or src_sec.get("countries")
        or []
    )

    src = SourceConfig(
        kind=cli.get("source_kind") or os.environ.get("ALPHA_SOURCE_KIND") or src_sec.get("kind", "json_file"),
        base_url=cli.get("base_url") or os.environ.get("DIRECTORY_BASE_URL") or src_sec.get("base_url", ""),
        auth_header=src_sec.get("auth_header", "Authorization"),
        auth_prefix=src_sec.get("auth_prefix", ""),
        token_env=src_sec.get("token_env", "DIRECTORY_API_TOKEN"),
        origin=os.environ.get("DIRECTORY_ORIGIN") or src_sec.get("origin", ""),
        referer=os.environ.get("DIRECTORY_REFERER") or src_sec.get("referer", ""),
        country_param=src_sec.get("country_param", "countryCode"),
        page_param=src_sec.get("page_param", "page"),
        page_size_param=src_sec.get("page_size_param", "pageSize"),
        page_size=int(cli.get("page_size") or src_sec.get("page_size", 100)),
        max_pages=int(cli.get("max_pages") or os.environ.get("ALPHA_MAX_PAGES") or src_sec.get("max_pages", 3)),
        request_delay_s=float(src_sec.get("request_delay_s", 0.35)),
        countries=list(countries),
        file_path=cli.get("file") or src_sec.get("file_path", ""),
        type_filter=src_sec.get("type_filter", "nonprofit"),
        require_registry=bool(src_sec.get("require_registry", True)),
        require_unclaimed=bool(src_sec.get("require_unclaimed", True)),
        field_map=dict(src_sec.get("field_map", {})),
    )

    prb = ProbeConfig(
        doh_url=os.environ.get("ALPHA_DOH_URL") or prb_sec.get("doh_url", "https://dns.google/resolve"),
        enable_doh=bool(cli.get("enable_doh") if cli.get("enable_doh") is not None else prb_sec.get("enable_doh", True)),
        iana_bootstrap_url=os.environ.get("ALPHA_RDAP_BOOTSTRAP_URL") or prb_sec.get("iana_bootstrap_url", "https://data.iana.org/rdap/dns.json"),
        rdap_cache_path=prb_sec.get("rdap_cache_path", "private/iana_rdap_dns.json"),
        rdap_cache_ttl_s=int(prb_sec.get("rdap_cache_ttl_s", 86400 * 7)),
        extra_rdap_servers=dict(prb_sec.get("extra_rdap_servers", {})),
        timeout_s=int(cli.get("timeout") or prb_sec.get("timeout_s", 10)),
        workers=int(cli.get("workers") or prb_sec.get("workers", 8)),
        skip_hosts=list(prb_sec.get("skip_hosts", DEFAULT_SKIP_HOSTS)),
    )

    return AlphaConfig(db_path=db_path, bridge_out=bridge_out, user_agent=user_agent, source=src, probe=prb)
