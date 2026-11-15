from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import threading

from ngo_domain_claim.core.config import load_config
from ngo_domain_claim.core.store import open_db
from ngo_domain_claim.scanner.dns_probe import probe_domain_dns
from ngo_domain_claim.scanner.pipeline import run_scan
from ngo_domain_claim.scanner.rdap import RdapResolver


class _MockServerHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002
        return

    def do_GET(self):
        if self.path.startswith("/v1/organisations"):
            if self.headers.get("Authorization") != "test-token-123":
                self.send_response(401)
                self.end_headers()
                return
            body = json.dumps({
                "data": [
                    {
                        "id": "org_1",
                        "name": "Clean Water Hope Foundation",
                        "countryCode": "MWI",
                        "type": "nonprofit",
                        "registryDetails": {"code": "NGORA", "englishName": "NGORA"},
                        "registryId": "NGO/01",
                        "website": "https://cleanwater-dead.org",
                        "claimedAt": None,
                    },
                    {
                        "id": "org_2",
                        "name": "Taken Charity Trust",
                        "countryCode": "MWI",
                        "type": "nonprofit",
                        "registryDetails": {"code": "NGORA", "englishName": "NGORA"},
                        "registryId": "NGO/02",
                        "website": "https://taken-charity.org",
                        "claimedAt": None,
                    },
                    {
                        "id": "org_3",
                        "name": "Unsupported TLD Org",
                        "countryCode": "BDI",
                        "type": "nonprofit",
                        "registryDetails": {"code": "MOIPS", "englishName": "MOIPS"},
                        "registryId": "530/1",
                        "website": "https://orphan.bi",
                        "claimedAt": None,
                    },
                ]
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/iana/dns.json":
            port = self.server.server_port
            body = json.dumps({
                "services": [
                    [["org", "com"], [f"http://127.0.0.1:{port}/rdap/"]]
                ]
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/rdap/domain/cleanwater-dead.org":
            self.send_response(404)
            self.end_headers()
            return

        if self.path == "/rdap/domain/taken-charity.org":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ldhName":"taken-charity.org"}')
            return

        if self.path.startswith("/resolve"):
            if "name=taken-charity.org" in self.path:
                payload = {"Status": 0, "Answer": [{"name": "taken-charity.org", "type": 1, "data": "192.0.2.1"}]}
            else:
                payload = {"Status": 3}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(payload).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()


def _start_mock():
    srv = HTTPServer(("127.0.0.1", 0), _MockServerHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def test_config_precedence(tmp_path: Path, monkeypatch):
    toml_file = tmp_path / "alpha.toml"
    toml_file.write_text(
        """[core]
db_path = "from_toml.sqlite"
[source]
kind = "csv_file"
countries = ["MWI"]
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("ALPHA_RECON_DB", "from_env.sqlite")
    cfg = load_config(toml_file, cli_overrides={"db": "from_cli.sqlite", "countries": ["BDI"]})
    assert cfg.db_path == "from_cli.sqlite"
    assert cfg.source.kind == "csv_file"
    assert cfg.source.countries == ["BDI"]


def test_iana_rdap_bootstrap_and_unsupported_tld(tmp_path: Path):
    srv = _start_mock()
    try:
        base = f"http://127.0.0.1:{srv.server_port}"
        res = RdapResolver(
            bootstrap_url=f"{base}/iana/dns.json",
            cache_path=tmp_path / "iana.json",
        )
        r_avail = res.check_domain("cleanwater-dead.org")
        r_taken = res.check_domain("taken-charity.org")
        r_unsup = res.check_domain("orphan.bi")
        assert r_avail["status"] == "available" and r_avail["confidence"] == "strong"
        assert r_taken["status"] == "taken"
        assert r_unsup["status"] == "unsupported_tld" and r_unsup["available"] is False
    finally:
        srv.shutdown()


def test_end_to_end_scan_pipeline_offline(tmp_path: Path, monkeypatch):
    srv = _start_mock()
    try:
        base = f"http://127.0.0.1:{srv.server_port}"
        monkeypatch.setenv("MOCK_DIR_TOKEN", "test-token-123")
        cfg_file = tmp_path / "alpha.toml"
        cfg_file.write_text(
            f"""[core]
db_path = "{tmp_path / 'alpha.sqlite'}"
bridge_out = "{tmp_path / 'bridge.json'}"

[source]
kind = "rest_directory"
base_url = "{base}/v1/organisations"
token_env = "MOCK_DIR_TOKEN"
max_pages = 1
request_delay_s = 0.0
countries = ["MWI"]

[probe]
doh_url = "{base}/resolve"
enable_doh = true
iana_bootstrap_url = "{base}/iana/dns.json"
rdap_cache_path = "{tmp_path / 'iana.json'}"
""",
            encoding="utf-8",
        )
        cfg = load_config(cfg_file)
        db = open_db(cfg.db_path)
        dns_taken = probe_domain_dns("taken-charity.org", enable_doh=True, doh_url=cfg.probe.doh_url, use_system_dns=False)
        assert dns_taken["alive"] is True

        report = run_scan(cfg, db, use_system_dns=False)
        assert report["scanned_records"] == 3
        assert report["rdap_available"] == 1
        assert report["rdap_taken"] == 0
        assert report["rdap_unsupported_tld"] == 1
        assert report["added"] == 1
        assert report["hits"][0]["domain"] == "cleanwater-dead.org"
        row = db.execute("SELECT director_name FROM targets WHERE root_domain='cleanwater-dead.org'").fetchone()
        assert row["director_name"] is None
    finally:
        srv.shutdown()
