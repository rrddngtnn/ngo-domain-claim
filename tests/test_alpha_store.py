from pathlib import Path
from ngo_domain_claim.core.store import (
    advance_stage,
    compute_score,
    open_db,
    status_summary,
    update_wayback,
    upsert_target,
)
from ngo_domain_claim.bridge.handoff import export_bridge_snapshot
from ngo_domain_claim.recon.wayback import parse_cdx_rows


def test_score_filters_commercial_entities():
    s_clean = compute_score("Star Kids International Foundation", "skifo.org", "strong", "LBR", 4)
    s_pty = compute_score("CONQUER FIRST AIDERS PTY", "culinarykidssouth.org", "strong", "ROCIP", 0)
    assert s_clean >= 90
    assert s_pty == 5


def test_lifecycle_and_bridge_export(tmp_path: Path):
    db = open_db(tmp_path / "alpha.sqlite")
    added = upsert_target(
        db,
        {
            "id": "organisation_test_01",
            "iso": "MWI",
            "country": "Malawi",
            "name": "Jallie Care Foundation",
            "reg": "NGORA",
            "regcode": "NGORA",
            "registryId": "NGO/L/23/020",
            "website": "https://jalliecare.org",
            "rdom": "jalliecare.org",
            "rdap": "AVAILABLE(404)",
            "conf": "strong",
        },
    )
    assert added is True

    cdx = parse_cdx_rows([
        ["timestamp", "original", "statuscode", "mimetype"],
        ["20210501120000", "https://jalliecare.org/", "200", "text/html"],
        ["20231110093000", "https://jalliecare.org/about", "200", "text/html"],
    ])
    row = update_wayback(db, "jalliecare.org", cdx["snapshots"], cdx["first_ts"], cdx["last_ts"])
    assert row["stage"] == "wayback_checked"
    assert row["wayback_snapshots"] == 2

    row2 = advance_stage(db, "jalliecare.org", "aging", notes="DNS + archive verified")
    assert row2["stage"] == "aging"

    out_json = tmp_path / "bridge.json"
    payload = export_bridge_snapshot(db, out_json)
    assert payload["schema"] == "ngo-recon-bridge/v1"
    assert payload["total"] == 1
    assert status_summary(db)["total_targets"] == 1
