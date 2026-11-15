"""SQLite persistence and lifecycle state machine for LMIC website domain claims."""
from __future__ import annotations

import datetime
import json
import os
from pathlib import Path
import sqlite3
from typing import Any

STAGES = (
    "discovered",
    "wayback_checked",
    "tainted_history",
    "domain_registered",
    "alibi_deployed",
    "aging",
    "claimed_goodstack",
    "approved_claude",
    "rejected",
)

COMMERCIAL_STOPWORDS = (
    " pty",
    "(pty)",
    "enterprise",
    "consulting",
    "boxing",
    "production",
    "limited liability",
    "s.a.r.l",
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
  id                INTEGER PRIMARY KEY,
  gs_id             TEXT UNIQUE NOT NULL,
  iso3              TEXT NOT NULL,
  country           TEXT NOT NULL,
  name              TEXT NOT NULL,
  registry_name     TEXT NOT NULL,
  registry_code     TEXT NOT NULL,
  registry_id       TEXT NOT NULL,
  website_url       TEXT NOT NULL,
  root_domain       TEXT NOT NULL,
  rdap_status       TEXT NOT NULL,
  confidence        TEXT NOT NULL,
  stage             TEXT NOT NULL DEFAULT 'discovered',
  score             INTEGER NOT NULL DEFAULT 0,
  wayback_snapshots INTEGER DEFAULT 0,
  wayback_first_ts  TEXT,
  wayback_last_ts   TEXT,
  director_name     TEXT,
  director_role     TEXT,
  director_email    TEXT,
  address           TEXT,
  mission           TEXT,
  registered_at     TEXT,
  alibi_deployed_at TEXT,
  claimed_at        TEXT,
  approved_at       TEXT,
  notes             TEXT,
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshot_meta (
  gs_id             TEXT PRIMARY KEY,
  snapshot_ts       TEXT,
  snapshot_url      TEXT,
  director_name     TEXT,
  other_names       TEXT,
  emails_on_page    TEXT,
  page_title        TEXT,
  meta_description  TEXT,
  mission_excerpt   TEXT,
  taint_verdict     TEXT DEFAULT 'clean',
  taint_reasons     TEXT DEFAULT '[]',
  fetched_at        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_snap_dom ON snapshot_meta(director_name);

CREATE TABLE IF NOT EXISTS events (
  id        INTEGER PRIMARY KEY,
  ts        TEXT NOT NULL,
  gs_id     TEXT NOT NULL,
  from_st   TEXT,
  to_st     TEXT,
  kind      TEXT NOT NULL,
  detail    TEXT
);

CREATE INDEX IF NOT EXISTS ix_targets_stage ON targets(stage);
CREATE INDEX IF NOT EXISTS ix_targets_score ON targets(score DESC);
CREATE INDEX IF NOT EXISTS ix_targets_dom   ON targets(root_domain);
CREATE INDEX IF NOT EXISTS ix_events_gs     ON events(gs_id, ts);
"""


def utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def compute_score(
    name: str,
    root_domain: str,
    confidence: str,
    registry_code: str,
    wayback_snapshots: int = 0,
) -> int:
    score = 0
    low_name = (name or "").lower()
    if any(tok in low_name for tok in COMMERCIAL_STOPWORDS):
        return 5
    if confidence == "strong":
        score += 45
    elif confidence == "medium":
        score += 20
    else:
        score += 5

    if root_domain.endswith(".org"):
        score += 25
    elif root_domain.endswith(".com"):
        score += 18
    elif root_domain.endswith(".net"):
        score += 12

    if any(k in low_name for k in ("foundation", "aid", "relief", "trust", "children", "women", "health", "education", "community", "development", "welfare", "care", "hope")):
        score += 15

    if registry_code and registry_code not in ("UNKNOWN", ""):
        score += 10

    if wayback_snapshots > 0:
        score += min(15, 5 + wayback_snapshots)

    return min(100, score)


def open_db(path: str | Path = "private/alpha_claims.sqlite") -> sqlite3.Connection:
    p = Path(path)
    if p.is_symlink():
        raise ValueError(f"Refusing symlink database path: {p}")
    p.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(p))
    try:
        os.chmod(str(p), 0o600)
    except OSError:
        pass
    db.executescript(SCHEMA)
    db.row_factory = sqlite3.Row
    cols = {r["name"] for r in db.execute("PRAGMA table_info(snapshot_meta)").fetchall()}
    if "taint_verdict" not in cols:
        db.execute("ALTER TABLE snapshot_meta ADD COLUMN taint_verdict TEXT DEFAULT 'clean'")
    if "taint_reasons" not in cols:
        db.execute("ALTER TABLE snapshot_meta ADD COLUMN taint_reasons TEXT DEFAULT '[]'")
    db.commit()
    return db


def record_event(
    db: sqlite3.Connection,
    gs_id: str,
    kind: str,
    detail: str = "",
    from_st: str | None = None,
    to_st: str | None = None,
) -> None:
    db.execute(
        "INSERT INTO events(ts, gs_id, from_st, to_st, kind, detail) VALUES(?,?,?,?,?,?)",
        (utcnow(), gs_id, from_st, to_st, kind, str(detail)[:2000]),
    )


def upsert_target(db: sqlite3.Connection, item: dict[str, Any]) -> bool:
    gs_id = item["id"]
    name = (item.get("name") or "").strip()
    rdom = (item.get("rdom") or item.get("root_domain") or item.get("domain") or "").lower().strip()
    if rdom.startswith("www."):
        rdom = rdom[4:]
    conf = item.get("conf") or item.get("confidence") or "medium"
    reg_code = item.get("regcode") or item.get("registry_code") or "REG"
    wb_snaps = int(item.get("wayback_snapshots") or 0)
    score = compute_score(name, rdom, conf, reg_code, wb_snaps)
    now = utcnow()

    existing = db.execute("SELECT id, stage, wayback_snapshots FROM targets WHERE gs_id=?", (gs_id,)).fetchone()
    if existing:
        snaps = max(wb_snaps, int(existing["wayback_snapshots"] or 0))
        new_score = compute_score(name, rdom, conf, reg_code, snaps)
        db.execute(
            """UPDATE targets
               SET iso3=?, country=?, name=?, registry_name=?, registry_code=?,
                   registry_id=?, website_url=?, root_domain=?, rdap_status=?,
                   confidence=?, score=?, updated_at=?
               WHERE gs_id=?""",
            (
                item.get("iso") or item.get("iso3") or "UNK",
                item.get("country") or "Unknown",
                name,
                item.get("reg") or item.get("registry_name") or "Official Registry",
                reg_code,
                str(item.get("registryId") or item.get("registry_id") or ""),
                item.get("website") or item.get("website_url") or f"https://{rdom}",
                rdom,
                item.get("rdap") or item.get("rdap_status") or "AVAILABLE(404)",
                conf,
                new_score,
                now,
                gs_id,
            ),
        )
        db.commit()
        return False

    director_email = item.get("director_email")
    director_name = item.get("director_name")
    director_role = item.get("director_role")
    mission = item.get("mission")
    address = item.get("address")

    db.execute(
        """INSERT INTO targets(
             gs_id, iso3, country, name, registry_name, registry_code, registry_id,
             website_url, root_domain, rdap_status, confidence, stage, score,
             wayback_snapshots, director_name, director_role, director_email,
             address, mission, created_at, updated_at
           ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            gs_id,
            item.get("iso") or item.get("iso3") or "UNK",
            item.get("country") or "Unknown",
            name,
            item.get("reg") or item.get("registry_name") or "Official Registry",
            reg_code,
            str(item.get("registryId") or item.get("registry_id") or ""),
            item.get("website") or item.get("website_url") or f"https://{rdom}",
            rdom,
            item.get("rdap") or item.get("rdap_status") or "AVAILABLE(404)",
            conf,
            "discovered",
            score,
            wb_snaps,
            director_name,
            director_role,
            director_email,
            address,
            mission,
            now,
            now,
        ),
    )
    record_event(db, gs_id, "imported", f"domain={rdom} score={score}", None, "discovered")
    db.commit()
    return True


def advance_stage(
    db: sqlite3.Connection,
    identifier: str,
    new_stage: str,
    notes: str | None = None,
    director_name: str | None = None,
    director_email: str | None = None,
) -> dict[str, Any]:
    if new_stage not in STAGES:
        raise ValueError(f"Unsupported stage: {new_stage}. Valid: {STAGES}")
    row = db.execute(
        "SELECT * FROM targets WHERE gs_id=? OR root_domain=?",
        (identifier, identifier.lower()),
    ).fetchone()
    if not row:
        raise KeyError(f"Target not found: {identifier}")

    old_stage = row["stage"]
    now = utcnow()
    ts_col = {
        "domain_registered": "registered_at",
        "alibi_deployed": "alibi_deployed_at",
        "claimed_goodstack": "claimed_at",
        "approved_claude": "approved_at",
    }.get(new_stage)

    updates = ["stage=?", "updated_at=?"]
    params: list[Any] = [new_stage, now]
    if ts_col:
        updates.append(f"{ts_col}=?")
        params.append(now)
    if notes is not None:
        updates.append("notes=?")
        params.append(notes)
    if director_name is not None:
        updates.append("director_name=?")
        params.append(director_name)
    if director_email is not None:
        updates.append("director_email=?")
        params.append(director_email)
    params.append(row["gs_id"])

    db.execute(f"UPDATE targets SET {', '.join(updates)} WHERE gs_id=?", params)
    record_event(db, row["gs_id"], "stage_transition", notes or "", old_stage, new_stage)
    db.commit()
    updated = db.execute("SELECT * FROM targets WHERE gs_id=?", (row["gs_id"],)).fetchone()
    return dict(updated)


def update_wayback(
    db: sqlite3.Connection,
    identifier: str,
    snapshots: int,
    first_ts: str | None,
    last_ts: str | None,
) -> dict[str, Any]:
    row = db.execute(
        "SELECT * FROM targets WHERE gs_id=? OR root_domain=?",
        (identifier, identifier.lower()),
    ).fetchone()
    if not row:
        raise KeyError(f"Target not found: {identifier}")
    new_score = compute_score(
        row["name"],
        row["root_domain"],
        row["confidence"],
        row["registry_code"],
        snapshots,
    )
    new_stage = "wayback_checked" if row["stage"] == "discovered" else row["stage"]
    now = utcnow()
    db.execute(
        """UPDATE targets
           SET wayback_snapshots=?, wayback_first_ts=?, wayback_last_ts=?,
               score=?, stage=?, updated_at=?
           WHERE gs_id=?""",
        (snapshots, first_ts, last_ts, new_score, new_stage, now, row["gs_id"]),
    )
    record_event(
        db,
        row["gs_id"],
        "wayback_checked",
        f"snapshots={snapshots} first={first_ts} last={last_ts}",
        row["stage"],
        new_stage,
    )
    db.commit()
    return dict(db.execute("SELECT * FROM targets WHERE gs_id=?", (row["gs_id"],)).fetchone())


def status_summary(db: sqlite3.Connection) -> dict[str, Any]:
    total = db.execute("SELECT COUNT(*) AS c FROM targets").fetchone()["c"]
    by_stage = {
        r["stage"]: r["c"]
        for r in db.execute("SELECT stage, COUNT(*) AS c FROM targets GROUP BY stage").fetchall()
    }
    by_iso = {
        r["iso3"]: r["c"]
        for r in db.execute("SELECT iso3, COUNT(*) AS c FROM targets GROUP BY iso3 ORDER BY c DESC").fetchall()
    }
    top = [
        dict(r)
        for r in db.execute(
            """SELECT gs_id, iso3, country, name, registry_code, registry_id,
                      root_domain, confidence, stage, score, wayback_snapshots
               FROM targets
               ORDER BY score DESC, id ASC
               LIMIT 10"""
        ).fetchall()
    ]
    return {
        "pipeline": "alpha_website_domain_claim",
        "total_targets": total,
        "by_stage": by_stage,
        "by_country": by_iso,
        "top_candidates": top,
    }


def save_snapshot_meta(db: sqlite3.Connection, gs_id: str, meta: dict[str, Any]) -> None:
    """Persist extracted Wayback snapshot metadata and auto-demote tainted targets."""
    now = utcnow()
    taint = meta.get("taint") or {}
    verdict = taint.get("verdict") or "clean"
    reasons = taint.get("reasons") or []
    db.execute(
        """INSERT INTO snapshot_meta(
             gs_id, snapshot_ts, snapshot_url, director_name, other_names,
             emails_on_page, page_title, meta_description, mission_excerpt,
             taint_verdict, taint_reasons, fetched_at
           ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(gs_id) DO UPDATE SET
             snapshot_ts=excluded.snapshot_ts,
             snapshot_url=excluded.snapshot_url,
             director_name=excluded.director_name,
             other_names=excluded.other_names,
             emails_on_page=excluded.emails_on_page,
             page_title=excluded.page_title,
             meta_description=excluded.meta_description,
             mission_excerpt=excluded.mission_excerpt,
             taint_verdict=excluded.taint_verdict,
             taint_reasons=excluded.taint_reasons,
             fetched_at=excluded.fetched_at""",
        (
            gs_id,
            meta.get("snapshot_ts"),
            meta.get("snapshot_url"),
            meta.get("director_name"),
            json.dumps(meta.get("other_names") or [], ensure_ascii=False),
            json.dumps(meta.get("emails_on_page") or [], ensure_ascii=False),
            meta.get("page_title"),
            meta.get("meta_description"),
            meta.get("mission_excerpt"),
            verdict,
            json.dumps(reasons, ensure_ascii=False),
            now,
        ),
    )
    if verdict != "clean":
        db.execute(
            "UPDATE targets SET stage='tainted_history', score=0, notes=?, updated_at=? WHERE gs_id=?",
            (f"taint:{verdict} {','.join(reasons)}", now, gs_id),
        )
        record_event(db, gs_id, "taint_flagged", f"verdict={verdict} reasons={reasons}", None, "tainted_history")
    else:
        record_event(db, gs_id, "snapshot_fetched", f"ts={meta.get('snapshot_ts')} director={meta.get('director_name')}")
    db.commit()


def get_snapshot_meta(db: sqlite3.Connection, identifier: str) -> dict[str, Any] | None:
    row = db.execute(
        """SELECT sm.* FROM snapshot_meta sm
           JOIN targets t ON t.gs_id = sm.gs_id
           WHERE t.gs_id=? OR t.root_domain=?""",
        (identifier, identifier.lower()),
    ).fetchone()
    return dict(row) if row else None
