"""
database/database.py
~~~~~~~~~~~~~~~~~~~~
SQLite database helper for the scanner application.

All queries use parameterised statements – never string-formatted SQL.
"""

import sqlite3
import json
import logging
import os
from pathlib import Path
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

# Resolve schema path relative to this file
SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def get_db_path() -> str:
    """Return database path from config (imported lazily to avoid circular imports)."""
    from config import Config
    return Config.DATABASE_PATH


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Open and return a SQLite connection with row_factory set."""
    path = db_path or get_db_path()
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """Create tables from schema.sql if they do not exist."""
    path = db_path or get_db_path()
    logger.info("Initialising database at: %s", path)
    schema_sql = SCHEMA_PATH.read_text(encoding="utf-8")
    with get_connection(path) as conn:
        conn.executescript(schema_sql)
    logger.info("Database ready.")


# ------------------------------------------------------------------ #
# Scan CRUD helpers
# ------------------------------------------------------------------ #

def save_scan(scan_data: Dict[str, Any], db_path: Optional[str] = None) -> int:
    """
    Insert a scan record and return its new id.

    scan_data keys (all optional except required ones):
        target, target_type, scan_time, risk_score, verdict,
        is_https, scheme, domain, ip_address, port, country, asn,
        reverse_dns, reputation_data, risk_reasons, technical_info
    """
    sql = """
        INSERT INTO scans (
            target, target_type, scan_time, risk_score, verdict,
            is_https, scheme, domain, ip_address, port,
            country, asn, reverse_dns,
            reputation_data, risk_reasons, technical_info
        ) VALUES (
            :target, :target_type, :scan_time, :risk_score, :verdict,
            :is_https, :scheme, :domain, :ip_address, :port,
            :country, :asn, :reverse_dns,
            :reputation_data, :risk_reasons, :technical_info
        )
    """
    # Serialise list/dict fields to JSON strings
    record = dict(scan_data)
    for field in ("risk_reasons", "technical_info", "reputation_data"):
        val = record.get(field)
        if val is not None and not isinstance(val, str):
            record[field] = json.dumps(val, ensure_ascii=False)
        elif val is None:
            record[field] = "[]" if field == "risk_reasons" else "{}"

    # Defaults for optional fields
    defaults = {
        "is_https": 0, "scheme": None, "domain": None,
        "ip_address": None, "port": None, "country": None,
        "asn": None, "reverse_dns": None, "reputation_data": "{}",
    }
    for k, v in defaults.items():
        record.setdefault(k, v)

    with get_connection(db_path) as conn:
        cursor = conn.execute(sql, record)
        return cursor.lastrowid


def get_scan_by_id(scan_id: int, db_path: Optional[str] = None) -> Optional[Dict]:
    """Return a single scan record as a dict, or None if not found."""
    sql = "SELECT * FROM scans WHERE id = ?"
    with get_connection(db_path) as conn:
        row = conn.execute(sql, (scan_id,)).fetchone()
    return _row_to_dict(row) if row else None


def get_scans(
    limit: int = 50,
    offset: int = 0,
    search: str = "",
    target_type: str = "",
    verdict: str = "",
    db_path: Optional[str] = None,
) -> List[Dict]:
    """Return a paginated, filtered list of scans ordered by scan_time desc."""
    conditions: List[str] = []
    params: List[Any] = []

    if search:
        conditions.append("target LIKE ?")
        params.append(f"%{search}%")
    if target_type:
        conditions.append("target_type = ?")
        params.append(target_type)
    if verdict:
        conditions.append("verdict = ?")
        params.append(verdict)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    sql = f"SELECT * FROM scans {where} ORDER BY scan_time DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with get_connection(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_row_to_dict(r) for r in rows]


def count_scans(
    search: str = "",
    target_type: str = "",
    verdict: str = "",
    db_path: Optional[str] = None,
) -> int:
    """Return total count matching filters (for pagination)."""
    conditions: List[str] = []
    params: List[Any] = []

    if search:
        conditions.append("target LIKE ?")
        params.append(f"%{search}%")
    if target_type:
        conditions.append("target_type = ?")
        params.append(target_type)
    if verdict:
        conditions.append("verdict = ?")
        params.append(verdict)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    sql = f"SELECT COUNT(*) FROM scans {where}"

    with get_connection(db_path) as conn:
        result = conn.execute(sql, params).fetchone()
    return result[0] if result else 0


def delete_scan(scan_id: int, db_path: Optional[str] = None) -> bool:
    """Delete a scan by id. Returns True if a row was deleted."""
    with get_connection(db_path) as conn:
        cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return cursor.rowcount > 0


def clear_all_scans(db_path: Optional[str] = None) -> int:
    """Delete all scan records. Returns number of rows deleted."""
    with get_connection(db_path) as conn:
        cursor = conn.execute("DELETE FROM scans")
        return cursor.rowcount


def get_dashboard_stats(db_path: Optional[str] = None) -> Dict[str, Any]:
    """Return aggregated statistics for the dashboard."""
    sql_totals = """
        SELECT
            COUNT(*)                                                        AS total,
            COALESCE(SUM(CASE WHEN verdict = 'SAFE'       THEN 1 ELSE 0 END), 0) AS safe_count,
            COALESCE(SUM(CASE WHEN verdict = 'LOW RISK'   THEN 1 ELSE 0 END), 0) AS low_risk_count,
            COALESCE(SUM(CASE WHEN verdict = 'SUSPICIOUS' THEN 1 ELSE 0 END), 0) AS suspicious_count,
            COALESCE(SUM(CASE WHEN verdict = 'HIGH RISK'  THEN 1 ELSE 0 END), 0) AS high_risk_count,
            COALESCE(SUM(CASE WHEN verdict = 'MALICIOUS'  THEN 1 ELSE 0 END), 0) AS malicious_count,
            COALESCE(SUM(CASE WHEN target_type = 'URL'    THEN 1 ELSE 0 END), 0) AS url_count,
            COALESCE(SUM(CASE WHEN target_type = 'IPv4'   THEN 1 ELSE 0 END), 0) AS ipv4_count,
            COALESCE(SUM(CASE WHEN target_type = 'IPv6'   THEN 1 ELSE 0 END), 0) AS ipv6_count
        FROM scans
    """
    # Daily scan counts for the last 30 days
    sql_daily = """
        SELECT DATE(scan_time) AS day, COUNT(*) AS cnt
        FROM scans
        WHERE scan_time >= DATE('now', '-30 days')
        GROUP BY day
        ORDER BY day ASC
    """
    with get_connection(db_path) as conn:
        totals = dict(conn.execute(sql_totals).fetchone())
        daily_rows = conn.execute(sql_daily).fetchall()

    daily = [{"day": r["day"], "count": r["cnt"]} for r in daily_rows]
    totals["daily_scans"] = daily
    return totals


def get_recent_scans(limit: int = 10, db_path: Optional[str] = None) -> List[Dict]:
    """Return the most recent `limit` scans."""
    sql = "SELECT * FROM scans ORDER BY scan_time DESC LIMIT ?"
    with get_connection(db_path) as conn:
        rows = conn.execute(sql, (limit,)).fetchall()
    return [_row_to_dict(r) for r in rows]


# ------------------------------------------------------------------ #
# Internal helpers
# ------------------------------------------------------------------ #

def _row_to_dict(row: sqlite3.Row) -> Dict:
    """Convert a sqlite3.Row to a plain dict, deserialising JSON fields."""
    d = dict(row)
    for field in ("risk_reasons", "technical_info", "reputation_data"):
        raw = d.get(field)
        if isinstance(raw, str):
            try:
                d[field] = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                d[field] = [] if field == "risk_reasons" else {}
    return d
