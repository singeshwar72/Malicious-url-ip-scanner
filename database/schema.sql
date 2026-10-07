-- schema.sql
-- SQLite schema for Malicious URL & IP Scanner
-- Auto-executed on first run via database.py

CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target          TEXT    NOT NULL,
    target_type     TEXT    NOT NULL,           -- URL | IPv4 | IPv6
    scan_time       TEXT    NOT NULL,           -- ISO-8601 timestamp
    risk_score      INTEGER NOT NULL DEFAULT 0,
    verdict         TEXT    NOT NULL,           -- SAFE | LOW RISK | SUSPICIOUS | HIGH RISK | MALICIOUS
    is_https        INTEGER NOT NULL DEFAULT 0, -- 1 = yes, 0 = no
    scheme          TEXT,
    domain          TEXT,
    ip_address      TEXT,
    port            INTEGER,
    country         TEXT,
    asn             TEXT,
    reverse_dns     TEXT,
    reputation_data TEXT,                       -- JSON blob from external APIs
    risk_reasons    TEXT    NOT NULL DEFAULT '[]', -- JSON array of reason strings
    technical_info  TEXT    NOT NULL DEFAULT '{}'  -- JSON object with parsed details
);

CREATE INDEX IF NOT EXISTS idx_scans_scan_time  ON scans(scan_time  DESC);
CREATE INDEX IF NOT EXISTS idx_scans_verdict    ON scans(verdict);
CREATE INDEX IF NOT EXISTS idx_scans_target     ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_type       ON scans(target_type);
