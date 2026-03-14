"""
ns_hunter/db.py — SQLite Schema & Helper Functions
"""
import sqlite3
import json
from datetime import datetime, date
from pathlib import Path
from typing import Optional


DB_PATH = Path(__file__).parent / "ns_hunter.db"


SCHEMA = """
-- ─────────────────────────────────────────────
--  QUERIES  (Shodan Search Definitions)
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS queries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    query       TEXT    NOT NULL,
    category    TEXT    NOT NULL DEFAULT 'generic',
    enabled     INTEGER NOT NULL DEFAULT 1,
    total_hits  INTEGER NOT NULL DEFAULT 0,
    last_run    TEXT,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ─────────────────────────────────────────────
--  HOSTS  (Jeden Tag gesammelte IPs)
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS hosts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip              TEXT    NOT NULL UNIQUE,
    first_seen      TEXT    NOT NULL,   -- ISO date YYYY-MM-DD
    last_seen       TEXT    NOT NULL,   -- ISO date YYYY-MM-DD
    status          TEXT    NOT NULL DEFAULT 'active',  -- active | dead
    asn             INTEGER,
    asn_name        TEXT,
    country_code    TEXT,
    country_name    TEXT,
    city            TEXT,
    org             TEXT,
    isp             TEXT,
    ssl_fingerprint TEXT,               -- SHA-256
    ssl_cn          TEXT,
    ssl_issuer_cn   TEXT,
    ssl_is_selfsig  INTEGER DEFAULT 0,
    ssl_expires     TEXT,
    http_server     TEXT,               -- z.B. "NetSupport Gateway/1.7"
    open_ports      TEXT,               -- JSON array
    hostnames       TEXT,               -- JSON array
    source_query    TEXT,               -- welche Query hat den Host gefunden
    source_name     TEXT,               -- Query-Name aus searches.yml
    is_suspicious   INTEGER DEFAULT 0,  -- liegt in bekanntem BPH-ASN
    notes           TEXT
);

-- ─────────────────────────────────────────────
--  DAILY SNAPSHOTS  (Tages-Diff)
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS daily_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_date    TEXT    NOT NULL,       -- YYYY-MM-DD
    ip          TEXT    NOT NULL,
    asn         INTEGER,
    asn_name    TEXT,
    country     TEXT,
    ssl_fp      TEXT,
    ssl_cn      TEXT,
    http_server TEXT,
    source_name TEXT,
    UNIQUE(run_date, ip)
);

-- ─────────────────────────────────────────────
--  CHANGE EVENTS  (new / dead / asn_changed / cert_changed)
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS change_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_date  TEXT    NOT NULL,       -- YYYY-MM-DD
    ip          TEXT    NOT NULL,
    event_type  TEXT    NOT NULL,       -- new | dead | asn_changed | cert_changed | reactivated
    old_value   TEXT,
    new_value   TEXT,
    detail      TEXT
);

-- ─────────────────────────────────────────────
--  ASN HISTORY  (pro IP: alle bekannten ASNs)
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS asn_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT    NOT NULL,
    asn         INTEGER,
    asn_name    TEXT,
    first_seen  TEXT    NOT NULL,
    last_seen   TEXT    NOT NULL,
    UNIQUE(ip, asn)
);

-- ─────────────────────────────────────────────
--  RUN LOG
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS run_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at          TEXT    NOT NULL,
    run_date        TEXT    NOT NULL,
    total_found     INTEGER DEFAULT 0,
    new_hosts       INTEGER DEFAULT 0,
    dead_hosts      INTEGER DEFAULT 0,
    asn_changes     INTEGER DEFAULT 0,
    cert_changes    INTEGER DEFAULT 0,
    queries_run     INTEGER DEFAULT 0,
    duration_sec    REAL    DEFAULT 0,
    errors          INTEGER DEFAULT 0
);

-- ─────────────────────────────────────────────
--  QUERY HITS  (tägliche Treffer pro Query)
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS query_hits (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_date    TEXT    NOT NULL,
    query_name  TEXT    NOT NULL,
    category    TEXT,
    hits        INTEGER NOT NULL DEFAULT 0,
    new_ips     INTEGER NOT NULL DEFAULT 0,   -- davon heute erstmals gesehen
    query_str   TEXT,
    UNIQUE(run_date, query_name)
);

-- ─────────────────────────────────────────────
--  VIEWS
-- ─────────────────────────────────────────────
CREATE VIEW IF NOT EXISTS v_active_hosts AS
    SELECT
        ip, first_seen, last_seen,
        asn, asn_name, country_code, country_name, city,
        ssl_cn, ssl_fingerprint, ssl_is_selfsig,
        http_server, open_ports, source_name, is_suspicious
    FROM hosts
    WHERE status = 'active'
    ORDER BY last_seen DESC;

CREATE VIEW IF NOT EXISTS v_today_new AS
    SELECT h.*
    FROM hosts h
    WHERE h.first_seen = date('now')
    AND   h.status = 'active';

CREATE VIEW IF NOT EXISTS v_asn_stats AS
    SELECT
        asn, asn_name, country_code,
        COUNT(*) AS host_count,
        SUM(is_suspicious) AS suspicious_count,
        MIN(first_seen) AS first_seen,
        MAX(last_seen) AS last_seen
    FROM hosts
    WHERE status = 'active'
    GROUP BY asn, asn_name
    ORDER BY host_count DESC;
"""


def get_conn(db_path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: Path = DB_PATH):
    """Erstellt Schema falls nicht vorhanden."""
    conn = get_conn(db_path)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def upsert_host(conn: sqlite3.Connection, host: dict, today: str) -> str:
    """
    Fügt einen Host ein oder aktualisiert ihn.
    Returns: 'new' | 'updated' | 'asn_changed' | 'cert_changed'
    """
    c = conn.cursor()
    c.execute("SELECT * FROM hosts WHERE ip = ?", (host["ip"],))
    existing = c.fetchone()

    event_type = "updated"

    if not existing:
        # Neuer Host
        c.execute("""
            INSERT INTO hosts (
                ip, first_seen, last_seen, status,
                asn, asn_name, country_code, country_name, city, org, isp,
                ssl_fingerprint, ssl_cn, ssl_issuer_cn, ssl_is_selfsig, ssl_expires,
                http_server, open_ports, hostnames,
                source_query, source_name, is_suspicious
            ) VALUES (
                :ip, :today, :today, 'active',
                :asn, :asn_name, :country_code, :country_name, :city, :org, :isp,
                :ssl_fp, :ssl_cn, :ssl_issuer_cn, :ssl_is_selfsig, :ssl_expires,
                :http_server, :open_ports, :hostnames,
                :source_query, :source_name, :is_suspicious
            )
        """, {**host, "today": today})
        event_type = "new"

        # ASN-History
        _upsert_asn_history(conn, host["ip"], host.get("asn"), host.get("asn_name"), today)

    else:
        # ASN-Wechsel erkennen
        if existing["asn"] and host.get("asn") and existing["asn"] != host["asn"]:
            event_type = "asn_changed"
            _log_change(conn, today, host["ip"], "asn_changed",
                        old_value=f"AS{existing['asn']} {existing['asn_name']}",
                        new_value=f"AS{host['asn']} {host.get('asn_name', '')}",
                        detail=f"SSL-CN: {host.get('ssl_cn', '')}")
            _upsert_asn_history(conn, host["ip"], host.get("asn"), host.get("asn_name"), today)

        # Zertifikat-Wechsel erkennen
        if existing["ssl_fingerprint"] and host.get("ssl_fp") and \
                existing["ssl_fingerprint"] != host["ssl_fp"]:
            if event_type != "asn_changed":
                event_type = "cert_changed"
            _log_change(conn, today, host["ip"], "cert_changed",
                        old_value=existing["ssl_fingerprint"][:32],
                        new_value=host["ssl_fp"][:32] if host.get("ssl_fp") else "",
                        detail=f"Old CN: {existing['ssl_cn']} → New CN: {host.get('ssl_cn', '')}")

        # Reaktivierung (war 'dead')
        if existing["status"] == "dead":
            event_type = "reactivated"
            _log_change(conn, today, host["ip"], "reactivated",
                        detail=f"Wieder aktiv auf AS{host.get('asn')} {host.get('asn_name', '')}")

        # Update
        c.execute("""
            UPDATE hosts SET
                last_seen = :today,
                status = 'active',
                asn = :asn, asn_name = :asn_name,
                country_code = :country_code, country_name = :country_name,
                city = :city, org = :org, isp = :isp,
                ssl_fingerprint = COALESCE(:ssl_fp, ssl_fingerprint),
                ssl_cn = COALESCE(:ssl_cn, ssl_cn),
                http_server = COALESCE(:http_server, http_server),
                open_ports = :open_ports,
                is_suspicious = :is_suspicious
            WHERE ip = :ip
        """, {**host, "today": today})

    return event_type


def mark_dead_hosts(conn: sqlite3.Connection, today: str, seen_ips: set) -> list:
    """
    Markiert Hosts als 'dead', die heute nicht mehr in den Ergebnissen auftauchen.
    Returns: Liste der neu als dead markierten IPs
    """
    c = conn.cursor()
    c.execute("""
        SELECT ip FROM hosts
        WHERE status = 'active' AND last_seen < ?
    """, (today,))

    dead = []
    for row in c.fetchall():
        ip = row["ip"]
        if ip not in seen_ips:
            c.execute("UPDATE hosts SET status = 'dead' WHERE ip = ?", (ip,))
            _log_change(conn, today, ip, "dead",
                        detail="Nicht mehr in Shodan-Ergebnissen gefunden")
            dead.append(ip)

    return dead


def add_daily_snapshot(conn: sqlite3.Connection, host: dict, run_date: str):
    c = conn.cursor()
    c.execute("""
        INSERT OR IGNORE INTO daily_snapshots
            (run_date, ip, asn, asn_name, country, ssl_fp, ssl_cn, http_server, source_name)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        run_date, host["ip"], host.get("asn"), host.get("asn_name"),
        host.get("country_code"), host.get("ssl_fp"), host.get("ssl_cn"),
        host.get("http_server"), host.get("source_name")
    ))


def _upsert_asn_history(conn, ip, asn, asn_name, today):
    if not asn:
        return
    conn.execute("""
        INSERT INTO asn_history (ip, asn, asn_name, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(ip, asn) DO UPDATE SET last_seen = excluded.last_seen
    """, (ip, asn, asn_name, today, today))


def _log_change(conn, event_date, ip, event_type,
                old_value=None, new_value=None, detail=None):
    conn.execute("""
        INSERT INTO change_events (event_date, ip, event_type, old_value, new_value, detail)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (event_date, ip, event_type, old_value, new_value, detail))


def log_run(conn, run_stats: dict):
    conn.execute("""
        INSERT INTO run_log
            (run_at, run_date, total_found, new_hosts, dead_hosts,
             asn_changes, cert_changes, queries_run, duration_sec, errors)
        VALUES (:run_at, :run_date, :total_found, :new_hosts, :dead_hosts,
                :asn_changes, :cert_changes, :queries_run, :duration_sec, :errors)
    """, run_stats)


def upsert_query(conn, name: str, query: str, category: str):
    conn.execute("""
        INSERT INTO queries (name, query, category)
        VALUES (?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET query = excluded.query, category = excluded.category
    """, (name, query, category))


def bump_query_hits(conn, name: str, hits: int, last_run: str):
    conn.execute("""
        UPDATE queries SET total_hits = total_hits + ?, last_run = ?
        WHERE name = ?
    """, (hits, last_run, name))

def log_query_hit(conn, run_date: str, query_name: str, category: str,
                  hits: int, new_ips: int, query_str: str):
    """Speichert tägliche Treffer pro Query für Performance-Tracking."""
    conn.execute("""
        INSERT INTO query_hits (run_date, query_name, category, hits, new_ips, query_str)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(run_date, query_name) DO UPDATE SET
            hits    = excluded.hits,
            new_ips = excluded.new_ips
    """, (run_date, query_name, category, hits, new_ips, query_str))

