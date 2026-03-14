"""
ns_hunter/export_json.py — Exportiert ns_hunter.db → JSON-Dateien für GitHub

Erzeugt:
  exports/latest.json              → aktueller Snapshot (Dashboard liest das)
  exports/history/YYYY-MM-DD.json  → tägliches Archiv für historische Daten
  exports/index.json               → Liste aller verfügbaren Snapshots

Workflow:
  python export_json.py
  git add exports/ && git commit -m "update $(date +%F)" && git push

Cron (täglich nach ns_hunter.py):
  0 4 * * * cd /opt/ns_hunter && python ns_hunter.py && python export_json.py && git add exports/ && git commit -m "update" && git push
"""
import json
import sqlite3
from datetime import date, datetime, timezone
from pathlib import Path

DB_PATH     = Path(__file__).parent / "ns_hunter.db"
EXPORTS_DIR = Path(__file__).parent / "exports"
HISTORY_DIR = EXPORTS_DIR / "history"


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def q(conn, sql, params=()):
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def q1(conn, sql, params=()):
    row = conn.execute(sql, params).fetchone()
    return dict(row) if row else {}


def build_export(conn) -> dict:
    today = date.today().isoformat()

    overview = {
        "active":       q1(conn, "SELECT COUNT(*) AS n FROM hosts WHERE status='active'")["n"],
        "dead_total":   q1(conn, "SELECT COUNT(*) AS n FROM hosts WHERE status='dead'")["n"],
        "new_today":    q1(conn, "SELECT COUNT(*) AS n FROM hosts WHERE first_seen=? AND status='active'", (today,))["n"],
        "dead_today":   q1(conn, "SELECT COUNT(*) AS n FROM change_events WHERE event_date=? AND event_type='dead'", (today,))["n"],
        "suspicious":   q1(conn, "SELECT COUNT(*) AS n FROM hosts WHERE is_suspicious=1 AND status='active'")["n"],
        "asn_changes":  q1(conn, "SELECT COUNT(*) AS n FROM change_events WHERE event_date=? AND event_type='asn_changed'", (today,))["n"],
        "cert_changes": q1(conn, "SELECT COUNT(*) AS n FROM change_events WHERE event_date=? AND event_type='cert_changed'", (today,))["n"],
        "last_run":     q1(conn, "SELECT run_date, total_found, new_hosts, dead_hosts, duration_sec FROM run_log ORDER BY run_at DESC LIMIT 1"),
        "today":        today,
        "exported_at":  datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    active_hosts = q(conn, """
        SELECT ip, asn, asn_name, country_code, country_name, city,
               ssl_cn, ssl_is_selfsig, ssl_fingerprint,
               http_server, open_ports, source_name, source_query,
               is_suspicious, first_seen, last_seen, notes
        FROM hosts WHERE status='active'
        ORDER BY last_seen DESC, is_suspicious DESC
    """)
    for h in active_hosts:
        try:    h["open_ports"] = json.loads(h["open_ports"] or "[]")
        except: h["open_ports"] = []
        h["malware_family"] = h.get("source_name", "")
        h["is_bph"] = h.get("is_suspicious", 0)
        h["tags"] = []

    dead_hosts = q(conn, """
        SELECT ip, asn, asn_name, country_code, ssl_cn,
               is_suspicious, first_seen, last_seen, source_name
        FROM hosts WHERE status='dead'
        ORDER BY last_seen DESC LIMIT 500
    """)
    for h in dead_hosts:
        h["malware_family"] = h.get("source_name", "")

    families = q(conn, """
        SELECT source_name AS malware_family, COUNT(*) AS host_count,
               SUM(is_suspicious) AS bph_count,
               MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen
        FROM hosts WHERE status='active' AND source_name IS NOT NULL
        GROUP BY source_name ORDER BY host_count DESC
    """)

    asn_stats = q(conn, """
        SELECT asn, asn_name, country_code,
               COUNT(*) AS host_count, SUM(is_suspicious) AS suspicious_count,
               MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen
        FROM hosts WHERE status='active'
        GROUP BY asn, asn_name ORDER BY host_count DESC LIMIT 50
    """)

    ssl_clusters = q(conn, """
        SELECT ssl_fingerprint, ssl_cn, ssl_is_selfsig,
               COUNT(*) AS host_count,
               GROUP_CONCAT(ip, ', ') AS ips,
               MIN(first_seen) AS first_seen
        FROM hosts WHERE status='active'
          AND ssl_fingerprint IS NOT NULL AND ssl_fingerprint != ''
        GROUP BY ssl_fingerprint HAVING host_count > 1
        ORDER BY host_count DESC LIMIT 30
    """)

    queries = q(conn, """
        SELECT query_name, category, query_str,
               SUM(hits) AS total_hits, SUM(new_ips) AS total_new,
               COUNT(*) AS days_run, MAX(hits) AS peak_hits,
               MAX(run_date) AS last_active
        FROM query_hits GROUP BY query_name ORDER BY total_hits DESC
    """)

    timeline = q(conn, """
        SELECT run_date, total_found, new_hosts, dead_hosts,
               asn_changes, cert_changes, duration_sec
        FROM run_log ORDER BY run_date ASC LIMIT 90
    """)

    changes = q(conn, """
        SELECT ce.event_date, ce.ip, ce.event_type,
               ce.old_value, ce.new_value, ce.detail,
               h.asn_name, h.country_code, h.source_name AS malware_family, h.is_suspicious
        FROM change_events ce
        LEFT JOIN hosts h ON h.ip = ce.ip
        ORDER BY ce.event_date DESC, ce.id DESC LIMIT 200
    """)

    new_today = q(conn, """
        SELECT ip, asn, asn_name, country_code, ssl_cn,
               is_suspicious, source_name, first_seen
        FROM hosts WHERE first_seen=? AND status='active'
        ORDER BY is_suspicious DESC
    """, (today,))
    for h in new_today:
        h["malware_family"] = h.get("source_name", "")

    return {
        "overview": overview, "active_hosts": active_hosts,
        "dead_hosts": dead_hosts, "new_today": new_today,
        "families": families, "asn_stats": asn_stats,
        "ssl_clusters": ssl_clusters, "queries": queries,
        "timeline": timeline, "changes": changes,
    }


def main():
    if not DB_PATH.exists():
        print(f"✗ DB nicht gefunden: {DB_PATH}"); return

    EXPORTS_DIR.mkdir(exist_ok=True)
    HISTORY_DIR.mkdir(exist_ok=True)

    conn = get_conn()
    data = build_export(conn)
    conn.close()

    today = date.today().isoformat()

    latest = EXPORTS_DIR / "latest.json"
    latest.write_text(json.dumps(data, ensure_ascii=False, indent=2))
    print(f"✓ {latest}  ({latest.stat().st_size // 1024} KB)")

    hist_data = {
        "date": today, "overview": data["overview"],
        "active_hosts": [{"ip": h["ip"],
            "malware_family": h.get("malware_family") or h.get("source_name",""),
            "asn": h["asn"], "asn_name": h["asn_name"],
            "country_code": h["country_code"], "is_suspicious": h["is_suspicious"],
            "first_seen": h["first_seen"]} for h in data["active_hosts"]],
        "families": data["families"],
    }
    hist = HISTORY_DIR / f"{today}.json"
    hist.write_text(json.dumps(hist_data, ensure_ascii=False, indent=2))
    print(f"✓ {hist}  ({hist.stat().st_size // 1024} KB)")

    index = sorted([f.stem for f in HISTORY_DIR.glob("*.json")], reverse=True)
    (EXPORTS_DIR / "index.json").write_text(json.dumps(index, indent=2))
    print(f"✓ exports/index.json  ({len(index)} Snapshots)")

    ov = data["overview"]
    print(f"\n  Aktive Hosts:    {ov['active']}")
    print(f"  Tote Hosts:      {ov['dead_total']}")
    print(f"  Neu heute:       {ov['new_today']}")
    print(f"  BPH/Suspicious:  {ov['suspicious']}")
    print(f"  Familien:        {len(data['families'])}")
    print(f"\n  git add exports/ && git commit -m 'ns-hunter {today}' && git push")


if __name__ == "__main__":
    main()
