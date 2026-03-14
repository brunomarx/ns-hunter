"""
ns_hunter/stats.py — Daily Statistics, Diff & Report Generator
"""
import json
import sqlite3
from datetime import datetime, date, timedelta
from pathlib import Path
from typing import Optional
from db import get_conn, DB_PATH


def get_daily_diff(conn: sqlite3.Connection, today: str, yesterday: str) -> dict:
    """
    Berechnet den Diff zwischen heute und gestern:
    - Neue IPs (heute das erste Mal gesehen)
    - Verschwundene IPs (gestern gesehen, heute nicht mehr)
    - ASN-Wechsel
    - Zertifikat-Wechsel
    """
    c = conn.cursor()

    # Neue Hosts heute
    c.execute("""
        SELECT ip, asn, asn_name, country_code, ssl_cn, http_server, source_name, is_suspicious
        FROM hosts
        WHERE first_seen = ? AND status = 'active'
        ORDER BY is_suspicious DESC, asn_name
    """, (today,))
    new_hosts = [dict(r) for r in c.fetchall()]

    # Hosts die heute verschwunden sind (dead event heute)
    c.execute("""
        SELECT ce.ip, h.asn, h.asn_name, h.country_code, h.ssl_cn, h.first_seen
        FROM change_events ce
        LEFT JOIN hosts h ON h.ip = ce.ip
        WHERE ce.event_date = ? AND ce.event_type = 'dead'
        ORDER BY h.asn_name
    """, (today,))
    dead_hosts = [dict(r) for r in c.fetchall()]

    # ASN-Wechsel heute
    c.execute("""
        SELECT ip, old_value, new_value, detail
        FROM change_events
        WHERE event_date = ? AND event_type = 'asn_changed'
    """, (today,))
    asn_changes = [dict(r) for r in c.fetchall()]

    # Zertifikat-Wechsel
    c.execute("""
        SELECT ip, old_value, new_value, detail
        FROM change_events
        WHERE event_date = ? AND event_type = 'cert_changed'
    """, (today,))
    cert_changes = [dict(r) for r in c.fetchall()]

    # Reaktivierungen
    c.execute("""
        SELECT ip, detail FROM change_events
        WHERE event_date = ? AND event_type = 'reactivated'
    """, (today,))
    reactivated = [dict(r) for r in c.fetchall()]

    return {
        "date": today,
        "new": new_hosts,
        "dead": dead_hosts,
        "asn_changed": asn_changes,
        "cert_changed": cert_changes,
        "reactivated": reactivated,
    }


def get_asn_distribution(conn: sqlite3.Connection) -> list:
    """Aktive Hosts gruppiert nach ASN."""
    c = conn.cursor()
    c.execute("""
        SELECT asn, asn_name, country_code,
               COUNT(*) AS host_count,
               SUM(is_suspicious) AS suspicious_count
        FROM hosts
        WHERE status = 'active'
        GROUP BY asn, asn_name
        ORDER BY host_count DESC
        LIMIT 25
    """)
    return [dict(r) for r in c.fetchall()]


def get_timeline(conn: sqlite3.Connection, days: int = 30) -> list:
    """Tägliche Counts: wie viele Hosts waren an welchem Tag aktiv."""
    c = conn.cursor()
    c.execute("""
        SELECT run_date,
               total_found,
               new_hosts,
               dead_hosts,
               asn_changes,
               cert_changes
        FROM run_log
        ORDER BY run_date DESC
        LIMIT ?
    """, (days,))
    return [dict(r) for r in c.fetchall()]


def get_ssl_clusters(conn: sqlite3.Connection) -> list:
    """Zertifikate, die von mehreren Hosts geteilt werden → Cluster-Indikator."""
    c = conn.cursor()
    c.execute("""
        SELECT ssl_fingerprint, ssl_cn, ssl_is_selfsig,
               COUNT(*) AS host_count,
               GROUP_CONCAT(ip, ', ') AS ips
        FROM hosts
        WHERE status = 'active'
          AND ssl_fingerprint != ''
          AND ssl_fingerprint IS NOT NULL
        GROUP BY ssl_fingerprint
        HAVING host_count > 1
        ORDER BY host_count DESC
        LIMIT 20
    """)
    return [dict(r) for r in c.fetchall()]


def get_asn_migration_history(conn: sqlite3.Connection, ip: str) -> list:
    """Zeigt alle bekannten ASNs eines Hosts (Migrations-Timeline)."""
    c = conn.cursor()
    c.execute("""
        SELECT asn, asn_name, first_seen, last_seen
        FROM asn_history
        WHERE ip = ?
        ORDER BY first_seen
    """, (ip,))
    return [dict(r) for r in c.fetchall()]


def generate_text_report(conn: sqlite3.Connection, today: str) -> str:
    """Erzeugt einen kompakten täglichen Text-Report (für Log / Telegram / Mail)."""
    yesterday = (datetime.strptime(today, "%Y-%m-%d") - timedelta(days=1)).strftime("%Y-%m-%d")
    diff = get_daily_diff(conn, today, yesterday)
    asn_dist = get_asn_distribution(conn)

    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM hosts WHERE status = 'active'")
    total_active = c.fetchone()[0]

    lines = [
        "=" * 62,
        f"  NetSupport RAT Infrastructure Hunter — {today}",
        "=" * 62,
        "",
        f"📊 GESAMT AKTIVE HOSTS: {total_active}",
        "",
    ]

    # Neue Hosts
    lines.append(f"🔴 NEU HEUTE ({len(diff['new'])})")
    if diff["new"]:
        for h in diff["new"]:
            flag = "⚠️ " if h["is_suspicious"] else "   "
            asn_name = str(h.get("asn_name") or "")
            country  = str(h.get("country_code") or "??")
            ssl_cn   = str(h.get("ssl_cn") or "n/a")
            asn      = str(h.get("asn") or "?")
            lines.append(
                f"  {flag}{h['ip']:<18} AS{asn:<8} "
                f"{asn_name:<28} "
                f"{country}  "
                f"SSL:{ssl_cn[:20]}"
            )
    else:
        lines.append("   (keine neuen Hosts)")

    lines.append("")

    # Verschwundene
    lines.append(f"💀 VERSCHWUNDEN ({len(diff['dead'])})")
    if diff["dead"]:
        for h in diff["dead"]:
            asn_name   = str(h.get("asn_name") or "")
            asn        = str(h.get("asn") or "?")
            first_seen = str(h.get("first_seen") or "?")
            lines.append(
                f"   {h['ip']:<18} AS{asn:<8} "
                f"{asn_name:<28} "
                f"(seit {first_seen})"
            )
    else:
        lines.append("   (keine Abgänge)")

    lines.append("")

    # ASN-Wechsel
    if diff["asn_changed"]:
        lines.append(f"🔀 ASN-MIGRATIONEN ({len(diff['asn_changed'])})")
        for h in diff["asn_changed"]:
            lines.append(f"   {h['ip']} | {h['old_value']} → {h['new_value']}")
        lines.append("")

    # Cert-Wechsel
    if diff["cert_changed"]:
        lines.append(f"🔑 ZERTIFIKAT-WECHSEL ({len(diff['cert_changed'])})")
        for h in diff["cert_changed"]:
            lines.append(f"   {h['ip']} | {h.get('detail','')}")
        lines.append("")

    # ASN-Verteilung (Top 10)
    lines.append("📡 TOP ASNs (aktive Hosts)")
    for row in asn_dist[:10]:
        bar = "█" * min(row["host_count"], 30)
        susp = " ⚠️ BPH" if row["suspicious_count"] else ""
        lines.append(
            f"   AS{row['asn']:<8} {row['asn_name']:<28} "
            f"{row['host_count']:>3} Hosts  {bar}{susp}"
        )

    lines.append("")
    lines.append("=" * 62)

    return "\n".join(lines)


def export_iocs_csv(conn: sqlite3.Connection, output_path: Path, today: str):
    """Exportiert aktive Hosts als CSV-IOC-Liste."""
    c = conn.cursor()
    c.execute("""
        SELECT ip, asn, asn_name, country_code, country_name,
               ssl_cn, ssl_fingerprint, http_server,
               first_seen, last_seen, source_name, is_suspicious
        FROM hosts
        WHERE status = 'active'
        ORDER BY is_suspicious DESC, last_seen DESC
    """)
    rows = c.fetchall()

    header = "ip,asn,asn_name,country,ssl_cn,ssl_fingerprint,http_server,first_seen,last_seen,source,is_suspicious\n"
    lines = [header]
    for r in rows:
        lines.append(
            f"{r['ip']},{r['asn']},{r['asn_name']},{r['country_code']},"
            f"\"{r['ssl_cn'] or ''}\",{r['ssl_fingerprint'] or ''},"
            f"\"{r['http_server'] or ''}\",{r['first_seen']},{r['last_seen']},"
            f"{r['source_name']},{r['is_suspicious']}\n"
        )

    output_path.write_text("".join(lines))


def export_iocs_json(conn: sqlite3.Connection, output_path: Path, today: str):
    """Exportiert aktive Hosts als JSON (MISP-kompatibel)."""
    c = conn.cursor()
    c.execute("""
        SELECT ip, asn, asn_name, country_code, ssl_cn, ssl_fingerprint,
               http_server, open_ports, first_seen, last_seen, source_name, is_suspicious
        FROM hosts WHERE status = 'active'
        ORDER BY last_seen DESC
    """)
    rows = [dict(r) for r in c.fetchall()]

    for r in rows:
        try:
            r["open_ports"] = json.loads(r["open_ports"] or "[]")
        except Exception:
            r["open_ports"] = []

    payload = {
        "generated_at": datetime.utcnow().isoformat(),
        "date": today,
        "malware_family": "NetSupport RAT",
        "total": len(rows),
        "iocs": rows,
    }
    output_path.write_text(json.dumps(payload, indent=2))
