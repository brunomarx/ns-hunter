#!/usr/bin/env python3
"""
ns_hunter.py — NetSupport RAT Infrastructure Tracker
=====================================================
Täglich laufendes Script, das über Shodan-Queries
NetSupport RAT C2-Infrastruktur trackt.

Erkennt:
  • Neue IPs (heute erstmals gesehen)
  • Verschwundene IPs (gestern aktiv, heute nicht)
  • ASN-Migrationen (gleiche IP, neuer AS)
  • Zertifikat-Wechsel (SSL-Fingerprint-Änderung)

Usage:
  python ns_hunter.py              # Normaler Tages-Run
  python ns_hunter.py --stats      # Statistiken anzeigen
  python ns_hunter.py --report     # Tages-Report ausgeben
  python ns_hunter.py --pivot IP   # SSL-Pivot für eine IP
  python ns_hunter.py --lookup IP  # Host-Details
  python ns_hunter.py --export     # IOC-Export erzwingen
  python ns_hunter.py --dry-run    # Nur anzeigen, nichts speichern
"""

import sys
import os
import time
import logging
import argparse
import json
from datetime import datetime, date, timedelta
from pathlib import Path

import yaml

# Lokale Module
from db import (
    init_db, get_conn, upsert_host, mark_dead_hosts,
    add_daily_snapshot, log_run, upsert_query, bump_query_hits,
    log_query_hit, DB_PATH
)
from shodan_hunter import ShodanHunter
from stats import (
    generate_text_report, get_daily_diff, get_asn_distribution,
    get_ssl_clusters, get_timeline,
    export_iocs_csv, export_iocs_json
)

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("ns_hunter.log", encoding="utf-8"),
    ]
)
logger = logging.getLogger("ns_hunter")

BASE_DIR = Path(__file__).parent
SEARCHES_YAML = BASE_DIR / "searches.yml"
EXPORTS_DIR = BASE_DIR / "exports"
ARCHIVE_DIR = BASE_DIR / "archive"


def load_config() -> dict:
    """Lädt searches.yml."""
    if not SEARCHES_YAML.exists():
        logger.error(f"searches.yml nicht gefunden: {SEARCHES_YAML}")
        sys.exit(1)
    with open(SEARCHES_YAML) as f:
        return yaml.safe_load(f)


def get_api_key() -> str:
    key = os.environ.get("SHODAN_API_KEY", "")
    if not key:
        # Fallback: .env-Datei
        env_file = BASE_DIR / ".env"
        if env_file.exists():
            for line in env_file.read_text().splitlines():
                if line.startswith("SHODAN_API_KEY="):
                    key = line.split("=", 1)[1].strip().strip('"')
                    break
    if not key:
        logger.error("SHODAN_API_KEY nicht gesetzt. Export via: export SHODAN_API_KEY=xxx")
        sys.exit(1)
    return key


# ─── Haupt-Run ────────────────────────────────────────────────────────────────

def run(dry_run: bool = False):
    today = date.today().isoformat()
    run_start = time.time()

    logger.info("=" * 62)
    logger.info(f"  NetSupport RAT Hunter — {today}")
    logger.info("=" * 62)

    # Setup
    config = load_config()
    EXPORTS_DIR.mkdir(exist_ok=True)
    ARCHIVE_DIR.mkdir(exist_ok=True)
    init_db()
    conn = get_conn()

    suspicious_asns = config.get("suspicious_asns", {})
    hunter = ShodanHunter(get_api_key(), suspicious_asns)

    queries = [q for q in config.get("shodan", []) if q.get("enabled", True) is not False]
    logger.info(f"Queries geladen: {len(queries)}")

    # Query-Definitionen in DB synchronisieren
    for q in queries:
        upsert_query(conn, q["name"], q["query"], q.get("category", "generic"))
    conn.commit()

    # ── Phase 1: Shodan Queries ──────────────────────────────────────────────
    all_hosts: dict[str, dict] = {}  # ip → host_dict (dedupliziert)
    run_stats = {
        "run_at": datetime.utcnow().isoformat(),
        "run_date": today,
        "total_found": 0,
        "new_hosts": 0,
        "dead_hosts": 0,
        "asn_changes": 0,
        "cert_changes": 0,
        "queries_run": 0,
        "duration_sec": 0,
        "errors": 0,
    }

    for q in queries:
        name = q["name"]
        query = q["query"]

        results, total = hunter.search(name, query)
        run_stats["queries_run"] += 1
        bump_query_hits(conn, name, total, today)

        query_new_ips = 0
        for host in results:
            ip = host["ip"]
            if not ip:
                continue
            if ip in all_hosts:
                if host["is_suspicious"]:
                    all_hosts[ip]["is_suspicious"] = 1
            else:
                all_hosts[ip] = host
                query_new_ips += 1

        # Query-Hit-Tracking für Performance-Analyse
        log_query_hit(conn, today, name, q.get("category", "generic"),
                      hits=len(results), new_ips=query_new_ips, query_str=query)
        conn.commit()

        logger.info(f"  {name}: {len(results)} Hosts  ({query_new_ips} neu heute)")

    run_stats["total_found"] = len(all_hosts)
    logger.info(f"\nGesamt einzigartige Hosts: {len(all_hosts)}")

    if dry_run:
        logger.info("[DRY RUN] Kein Datenbankschreiben. Hosts gefunden:")
        for ip, h in list(all_hosts.items())[:20]:
            logger.info(f"  {ip:18} AS{h.get('asn','?'):<8} {h.get('asn_name','')}")
        return

    # ── Phase 2: DB-Upsert & Change Detection ───────────────────────────────
    seen_ips = set()
    event_counts = {"new": 0, "asn_changed": 0, "cert_changed": 0, "reactivated": 0}

    for ip, host in all_hosts.items():
        event_type = upsert_host(conn, host, today)
        add_daily_snapshot(conn, host, today)
        seen_ips.add(ip)

        if event_type == "new":
            event_counts["new"] += 1
            flag = "⚠️  [BPH]" if host["is_suspicious"] else "      "
            logger.info(
                f"  🔴 NEU    {flag} {ip:<18} "
                f"AS{str(host.get('asn') or '?'):<8} {str(host.get('asn_name') or ''):<28} "
                f"{str(host.get('country_code') or '??')}  SSL-CN:{str(host.get('ssl_cn') or 'n/a')}"
            )
        elif event_type == "asn_changed":
            event_counts["asn_changed"] += 1
            logger.warning(f"  🔀 ASN-WECHSEL {ip}")
        elif event_type == "cert_changed":
            event_counts["cert_changed"] += 1
            logger.info(f"  🔑 CERT-WECHSEL {ip}")
        elif event_type == "reactivated":
            event_counts["reactivated"] += 1
            logger.info(f"  ♻️  REAKTIVIERT {ip}")

    conn.commit()

    # ── Phase 3: Dead-Host-Detection ────────────────────────────────────────
    dead = mark_dead_hosts(conn, today, seen_ips)
    run_stats["dead_hosts"] = len(dead)
    if dead:
        logger.info(f"\n💀 Verschwundene Hosts ({len(dead)}):")
        for ip in dead[:20]:
            logger.info(f"   {ip}")
        if len(dead) > 20:
            logger.info(f"   ... und {len(dead)-20} weitere")

    conn.commit()

    run_stats["new_hosts"] = event_counts["new"]
    run_stats["asn_changes"] = event_counts["asn_changed"]
    run_stats["cert_changes"] = event_counts["cert_changed"]

    # ── Phase 4: Export ──────────────────────────────────────────────────────
    csv_path = EXPORTS_DIR / f"netsupport_c2_{today}.csv"
    json_path = EXPORTS_DIR / f"netsupport_c2_{today}.json"
    export_iocs_csv(conn, csv_path, today)
    export_iocs_json(conn, json_path, today)
    logger.info(f"\n📁 Exports: {csv_path.name}, {json_path.name}")

    # ── Phase 5: Report & Zusammenfassung ───────────────────────────────────
    run_stats["duration_sec"] = time.time() - run_start
    log_run(conn, run_stats)
    conn.commit()

    report = generate_text_report(conn, today)
    print("\n" + report)

    # Report auch in Datei speichern
    report_path = EXPORTS_DIR / f"report_{today}.txt"
    report_path.write_text(report)

    conn.close()

    logger.info(f"\n✅ Run abgeschlossen in {run_stats['duration_sec']:.1f}s")


# ─── CLI-Commands ─────────────────────────────────────────────────────────────

def cmd_stats():
    """Gesamtstatistiken aus der DB."""
    init_db()
    conn = get_conn()
    c = conn.cursor()

    print("\n" + "=" * 62)
    print("  NetSupport RAT Hunter — Statistiken")
    print("=" * 62)

    c.execute("SELECT COUNT(*) FROM hosts WHERE status='active'")
    active = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM hosts WHERE status='dead'")
    dead = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM hosts")
    total = c.fetchone()[0]
    c.execute("SELECT MIN(first_seen), MAX(last_seen) FROM hosts")
    row = c.fetchone()

    print(f"\n📊 Hosts:")
    print(f"   Gesamt:  {total}")
    print(f"   Aktiv:   {active}")
    print(f"   Dead:    {dead}")
    print(f"   Zeitraum: {row[0]} bis {row[1]}")

    print(f"\n📡 ASN-Verteilung (Top 15):")
    for r in get_asn_distribution(conn)[:15]:
        bar = "█" * min(r["host_count"], 25)
        susp = " ⚠️  BPH" if r["suspicious_count"] else ""
        print(f"   AS{r['asn']:<8} {r['asn_name']:<30} {r['host_count']:>3}  {bar}{susp}")

    print(f"\n🔑 Geteilte SSL-Zertifikate (Cluster-Indikatoren):")
    for r in get_ssl_clusters(conn)[:10]:
        selfsig = " [self-signed]" if r["ssl_is_selfsig"] else ""
        print(f"   CN:{r['ssl_cn'] or 'n/a':<28}{selfsig}  {r['host_count']} Hosts")
        print(f"      FP:{r['ssl_fingerprint'][:32]}...")
        print(f"      IPs: {r['ips'][:80]}")

    print(f"\n📈 Run-Historie (letzte 14 Tage):")
    print(f"   {'Datum':<12} {'Total':>6} {'Neu':>5} {'Dead':>5} {'ASN-Δ':>6} {'Cert-Δ':>6}")
    for r in get_timeline(conn, 14):
        print(f"   {r['run_date']:<12} {r['total_found']:>6} {r['new_hosts']:>5} "
              f"{r['dead_hosts']:>5} {r['asn_changes']:>6} {r['cert_changes']:>6}")

    print()
    conn.close()


def cmd_report(target_date: str = None):
    """Zeigt den täglichen Text-Report."""
    init_db()
    conn = get_conn()
    today = target_date or date.today().isoformat()
    print(generate_text_report(conn, today))
    conn.close()


def cmd_lookup(ip: str):
    """Details zu einer bestimmten IP."""
    init_db()
    conn = get_conn()
    c = conn.cursor()

    c.execute("SELECT * FROM hosts WHERE ip = ?", (ip,))
    h = c.fetchone()
    if not h:
        print(f"IP {ip} nicht in der Datenbank.")
        return

    h = dict(h)
    print(f"\n{'='*62}")
    print(f"  Host: {ip}")
    print(f"{'='*62}")
    print(f"  Status:        {h['status']}")
    print(f"  First seen:    {h['first_seen']}")
    print(f"  Last seen:     {h['last_seen']}")
    print(f"  ASN:           AS{h['asn']} {h['asn_name']}")
    print(f"  Country:       {h['country_name']} ({h['country_code']})")
    print(f"  City:          {h['city']}")
    print(f"  Org/ISP:       {h['org']} / {h['isp']}")
    print(f"  SSL CN:        {h['ssl_cn']}")
    print(f"  SSL Issuer:    {h['ssl_issuer_cn']}")
    print(f"  SSL Self-sig:  {'Ja' if h['ssl_is_selfsig'] else 'Nein'}")
    print(f"  SSL FP:        {h['ssl_fingerprint']}")
    print(f"  HTTP Server:   {h['http_server']}")
    print(f"  Open Ports:    {h['open_ports']}")
    print(f"  Source Query:  {h['source_name']}")
    print(f"  Suspicious:    {'⚠️  Ja (BPH-ASN)' if h['is_suspicious'] else 'Nein'}")

    c2 = conn.cursor()
    c2.execute("SELECT asn, asn_name, first_seen, last_seen FROM asn_history WHERE ip = ? ORDER BY first_seen", (ip,))
    migrations = [dict(r) for r in c2.fetchall()]
    if migrations:
        print(f"\n  ASN-History:")
        for m in migrations:
            print(f"    AS{m['asn']:<8} {m['asn_name']:<30} {m['first_seen']} – {m['last_seen']}")

    # Change Events
    c.execute("""
        SELECT event_date, event_type, old_value, new_value, detail
        FROM change_events WHERE ip = ?
        ORDER BY event_date DESC LIMIT 10
    """, (ip,))
    events = c.fetchall()
    if events:
        print(f"\n  Change-Events:")
        for e in events:
            print(f"    {e['event_date']}  {e['event_type']:<15} {e['detail'] or ''}")

    print()
    conn.close()


def cmd_pivot(ip: str):
    """SSL-Fingerprint-Pivot für eine bekannte IP."""
    init_db()
    conn = get_conn()
    c = conn.cursor()

    c.execute("SELECT ssl_fingerprint, ssl_cn FROM hosts WHERE ip = ?", (ip,))
    row = c.fetchone()
    if not row or not row["ssl_fingerprint"]:
        print(f"Kein SSL-Fingerprint für {ip} in der DB.")
        conn.close()
        return

    fingerprint = row["ssl_fingerprint"]
    print(f"\nSSL-Pivot für {ip}")
    print(f"Fingerprint: {fingerprint}")
    print(f"CN: {row['ssl_cn']}")
    print(f"\nSuche andere Hosts mit gleichem Zertifikat...")

    config = load_config()
    hunter = ShodanHunter(get_api_key(), config.get("suspicious_asns", {}))
    related = hunter.pivot_ssl_fingerprint(fingerprint)

    print(f"\nGefunden: {len(related)} verwandte Hosts")
    for h in related:
        flag = "⚠️ " if h["is_suspicious"] else "   "
        print(f"  {flag}{h['ip']:<18} AS{h.get('asn','?'):<8} "
              f"{h.get('asn_name',''):<28} {h.get('country_code','')}")

    conn.close()



def cmd_query_performance():
    """Zeigt Query-Performance über Zeit: welche Query liefert wie viele Treffer."""
    init_db()
    conn = get_conn()
    c = conn.cursor()

    print("\n" + "=" * 72)
    print("  Query Performance — Treffer über Zeit")
    print("=" * 72)

    # Alle Query-Namen
    c.execute("""
        SELECT DISTINCT query_name, category, query_str
        FROM query_hits
        ORDER BY category, query_name
    """)
    queries = c.fetchall()

    if not queries:
        print("\nNoch keine Daten. Mindestens ein Run erforderlich.")
        conn.close()
        return

    for q in queries:
        name     = q["query_name"]
        category = q["category"] or "generic"
        qstr     = q["query_str"] or ""

        # Gesamt-Stats
        c.execute("""
            SELECT
                COUNT(*)        AS days_run,
                SUM(hits)       AS total_hits,
                SUM(new_ips)    AS total_new,
                AVG(hits)       AS avg_hits,
                MAX(hits)       AS peak_hits,
                MAX(run_date)   AS last_active
            FROM query_hits WHERE query_name = ?
        """, (name,))
        s = c.fetchone()

        print(f"\n┌─ {name}  [{category}]")
        print(f"│  Query:      {qstr}")
        print(f"│  Tage:       {s['days_run']}  |  "
              f"Gesamt-Hits: {s['total_hits']}  |  "
              f"Neue IPs: {s['total_new']}  |  "
              f"Ø/Tag: {s['avg_hits']:.1f}  |  "
              f"Peak: {s['peak_hits']}")
        print(f"│  Zuletzt aktiv: {s['last_active']}")

        # Tagesverlauf (letzte 14 Tage)
        c.execute("""
            SELECT run_date, hits, new_ips
            FROM query_hits
            WHERE query_name = ?
            ORDER BY run_date DESC
            LIMIT 14
        """, (name,))
        days = c.fetchall()

        if days:
            print("│")
            print("│  Letzte 14 Tage (neueste zuerst):")
            print("│  {:12}  {:>8}  {:>8}  {}".format("Datum", "Hits", "Neu", "Balken"))
            for d in days:
                bar = "█" * min(d["hits"], 40)
                new_marker = f" +{d['new_ips']}" if d["new_ips"] > 0 else ""
                print(f"│  {d['run_date']:<12}  {d['hits']:>8}  "
                      f"{d['new_ips']:>8}  {bar}{new_marker}")
        print("└" + "─" * 70)

    # Gesamt-Ranking
    print("\n" + "─" * 72)
    print("  RANKING — Meiste Treffer gesamt")
    print("─" * 72)
    c.execute("""
        SELECT query_name, category, SUM(hits) AS total, SUM(new_ips) AS new_total
        FROM query_hits
        GROUP BY query_name
        ORDER BY total DESC
    """)
    for i, row in enumerate(c.fetchall(), 1):
        bar = "█" * min(row["total"] // max(1, 1), 30)
        print(f"  #{i:<3} {row['query_name']:<35} "
              f"{row['total']:>6} hits  {row['new_total']:>5} neu  {bar}")

    print()
    conn.close()


def cmd_reverse_lookup(ip: str):
    """
    Rückwärts-Suche: IP eingeben → woher kommt sie?
    Zeigt: welche Query, wann erstmals, ASN-Verlauf, alle Change-Events.
    Ideal für: Kunde meldet verdächtige IP → sofort Kontext.
    """
    init_db()
    conn = get_conn()
    c = conn.cursor()

    # Host in DB?
    c.execute("SELECT * FROM hosts WHERE ip = ?", (ip,))
    h = c.fetchone()

    print("\n" + "=" * 72)
    print(f"  Reverse Lookup: {ip}")
    print("=" * 72)

    if h:
        h = dict(h)
        status_icon = "🟢" if h["status"] == "active" else "💀"
        susp_icon   = "⚠️  [BPH-ASN]" if h["is_suspicious"] else ""
        print(f"\n  Status:      {status_icon} {h['status'].upper()}  {susp_icon}")
        print(f"  First seen:  {h['first_seen']}  (erstmals durch Hunter erfasst)")
        print(f"  Last seen:   {h['last_seen']}")
        print(f"\n  ASN:         AS{h['asn']} — {h['asn_name'] or 'unbekannt'}")
        print(f"  Land:        {h['country_name'] or '?'} ({h['country_code'] or '?'})")
        print(f"  Stadt:       {h['city'] or '?'}")
        print(f"  Org/ISP:     {h['org'] or '?'}")
        print(f"\n  SSL CN:      {h['ssl_cn'] or 'n/a'}")
        print(f"  SSL Issuer:  {h['ssl_issuer_cn'] or 'n/a'}")
        print(f"  Self-signed: {'Ja' if h['ssl_is_selfsig'] else 'Nein'}")
        print(f"  SSL FP:      {h['ssl_fingerprint'] or 'n/a'}")
        print(f"  HTTP Server: {h['http_server'] or 'n/a'}")
        print(f"  Open Ports:  {h['open_ports'] or 'unbekannt'}")

        print(f"\n  Gefunden durch Query: [{h['source_name']}]")
        print(f"  Query-String: {h['source_query'] or 'n/a'}")

        # Query-Performance-Kontext
        c.execute("""
            SELECT SUM(hits) AS total_hits, COUNT(*) AS days_active
            FROM query_hits WHERE query_name = ?
        """, (h["source_name"],))
        qp = c.fetchone()
        if qp and qp["total_hits"]:
            print(f"  Query hat bisher {qp['total_hits']} Treffer über {qp['days_active']} Tage geliefert")

    else:
        print(f"\n  ❌ IP {ip} ist NICHT in der Datenbank.")
        print(f"  → Entweder nie von einer Query erfasst,")
        print(f"    oder als 'dead' markiert und du suchst mit --lookup.")
        print(f"\n  Tipp: Probiere --pivot {ip} für einen Live-SSL-Fingerprint-Pivot.")

    # ASN-History (Migrationen)
    c.execute("""
        SELECT asn, asn_name, first_seen, last_seen
        FROM asn_history WHERE ip = ?
        ORDER BY first_seen
    """, (ip,))
    asn_hist = c.fetchall()
    if len(asn_hist) > 1:
        print(f"\n  🔀 ASN-MIGRATIONEN ERKANNT ({len(asn_hist)} ASNs):")
        for row in asn_hist:
            print(f"     AS{row['asn']:<8} {row['asn_name'] or '':<30} "
                  f"{row['first_seen']} → {row['last_seen']}")
    elif asn_hist:
        print(f"\n  ASN-History: 1 ASN, keine Migration")

    # Alle Change-Events
    c.execute("""
        SELECT event_date, event_type, old_value, new_value, detail
        FROM change_events WHERE ip = ?
        ORDER BY event_date DESC
    """, (ip,))
    events = c.fetchall()
    if events:
        print(f"\n  📋 CHANGE EVENTS ({len(events)}):")
        for e in events:
            old = f" | {e['old_value']} → {e['new_value']}" if e["old_value"] else ""
            detail = f" | {e['detail']}" if e["detail"] else ""
            print(f"     {e['event_date']}  {e['event_type']:<15}{old}{detail}")

    # Hosts mit gleichem SSL-Fingerprint (Cluster)
    if h and h.get("ssl_fingerprint"):
        c.execute("""
            SELECT ip, asn_name, country_code, first_seen, status
            FROM hosts
            WHERE ssl_fingerprint = ? AND ip != ?
            ORDER BY first_seen
        """, (h["ssl_fingerprint"], ip))
        cluster = c.fetchall()
        if cluster:
            print(f"\n  🔗 GLEICHE SSL-FINGERPRINT — {len(cluster)} weitere Hosts:")
            for row in cluster:
                dead = " [dead]" if row["status"] == "dead" else ""
                print(f"     {row['ip']:<18} {row['asn_name'] or '':<28} "
                      f"{row['country_code'] or ''}  seit {row['first_seen']}{dead}")

    print()
    conn.close()

def cmd_export():
    """Erzwingt IOC-Export für heute."""
    today = date.today().isoformat()
    init_db()
    conn = get_conn()
    EXPORTS_DIR.mkdir(exist_ok=True)
    csv_path = EXPORTS_DIR / f"netsupport_c2_{today}.csv"
    json_path = EXPORTS_DIR / f"netsupport_c2_{today}.json"
    export_iocs_csv(conn, csv_path, today)
    export_iocs_json(conn, json_path, today)
    print(f"✅ Exportiert:\n  {csv_path}\n  {json_path}")
    conn.close()


# ─── Entry Point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="NetSupport RAT Infrastructure Hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  python ns_hunter.py                     # Täglicher Run
  python ns_hunter.py --stats             # Gesamtstatistiken
  python ns_hunter.py --report            # Heutiger Report
  python ns_hunter.py --report 2026-03-01 # Report für Datum
  python ns_hunter.py --lookup 1.2.3.4    # IP-Details
  python ns_hunter.py --pivot  1.2.3.4    # SSL-Pivot
  python ns_hunter.py --queries           # Query-Performance über Zeit
  python ns_hunter.py --where  1.2.3.4   # Woher kommt diese IP?
  python ns_hunter.py --export            # IOC-Export erzwingen
  python ns_hunter.py --dry-run           # Test ohne DB-Schreiben
        """
    )
    parser.add_argument("--stats",    action="store_true",    help="Statistiken anzeigen")
    parser.add_argument("--report",   nargs="?", const=True,  help="Tages-Report [YYYY-MM-DD]")
    parser.add_argument("--lookup",   metavar="IP",           help="Host-Details")
    parser.add_argument("--pivot",    metavar="IP",           help="SSL-Fingerprint-Pivot")
    parser.add_argument("--queries",  action="store_true",    help="Query-Performance über Zeit")
    parser.add_argument("--where",    metavar="IP",           help="Rückwärts-Suche: woher kommt diese IP?")
    parser.add_argument("--export",   action="store_true",    help="IOC-Export erzwingen")
    parser.add_argument("--dry-run",  action="store_true",    help="Kein DB-Schreiben")

    args = parser.parse_args()

    if args.stats:
        cmd_stats()
    elif args.report is not None:
        date_arg = args.report if isinstance(args.report, str) else None
        cmd_report(date_arg)
    elif args.lookup:
        cmd_lookup(args.lookup)
    elif args.pivot:
        cmd_pivot(args.pivot)
    elif args.queries:
        cmd_query_performance()
    elif args.where:
        cmd_reverse_lookup(args.where)
    elif args.export:
        cmd_export()
    else:
        run(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
