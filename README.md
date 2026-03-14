# ns-hunter — NetSupport RAT Infrastructure Tracker

Täglich laufendes Shodan-Tool zum Tracking von NetSupport RAT C2-Infrastruktur.
Analog zu cobalt-stats.de / melting-cobalt, aber spezialisiert auf NetSupport RAT,
SmartApeSG und zugehörige Bulletproof-Hosting-Cluster.

## Was wird getrackt

- **Neue IPs** — heute erstmals in Shodan-Ergebnissen aufgetaucht
- **Verschwundene IPs** — gestern aktiv, heute nicht mehr auffindbar  
- **ASN-Migrationen** — gleiche IP, anderer Autonomous System (BPH-Wechsel)
- **Zertifikat-Wechsel** — SSL-Fingerprint hat sich geändert (Redeployment-Indikator)
- **SSL-Cluster** — mehrere Hosts mit identischem Zertifikat (shared template)
- **Reaktivierungen** — als dead markierte IPs tauchen wieder auf

## Setup

```bash
# 1. Abhängigkeiten
pip install -r requirements.txt

# 2. Shodan API Key setzen
export SHODAN_API_KEY="dein_key"

# Oder .env Datei anlegen:
echo 'SHODAN_API_KEY=dein_key' > .env

# 3. Ersten Run starten
python ns_hunter.py
```

## Usage

```bash
# Täglicher Run (für Cronjob)
python ns_hunter.py

# Nur anzeigen, nichts speichern (Test)
python ns_hunter.py --dry-run

# Gesamtstatistiken
python ns_hunter.py --stats

# Report für heute
python ns_hunter.py --report

# Report für bestimmtes Datum
python ns_hunter.py --report 2026-03-01

# Details zu einer IP
python ns_hunter.py --lookup 5.181.156.16

# SSL-Fingerprint-Pivot (findet verwandte Hosts)
python ns_hunter.py --pivot 5.181.156.16

# IOC-Export erzwingen
python ns_hunter.py --export
```

## Cronjob

```bash
# Täglich 06:00 UTC
0 6 * * * cd /opt/ns-hunter && python ns_hunter.py >> ns_hunter.log 2>&1
```

## Queries anpassen

`searches.yml` editieren. Neue Query hinzufügen:

```yaml
shodan:
  - name: "mein_query_name"
    query: '"DESKTOP-XXXXX" port:3389'
    category: "rdp_template"
```

Kategorie-Optionen: `rdp_template`, `netsupport_banner`, `c2_management`, `smartapesg`, `generic`

## Dateistruktur

```
ns-hunter/
├── ns_hunter.py      # Haupt-Runner + CLI
├── db.py             # SQLite Schema + Helper
├── shodan_hunter.py  # Shodan API Wrapper + Normalizer
├── stats.py          # Diff, Reports, Exports
├── searches.yml      # Query-Definitionen
├── requirements.txt
├── ns_hunter.db      # SQLite Datenbank (wird auto-erstellt)
├── ns_hunter.log     # Log-Datei
├── exports/          # Tägliche IOC-Exports (CSV + JSON)
└── archive/          # Archivierte Reports
```

## Outputs

Täglich in `exports/`:
- `netsupport_c2_YYYY-MM-DD.csv` — IOC-Liste (für SIEM-Import)
- `netsupport_c2_YYYY-MM-DD.json` — JSON mit Metadaten
- `report_YYYY-MM-DD.txt` — Tages-Textreport

## Datenbank-Schema

| Tabelle           | Inhalt                                      |
|-------------------|---------------------------------------------|
| `hosts`           | Alle bekannten Hosts mit ASN, Cert, Status  |
| `daily_snapshots` | Tages-Schnappschuss aller aktiven Hosts     |
| `change_events`   | new / dead / asn_changed / cert_changed     |
| `asn_history`     | Pro IP: alle bekannten ASNs (Migrations)    |
| `queries`         | Query-Definitionen mit Hit-Stats            |
| `run_log`         | Pro Run: Statistiken und Dauer              |
