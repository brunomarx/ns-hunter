"""
app.py — NetSupport RAT Hunter Dashboard
Flask-Web-App, liest direkt aus ns_hunter.db
"""
import json
import sqlite3
from datetime import date, datetime, timedelta
from pathlib import Path
from flask import Flask, jsonify, render_template_string, request

DB_PATH = Path(__file__).parent / "ns_hunter.db"
app = Flask(__name__)


# ── DB Helper ─────────────────────────────────────────────────────────────────

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def q(sql, params=()):
    conn = get_conn()
    rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    conn.close()
    return rows


def q1(sql, params=()):
    conn = get_conn()
    row = conn.execute(sql, params).fetchone()
    conn.close()
    return dict(row) if row else {}


# ── API Routes ────────────────────────────────────────────────────────────────

@app.route("/api/overview")
def api_overview():
    today = date.today().isoformat()
    yesterday = (date.today() - timedelta(days=1)).isoformat()

    active   = q1("SELECT COUNT(*) AS n FROM hosts WHERE status='active'")["n"]
    dead     = q1("SELECT COUNT(*) AS n FROM hosts WHERE status='dead'")["n"]
    new_today = q1("SELECT COUNT(*) AS n FROM hosts WHERE first_seen=? AND status='active'", (today,))["n"]
    dead_today = q1("SELECT COUNT(*) AS n FROM change_events WHERE event_date=? AND event_type='dead'", (today,))["n"]
    asn_changes = q1("SELECT COUNT(*) AS n FROM change_events WHERE event_date=? AND event_type='asn_changed'", (today,))["n"]
    cert_changes = q1("SELECT COUNT(*) AS n FROM change_events WHERE event_date=? AND event_type='cert_changed'", (today,))["n"]
    suspicious = q1("SELECT COUNT(*) AS n FROM hosts WHERE is_suspicious=1 AND status='active'")["n"]
    last_run = q1("SELECT run_date, total_found, duration_sec FROM run_log ORDER BY run_at DESC LIMIT 1")

    return jsonify({
        "active": active,
        "dead_total": dead,
        "new_today": new_today,
        "dead_today": dead_today,
        "asn_changes": asn_changes,
        "cert_changes": cert_changes,
        "suspicious": suspicious,
        "last_run": last_run,
        "today": today,
    })


@app.route("/api/feed")
def api_feed():
    today = date.today().isoformat()
    limit = int(request.args.get("limit", 100))

    new_hosts = q("""
        SELECT ip, asn, asn_name, country_code, country_name, city,
               ssl_cn, http_server, open_ports, source_name,
               is_suspicious, first_seen, last_seen
        FROM hosts
        WHERE status='active'
        ORDER BY last_seen DESC, first_seen DESC
        LIMIT ?
    """, (limit,))

    new_today = q("""
        SELECT ip, asn, asn_name, country_code, ssl_cn, http_server,
               source_name, is_suspicious, first_seen
        FROM hosts
        WHERE first_seen=? AND status='active'
        ORDER BY is_suspicious DESC
    """, (today,))

    dead_today = q("""
        SELECT ce.ip, h.asn, h.asn_name, h.country_code, h.ssl_cn, h.first_seen
        FROM change_events ce
        LEFT JOIN hosts h ON h.ip = ce.ip
        WHERE ce.event_date=? AND ce.event_type='dead'
    """, (today,))

    return jsonify({
        "active_hosts": new_hosts,
        "new_today": new_today,
        "dead_today": dead_today,
    })


@app.route("/api/asn")
def api_asn():
    rows = q("""
        SELECT asn, asn_name, country_code,
               COUNT(*) AS host_count,
               SUM(is_suspicious) AS suspicious_count,
               MIN(first_seen) AS first_seen,
               MAX(last_seen) AS last_seen
        FROM hosts
        WHERE status='active'
        GROUP BY asn, asn_name
        ORDER BY host_count DESC
        LIMIT 30
    """)
    return jsonify(rows)


@app.route("/api/queries")
def api_queries():
    rows = q("""
        SELECT query_name, category, query_str,
               SUM(hits) AS total_hits,
               SUM(new_ips) AS total_new,
               COUNT(*) AS days_run,
               MAX(hits) AS peak_hits,
               MAX(run_date) AS last_active
        FROM query_hits
        GROUP BY query_name
        ORDER BY total_hits DESC
    """)

    timeline = q("""
        SELECT run_date, query_name, hits, new_ips
        FROM query_hits
        ORDER BY run_date DESC
        LIMIT 200
    """)

    return jsonify({"summary": rows, "timeline": timeline})


@app.route("/api/timeline")
def api_timeline():
    rows = q("""
        SELECT run_date, total_found, new_hosts, dead_hosts,
               asn_changes, cert_changes
        FROM run_log
        ORDER BY run_date ASC
        LIMIT 60
    """)
    return jsonify(rows)


@app.route("/api/ssl_clusters")
def api_ssl_clusters():
    rows = q("""
        SELECT ssl_fingerprint, ssl_cn, ssl_is_selfsig,
               COUNT(*) AS host_count,
               GROUP_CONCAT(ip, ', ') AS ips,
               MIN(first_seen) AS first_seen
        FROM hosts
        WHERE status='active'
          AND ssl_fingerprint != ''
          AND ssl_fingerprint IS NOT NULL
        GROUP BY ssl_fingerprint
        HAVING host_count > 1
        ORDER BY host_count DESC
        LIMIT 20
    """)
    return jsonify(rows)


@app.route("/api/changes")
def api_changes():
    rows = q("""
        SELECT ce.event_date, ce.ip, ce.event_type,
               ce.old_value, ce.new_value, ce.detail,
               h.asn_name, h.country_code
        FROM change_events ce
        LEFT JOIN hosts h ON h.ip = ce.ip
        ORDER BY ce.event_date DESC, ce.id DESC
        LIMIT 100
    """)
    return jsonify(rows)


@app.route("/api/lookup/<ip>")
def api_lookup(ip):
    host = q1("SELECT * FROM hosts WHERE ip=?", (ip,))
    if not host:
        return jsonify({"found": False, "ip": ip})

    asn_hist = q("""
        SELECT asn, asn_name, first_seen, last_seen
        FROM asn_history WHERE ip=? ORDER BY first_seen
    """, (ip,))

    events = q("""
        SELECT event_date, event_type, old_value, new_value, detail
        FROM change_events WHERE ip=? ORDER BY event_date DESC
    """, (ip,))

    cluster = []
    if host.get("ssl_fingerprint"):
        cluster = q("""
            SELECT ip, asn_name, country_code, first_seen, status
            FROM hosts
            WHERE ssl_fingerprint=? AND ip!=?
            ORDER BY first_seen
        """, (host["ssl_fingerprint"], ip))

    try:
        host["open_ports"] = json.loads(host.get("open_ports") or "[]")
    except Exception:
        host["open_ports"] = []

    return jsonify({
        "found": True,
        "host": host,
        "asn_history": asn_hist,
        "events": events,
        "ssl_cluster": cluster,
    })


# ── Frontend ──────────────────────────────────────────────────────────────────

TEMPLATE = r"""<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NS-Hunter — NetSupport RAT Infrastructure</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  :root {
    --bg:       #080c0e;
    --bg2:      #0d1417;
    --bg3:      #111a1e;
    --border:   #1a2e35;
    --green:    #00e676;
    --green2:   #00ff9f;
    --amber:    #ffab00;
    --red:      #ff3d3d;
    --blue:     #29b6f6;
    --dim:      #3a5560;
    --text:     #c8dde3;
    --textdim:  #5a7a85;
    --mono:     'Share Tech Mono', monospace;
    --sans:     'Rajdhani', sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 15px;
    line-height: 1.5;
    min-height: 100vh;
    /* scanline overlay */
    background-image:
      repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0,230,118,0.015) 2px,
        rgba(0,230,118,0.015) 4px
      );
  }

  /* ── Header ── */
  header {
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    padding: 0 2rem;
    display: flex;
    align-items: center;
    gap: 2rem;
    height: 56px;
    position: sticky;
    top: 0;
    z-index: 100;
  }
  .logo {
    font-family: var(--mono);
    font-size: 13px;
    color: var(--green);
    letter-spacing: 2px;
    white-space: nowrap;
  }
  .logo span { color: var(--textdim); }
  .tagline {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--textdim);
    flex: 1;
  }
  .live-dot {
    width: 8px; height: 8px;
    background: var(--green);
    border-radius: 50%;
    box-shadow: 0 0 8px var(--green);
    animation: pulse 2s ease-in-out infinite;
  }
  @keyframes pulse {
    0%,100% { opacity: 1; box-shadow: 0 0 8px var(--green); }
    50%      { opacity: 0.4; box-shadow: 0 0 3px var(--green); }
  }
  #last-updated {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--textdim);
  }

  /* ── Stats Bar ── */
  .stats-bar {
    display: grid;
    grid-template-columns: repeat(7, 1fr);
    gap: 1px;
    background: var(--border);
    border-bottom: 1px solid var(--border);
  }
  .stat-cell {
    background: var(--bg2);
    padding: 1rem 1.25rem;
    text-align: center;
  }
  .stat-val {
    font-family: var(--mono);
    font-size: 28px;
    font-weight: 700;
    line-height: 1;
    display: block;
    margin-bottom: 4px;
  }
  .stat-val.green  { color: var(--green);  text-shadow: 0 0 20px rgba(0,230,118,0.4); }
  .stat-val.amber  { color: var(--amber);  text-shadow: 0 0 20px rgba(255,171,0,0.4); }
  .stat-val.red    { color: var(--red);    text-shadow: 0 0 20px rgba(255,61,61,0.4); }
  .stat-val.blue   { color: var(--blue);   text-shadow: 0 0 20px rgba(41,182,246,0.4); }
  .stat-label {
    font-size: 10px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: var(--textdim);
    font-family: var(--mono);
  }

  /* ── Tabs ── */
  .tabs {
    display: flex;
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    padding: 0 2rem;
    gap: 0;
  }
  .tab {
    padding: 0.75rem 1.5rem;
    font-family: var(--mono);
    font-size: 12px;
    letter-spacing: 1px;
    color: var(--textdim);
    cursor: pointer;
    border-bottom: 2px solid transparent;
    transition: all 0.15s;
    text-transform: uppercase;
    user-select: none;
  }
  .tab:hover { color: var(--text); }
  .tab.active { color: var(--green); border-bottom-color: var(--green); }

  /* ── Main ── */
  .main { padding: 1.5rem 2rem; }
  .panel { display: none; }
  .panel.active { display: block; }

  /* ── Section headers ── */
  .section-head {
    font-family: var(--mono);
    font-size: 11px;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: var(--green);
    border-bottom: 1px solid var(--border);
    padding-bottom: 0.5rem;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .section-head::before {
    content: '▸';
    color: var(--dim);
  }

  /* ── Tables ── */
  .data-table {
    width: 100%;
    border-collapse: collapse;
    font-family: var(--mono);
    font-size: 12px;
  }
  .data-table th {
    text-align: left;
    padding: 0.4rem 0.75rem;
    font-size: 10px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: var(--textdim);
    border-bottom: 1px solid var(--border);
    background: var(--bg2);
    position: sticky;
    top: 57px;
  }
  .data-table td {
    padding: 0.35rem 0.75rem;
    border-bottom: 1px solid rgba(26,46,53,0.5);
    vertical-align: middle;
  }
  .data-table tr:hover td { background: rgba(0,230,118,0.03); }
  .ip      { color: var(--green2); }
  .asn     { color: var(--blue); }
  .bph     { color: var(--amber); }
  .dead-ip { color: var(--red); }
  .cn      { color: var(--textdim); }

  .badge {
    display: inline-block;
    padding: 1px 6px;
    border-radius: 3px;
    font-size: 10px;
    letter-spacing: 1px;
    text-transform: uppercase;
  }
  .badge-bph    { background: rgba(255,171,0,0.15); color: var(--amber); border: 1px solid rgba(255,171,0,0.3); }
  .badge-new    { background: rgba(0,230,118,0.1);  color: var(--green); border: 1px solid rgba(0,230,118,0.3); }
  .badge-dead   { background: rgba(255,61,61,0.1);  color: var(--red);   border: 1px solid rgba(255,61,61,0.3); }
  .badge-asn    { background: rgba(41,182,246,0.1); color: var(--blue);  border: 1px solid rgba(41,182,246,0.3); }
  .badge-cert   { background: rgba(255,171,0,0.1);  color: var(--amber); border: 1px solid rgba(255,171,0,0.3); }

  /* ── Two-col layout ── */
  .two-col {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1.5rem;
    margin-bottom: 1.5rem;
  }
  .card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 1.25rem;
  }

  /* ── Charts ── */
  .chart-wrap { position: relative; height: 220px; }
  .chart-wrap-tall { position: relative; height: 300px; }

  /* ── ASN Bar ── */
  .asn-bar-wrap { display: flex; flex-direction: column; gap: 6px; }
  .asn-row { display: flex; align-items: center; gap: 8px; font-family: var(--mono); font-size: 11px; }
  .asn-name { width: 200px; color: var(--textdim); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .asn-bar-bg { flex: 1; background: var(--bg3); border-radius: 2px; height: 16px; overflow: hidden; }
  .asn-bar-fill { height: 100%; background: linear-gradient(90deg, var(--green) 0%, var(--green2) 100%); transition: width 0.8s ease; border-radius: 2px; }
  .asn-bar-fill.bph { background: linear-gradient(90deg, var(--amber) 0%, #ffd740 100%); }
  .asn-count { width: 30px; text-align: right; color: var(--green); }
  .asn-code { width: 36px; color: var(--textdim); font-size: 10px; }

  /* ── Lookup ── */
  .lookup-box {
    display: flex;
    gap: 0.75rem;
    margin-bottom: 1.5rem;
  }
  .lookup-input {
    flex: 1;
    background: var(--bg3);
    border: 1px solid var(--border);
    color: var(--green2);
    font-family: var(--mono);
    font-size: 14px;
    padding: 0.65rem 1rem;
    outline: none;
    border-radius: 3px;
    transition: border-color 0.15s;
  }
  .lookup-input:focus { border-color: var(--green); }
  .lookup-input::placeholder { color: var(--dim); }
  .lookup-btn {
    background: rgba(0,230,118,0.1);
    border: 1px solid rgba(0,230,118,0.3);
    color: var(--green);
    font-family: var(--mono);
    font-size: 12px;
    letter-spacing: 2px;
    padding: 0.65rem 1.5rem;
    cursor: pointer;
    border-radius: 3px;
    text-transform: uppercase;
    transition: all 0.15s;
  }
  .lookup-btn:hover { background: rgba(0,230,118,0.2); }

  .lookup-result {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 1.5rem;
    font-family: var(--mono);
    font-size: 12px;
    display: none;
  }
  .lookup-result.visible { display: block; }
  .lr-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1rem; }
  .lr-group { margin-bottom: 1.25rem; }
  .lr-key { font-size: 10px; color: var(--textdim); letter-spacing: 1px; text-transform: uppercase; margin-bottom: 3px; }
  .lr-val { color: var(--text); }
  .lr-val.highlight { color: var(--green2); }
  .lr-val.warn { color: var(--amber); }
  .lr-val.danger { color: var(--red); }

  .not-found {
    font-family: var(--mono);
    color: var(--red);
    font-size: 13px;
    padding: 1.5rem;
    background: rgba(255,61,61,0.05);
    border: 1px solid rgba(255,61,61,0.2);
    border-radius: 4px;
  }

  /* ── SSL Cluster ── */
  .cluster-card {
    background: var(--bg3);
    border: 1px solid var(--border);
    border-left: 3px solid var(--amber);
    padding: 0.75rem 1rem;
    margin-bottom: 0.75rem;
    border-radius: 0 3px 3px 0;
    font-family: var(--mono);
    font-size: 11px;
  }
  .cluster-fp { color: var(--textdim); font-size: 10px; margin-bottom: 4px; }
  .cluster-cn { color: var(--amber); font-size: 13px; margin-bottom: 6px; }
  .cluster-ips { color: var(--green2); }
  .cluster-count { float: right; color: var(--amber); font-size: 18px; font-weight: 700; }

  /* ── Changes feed ── */
  .change-item {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.4rem 0.5rem;
    border-bottom: 1px solid rgba(26,46,53,0.5);
    font-family: var(--mono);
    font-size: 11px;
  }
  .change-date { color: var(--textdim); width: 90px; flex-shrink: 0; }
  .change-ip   { color: var(--green2); width: 130px; flex-shrink: 0; cursor: pointer; }
  .change-ip:hover { text-decoration: underline; }
  .change-detail { color: var(--textdim); flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  /* ── Query perf ── */
  .qperf-row {
    background: var(--bg3);
    border: 1px solid var(--border);
    padding: 0.75rem 1rem;
    margin-bottom: 0.5rem;
    border-radius: 3px;
    font-family: var(--mono);
    font-size: 11px;
  }
  .qperf-top { display: flex; align-items: center; gap: 1rem; margin-bottom: 6px; }
  .qperf-name { color: var(--green); font-size: 13px; flex: 1; }
  .qperf-cat { font-size: 10px; color: var(--textdim); }
  .qperf-nums { display: flex; gap: 1.5rem; }
  .qperf-num  { text-align: center; }
  .qperf-num .n { font-size: 20px; color: var(--amber); display: block; }
  .qperf-num .l { font-size: 9px; color: var(--textdim); letter-spacing: 1px; text-transform: uppercase; }
  .qperf-query { color: var(--textdim); font-size: 10px; margin-top: 4px; }
  .qperf-bar-bg { background: var(--bg); height: 4px; border-radius: 2px; margin-top: 6px; }
  .qperf-bar-fill { height: 100%; border-radius: 2px; background: linear-gradient(90deg, var(--amber), #ffd740); transition: width 0.8s; }

  /* ── Scrollbar ── */
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--dim); border-radius: 3px; }

  /* ── Empty state ── */
  .empty { font-family: var(--mono); color: var(--dim); font-size: 12px; padding: 2rem; text-align: center; }

  /* ── Loading ── */
  .loading { font-family: var(--mono); color: var(--green); font-size: 12px; padding: 1rem; }
  .loading::after { content: '...'; animation: dots 1.2s steps(4,end) infinite; }
  @keyframes dots { 0%,20%{content:'.'} 40%{content:'..'} 60%,100%{content:'...'} }
</style>
</head>
<body>

<header>
  <div class="logo">NS<span>-</span>HUNTER <span>// NETSUPPORT RAT INFRASTRUCTURE TRACKER</span></div>
  <div class="tagline">Shodan-based daily C2 tracking · SmartApeSG / FakeUpdate campaigns</div>
  <div class="live-dot"></div>
  <div id="last-updated">–</div>
</header>

<div class="stats-bar">
  <div class="stat-cell">
    <span class="stat-val green" id="s-active">–</span>
    <span class="stat-label">Active Hosts</span>
  </div>
  <div class="stat-cell">
    <span class="stat-val amber" id="s-suspicious">–</span>
    <span class="stat-label">BPH-ASN</span>
  </div>
  <div class="stat-cell">
    <span class="stat-val green" id="s-new">–</span>
    <span class="stat-label">New Today</span>
  </div>
  <div class="stat-cell">
    <span class="stat-val red" id="s-dead">–</span>
    <span class="stat-label">Dead Today</span>
  </div>
  <div class="stat-cell">
    <span class="stat-val blue" id="s-asn">–</span>
    <span class="stat-label">ASN Changes</span>
  </div>
  <div class="stat-cell">
    <span class="stat-val amber" id="s-cert">–</span>
    <span class="stat-label">Cert Changes</span>
  </div>
  <div class="stat-cell">
    <span class="stat-val" id="s-lastrun" style="font-size:13px;color:var(--textdim)">–</span>
    <span class="stat-label">Last Run</span>
  </div>
</div>

<div class="tabs">
  <div class="tab active" onclick="switchTab('feed')">Live Feed</div>
  <div class="tab" onclick="switchTab('asn')">ASN Distribution</div>
  <div class="tab" onclick="switchTab('timeline')">Timeline</div>
  <div class="tab" onclick="switchTab('queries')">Query Performance</div>
  <div class="tab" onclick="switchTab('clusters')">SSL Clusters</div>
  <div class="tab" onclick="switchTab('changes')">Change Events</div>
  <div class="tab" onclick="switchTab('lookup')">Reverse Lookup</div>
</div>

<div class="main">

  <!-- ── FEED ── -->
  <div class="panel active" id="panel-feed">
    <div class="two-col">
      <div>
        <div class="section-head">New Today</div>
        <div id="new-today-list"><div class="loading">Loading</div></div>
      </div>
      <div>
        <div class="section-head">Dead Today</div>
        <div id="dead-today-list"><div class="loading">Loading</div></div>
      </div>
    </div>
    <div class="section-head">All Active Hosts</div>
    <div id="active-hosts-table"><div class="loading">Loading</div></div>
  </div>

  <!-- ── ASN ── -->
  <div class="panel" id="panel-asn">
    <div class="two-col">
      <div class="card">
        <div class="section-head">Top ASNs (active hosts)</div>
        <div class="chart-wrap-tall"><canvas id="asn-chart"></canvas></div>
      </div>
      <div class="card">
        <div class="section-head">Distribution</div>
        <div id="asn-bar-list"><div class="loading">Loading</div></div>
      </div>
    </div>
    <div class="section-head">ASN Table</div>
    <div id="asn-table"><div class="loading">Loading</div></div>
  </div>

  <!-- ── TIMELINE ── -->
  <div class="panel" id="panel-timeline">
    <div class="card" style="margin-bottom:1.5rem">
      <div class="section-head">Active Hosts per Day</div>
      <div class="chart-wrap-tall"><canvas id="tl-active-chart"></canvas></div>
    </div>
    <div class="two-col">
      <div class="card">
        <div class="section-head">New vs Dead per Day</div>
        <div class="chart-wrap"><canvas id="tl-diff-chart"></canvas></div>
      </div>
      <div class="card">
        <div class="section-head">ASN + Cert Changes</div>
        <div class="chart-wrap"><canvas id="tl-changes-chart"></canvas></div>
      </div>
    </div>
  </div>

  <!-- ── QUERIES ── -->
  <div class="panel" id="panel-queries">
    <div class="section-head">Query Performance — Hits over Time</div>
    <div id="query-list"><div class="loading">Loading</div></div>
  </div>

  <!-- ── CLUSTERS ── -->
  <div class="panel" id="panel-clusters">
    <div class="section-head">Shared SSL Certificates — Infrastructure Clusters</div>
    <div id="cluster-list"><div class="loading">Loading</div></div>
  </div>

  <!-- ── CHANGES ── -->
  <div class="panel" id="panel-changes">
    <div class="section-head">Change Events — new / dead / asn_changed / cert_changed</div>
    <div id="change-list"><div class="loading">Loading</div></div>
  </div>

  <!-- ── LOOKUP ── -->
  <div class="panel" id="panel-lookup">
    <div class="section-head">Reverse Lookup — Where does this IP come from?</div>
    <div class="lookup-box">
      <input id="lookup-ip" class="lookup-input" type="text"
             placeholder="Enter IP address, e.g. 45.137.66.61"
             onkeydown="if(event.key==='Enter') doLookup()">
      <button class="lookup-btn" onclick="doLookup()">▸ LOOKUP</button>
    </div>
    <div id="lookup-result"></div>
  </div>

</div>

<script>
// ── Tab Switching ──────────────────────────────────────────────────────────
const loaded = {};
function switchTab(name) {
  document.querySelectorAll('.tab').forEach((t,i) => {
    t.classList.toggle('active', ['feed','asn','timeline','queries','clusters','changes','lookup'][i] === name);
  });
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.getElementById('panel-' + name).classList.add('active');
  if (!loaded[name]) { loadPanel(name); loaded[name] = true; }
}

// ── Fetch helpers ──────────────────────────────────────────────────────────
async function api(path) {
  const r = await fetch(path);
  return r.json();
}

// ── Overview ──────────────────────────────────────────────────────────────
async function loadOverview() {
  const d = await api('/api/overview');
  document.getElementById('s-active').textContent = d.active ?? '–';
  document.getElementById('s-suspicious').textContent = d.suspicious ?? '–';
  document.getElementById('s-new').textContent = d.new_today ?? '–';
  document.getElementById('s-dead').textContent = d.dead_today ?? '–';
  document.getElementById('s-asn').textContent = d.asn_changes ?? '–';
  document.getElementById('s-cert').textContent = d.cert_changes ?? '–';
  const lr = d.last_run;
  document.getElementById('s-lastrun').textContent = lr?.run_date ?? '–';
  document.getElementById('last-updated').textContent = 'UPDATED: ' + (d.today ?? '');
}

// ── Badges ────────────────────────────────────────────────────────────────
function bph(v) { return v ? '<span class="badge badge-bph">⚠ BPH</span>' : ''; }
function escHtml(s) { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;'); }

// ── Panel Loader ──────────────────────────────────────────────────────────
async function loadPanel(name) {
  if (name === 'feed')     await loadFeed();
  if (name === 'asn')      await loadASN();
  if (name === 'timeline') await loadTimeline();
  if (name === 'queries')  await loadQueries();
  if (name === 'clusters') await loadClusters();
  if (name === 'changes')  await loadChanges();
}

// ── FEED ──────────────────────────────────────────────────────────────────
async function loadFeed() {
  const d = await api('/api/feed');

  // New today
  const nt = document.getElementById('new-today-list');
  if (!d.new_today?.length) { nt.innerHTML = '<div class="empty">No new hosts today</div>'; }
  else {
    nt.innerHTML = `<table class="data-table">
      <thead><tr><th>IP</th><th>ASN</th><th>Country</th><th>SSL CN</th><th>Source</th></tr></thead>
      <tbody>${d.new_today.map(h => `
        <tr>
          <td><span class="ip">${escHtml(h.ip)}</span> ${bph(h.is_suspicious)}</td>
          <td class="asn">AS${h.asn||'?'} ${escHtml(h.asn_name||'')}</td>
          <td>${h.country_code||'?'}</td>
          <td class="cn">${escHtml(h.ssl_cn||'n/a')}</td>
          <td class="cn">${escHtml(h.source_name||'')}</td>
        </tr>`).join('')}
      </tbody></table>`;
  }

  // Dead today
  const dt = document.getElementById('dead-today-list');
  if (!d.dead_today?.length) { dt.innerHTML = '<div class="empty">No hosts went dead today</div>'; }
  else {
    dt.innerHTML = `<table class="data-table">
      <thead><tr><th>IP</th><th>ASN</th><th>Country</th><th>Since</th></tr></thead>
      <tbody>${d.dead_today.map(h => `
        <tr>
          <td><span class="dead-ip">${escHtml(h.ip)}</span></td>
          <td class="asn">AS${h.asn||'?'} ${escHtml(h.asn_name||'')}</td>
          <td>${h.country_code||'?'}</td>
          <td class="cn">${h.first_seen||'?'}</td>
        </tr>`).join('')}
      </tbody></table>`;
  }

  // All active
  const at = document.getElementById('active-hosts-table');
  at.innerHTML = `<table class="data-table">
    <thead><tr><th>IP</th><th>ASN</th><th>Country</th><th>SSL CN</th><th>HTTP Server</th><th>Ports</th><th>Source</th><th>First Seen</th><th>Last Seen</th></tr></thead>
    <tbody>${d.active_hosts.map(h => `
      <tr>
        <td><span class="ip">${escHtml(h.ip)}</span> ${bph(h.is_suspicious)}</td>
        <td class="asn" style="font-size:11px">AS${h.asn||'?'}<br><span style="color:var(--textdim)">${escHtml(h.asn_name||'')}</span></td>
        <td>${h.country_code||'?'}</td>
        <td class="cn">${escHtml(h.ssl_cn||'–')}</td>
        <td class="cn" style="color:var(--blue)">${escHtml(h.http_server||'–')}</td>
        <td class="cn">${escHtml(h.open_ports||'–')}</td>
        <td class="cn">${escHtml(h.source_name||'–')}</td>
        <td class="cn">${h.first_seen||'–'}</td>
        <td class="cn">${h.last_seen||'–'}</td>
      </tr>`).join('')}
    </tbody></table>`;
}

// ── ASN ───────────────────────────────────────────────────────────────────
let asnChart = null;
async function loadASN() {
  const rows = await api('/api/asn');
  const top10 = rows.slice(0, 10);
  const max = Math.max(...rows.map(r => r.host_count), 1);

  // Bar list
  document.getElementById('asn-bar-list').innerHTML = rows.slice(0,15).map(r => `
    <div class="asn-row">
      <div class="asn-code" style="color:var(--textdim)">AS${r.asn}</div>
      <div class="asn-name">${escHtml(r.asn_name||'?')}</div>
      <div class="asn-bar-bg">
        <div class="asn-bar-fill ${r.suspicious_count ? 'bph' : ''}"
             style="width:${Math.round(r.host_count/max*100)}%"></div>
      </div>
      <div class="asn-count">${r.host_count}</div>
    </div>`).join('');

  // Chart
  if (asnChart) asnChart.destroy();
  const ctx = document.getElementById('asn-chart').getContext('2d');
  asnChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: top10.map(r => `AS${r.asn}`),
      datasets: [{
        label: 'Active Hosts',
        data: top10.map(r => r.host_count),
        backgroundColor: top10.map(r => r.suspicious_count
          ? 'rgba(255,171,0,0.6)' : 'rgba(0,230,118,0.5)'),
        borderColor: top10.map(r => r.suspicious_count
          ? 'rgba(255,171,0,1)' : 'rgba(0,230,118,1)'),
        borderWidth: 1,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#5a7a85', font: { family: 'Share Tech Mono', size: 10 } }, grid: { color: '#1a2e35' } },
        y: { ticks: { color: '#5a7a85', font: { family: 'Share Tech Mono', size: 10 } }, grid: { color: '#1a2e35' } }
      }
    }
  });

  // Table
  document.getElementById('asn-table').innerHTML = `<table class="data-table">
    <thead><tr><th>ASN</th><th>Name</th><th>Country</th><th>Hosts</th><th>BPH Flag</th><th>First Seen</th><th>Last Seen</th></tr></thead>
    <tbody>${rows.map(r => `
      <tr>
        <td class="asn">AS${r.asn}</td>
        <td>${escHtml(r.asn_name||'?')}</td>
        <td>${r.country_code||'?'}</td>
        <td><span style="color:var(--green)">${r.host_count}</span></td>
        <td>${r.suspicious_count ? '<span class="badge badge-bph">⚠ BPH</span>' : ''}</td>
        <td class="cn">${r.first_seen||'–'}</td>
        <td class="cn">${r.last_seen||'–'}</td>
      </tr>`).join('')}
    </tbody></table>`;
}

// ── TIMELINE ──────────────────────────────────────────────────────────────
let tlCharts = {};
async function loadTimeline() {
  const rows = await api('/api/timeline');
  if (!rows.length) {
    ['tl-active-chart','tl-diff-chart','tl-changes-chart'].forEach(id => {
      document.getElementById(id).parentElement.innerHTML = '<div class="empty">No timeline data yet — run the hunter daily to build history</div>';
    });
    return;
  }
  const labels = rows.map(r => r.run_date);
  const cfg = (data, color, label) => ({
    type: 'line',
    data: { labels, datasets: [{ label, data, borderColor: color,
      backgroundColor: color.replace('1)', '0.1)'), fill: true,
      tension: 0.3, pointRadius: 3, pointHoverRadius: 5 }] },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { color: '#5a7a85', font: { family: 'Share Tech Mono', size: 10 } } } },
      scales: {
        x: { ticks: { color: '#5a7a85', font: { family: 'Share Tech Mono', size: 9 }, maxRotation: 45 }, grid: { color: '#1a2e35' } },
        y: { ticks: { color: '#5a7a85', font: { family: 'Share Tech Mono', size: 10 } }, grid: { color: '#1a2e35' } }
      }
    }
  });

  if (tlCharts.active) tlCharts.active.destroy();
  tlCharts.active = new Chart(document.getElementById('tl-active-chart').getContext('2d'), {
    type: 'line',
    data: { labels, datasets: [{
      label: 'Active Hosts', data: rows.map(r => r.total_found),
      borderColor: 'rgba(0,230,118,1)', backgroundColor: 'rgba(0,230,118,0.08)',
      fill: true, tension: 0.3, pointRadius: 3
    }]},
    options: cfg([], '', '').options
  });

  if (tlCharts.diff) tlCharts.diff.destroy();
  tlCharts.diff = new Chart(document.getElementById('tl-diff-chart').getContext('2d'), {
    type: 'bar',
    data: { labels, datasets: [
      { label: 'New', data: rows.map(r => r.new_hosts), backgroundColor: 'rgba(0,230,118,0.6)' },
      { label: 'Dead', data: rows.map(r => -r.dead_hosts), backgroundColor: 'rgba(255,61,61,0.6)' }
    ]},
    options: { responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { color: '#5a7a85', font: { family: 'Share Tech Mono', size: 10 } } } },
      scales: {
        x: { stacked: true, ticks: { color: '#5a7a85', font: { family: 'Share Tech Mono', size: 9 } }, grid: { color: '#1a2e35' } },
        y: { stacked: true, ticks: { color: '#5a7a85', font: { family: 'Share Tech Mono', size: 10 } }, grid: { color: '#1a2e35' } }
      }
    }
  });

  if (tlCharts.changes) tlCharts.changes.destroy();
  tlCharts.changes = new Chart(document.getElementById('tl-changes-chart').getContext('2d'), {
    type: 'bar',
    data: { labels, datasets: [
      { label: 'ASN Changes', data: rows.map(r => r.asn_changes), backgroundColor: 'rgba(41,182,246,0.6)' },
      { label: 'Cert Changes', data: rows.map(r => r.cert_changes), backgroundColor: 'rgba(255,171,0,0.6)' }
    ]},
    options: { responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { color: '#5a7a85', font: { family: 'Share Tech Mono', size: 10 } } } },
      scales: {
        x: { ticks: { color: '#5a7a85', font: { family: 'Share Tech Mono', size: 9 } }, grid: { color: '#1a2e35' } },
        y: { ticks: { color: '#5a7a85', font: { family: 'Share Tech Mono', size: 10 } }, grid: { color: '#1a2e35' } }
      }
    }
  });
}

// ── QUERIES ───────────────────────────────────────────────────────────────
async function loadQueries() {
  const d = await api('/api/queries');
  const summary = d.summary || [];
  const maxHits = Math.max(...summary.map(q => q.total_hits), 1);

  if (!summary.length) {
    document.getElementById('query-list').innerHTML = '<div class="empty">No query data yet — runs after first daily execution</div>';
    return;
  }

  document.getElementById('query-list').innerHTML = summary.map(q => `
    <div class="qperf-row">
      <div class="qperf-top">
        <div class="qperf-name">${escHtml(q.query_name)}</div>
        <div class="qperf-cat">[${escHtml(q.category||'generic')}]</div>
        <div class="qperf-nums">
          <div class="qperf-num"><span class="n">${q.total_hits}</span><span class="l">Total Hits</span></div>
          <div class="qperf-num"><span class="n" style="color:var(--green)">${q.total_new}</span><span class="l">New IPs</span></div>
          <div class="qperf-num"><span class="n" style="color:var(--blue)">${q.days_run}</span><span class="l">Days Run</span></div>
          <div class="qperf-num"><span class="n" style="color:var(--textdim)">${q.peak_hits}</span><span class="l">Peak</span></div>
        </div>
      </div>
      <div class="qperf-query">▸ ${escHtml(q.query_str||'')}</div>
      <div class="qperf-bar-bg">
        <div class="qperf-bar-fill" style="width:${Math.round(q.total_hits/maxHits*100)}%"></div>
      </div>
    </div>`).join('');
}

// ── CLUSTERS ──────────────────────────────────────────────────────────────
async function loadClusters() {
  const rows = await api('/api/ssl_clusters');
  if (!rows.length) {
    document.getElementById('cluster-list').innerHTML = '<div class="empty">No shared certificates found — clusters appear when multiple hosts share the same SSL fingerprint</div>';
    return;
  }
  document.getElementById('cluster-list').innerHTML = rows.map(r => `
    <div class="cluster-card">
      <div class="cluster-count">${r.host_count}</div>
      <div class="cluster-cn">${escHtml(r.ssl_cn||'(no CN)')} ${r.ssl_is_selfsig ? '<span class="badge badge-bph">self-signed</span>' : ''}</div>
      <div class="cluster-fp">SHA256: ${escHtml(r.ssl_fingerprint||'')}</div>
      <div class="cluster-ips">IPs: ${escHtml(r.ips||'')}</div>
      <div style="font-family:var(--mono);font-size:10px;color:var(--textdim);margin-top:4px">First seen: ${r.first_seen||'?'}</div>
    </div>`).join('');
}

// ── CHANGES ───────────────────────────────────────────────────────────────
async function loadChanges() {
  const rows = await api('/api/changes');
  const badge = t => {
    if (t==='new') return '<span class="badge badge-new">new</span>';
    if (t==='dead') return '<span class="badge badge-dead">dead</span>';
    if (t==='asn_changed') return '<span class="badge badge-asn">asn ⇄</span>';
    if (t==='cert_changed') return '<span class="badge badge-cert">cert ⇄</span>';
    if (t==='reactivated') return '<span class="badge badge-new">↩ back</span>';
    return t;
  };
  document.getElementById('change-list').innerHTML = rows.map(r => `
    <div class="change-item">
      <span class="change-date">${r.event_date||'?'}</span>
      <span class="change-ip" onclick="gotoLookup('${escHtml(r.ip)}')">${escHtml(r.ip)}</span>
      ${badge(r.event_type)}
      <span class="change-detail">${escHtml(r.detail||r.old_value||'')} ${r.new_value ? '→ '+escHtml(r.new_value) : ''}</span>
      <span style="font-family:var(--mono);font-size:10px;color:var(--textdim)">${r.country_code||''}</span>
    </div>`).join('');
}

// ── LOOKUP ────────────────────────────────────────────────────────────────
function gotoLookup(ip) {
  switchTab('lookup');
  loaded['lookup'] = true;
  document.getElementById('lookup-ip').value = ip;
  doLookup();
}

async function doLookup() {
  const ip = document.getElementById('lookup-ip').value.trim();
  if (!ip) return;
  const el = document.getElementById('lookup-result');
  el.innerHTML = '<div class="loading">Querying</div>';
  el.className = 'lookup-result visible';

  const d = await api(`/api/lookup/${encodeURIComponent(ip)}`);
  if (!d.found) {
    el.innerHTML = `<div class="not-found">❌ ${escHtml(ip)} not found in database.<br>
      <span style="color:var(--textdim);font-size:11px">Either not captured by any query, or never seen by the hunter.</span></div>`;
    return;
  }

  const h = d.host;
  const statusColor = h.status === 'active' ? 'var(--green)' : 'var(--red)';
  const suspBadge = h.is_suspicious ? '<span class="badge badge-bph">⚠ BPH-ASN</span>' : '';

  let html = `
    <div style="display:flex;align-items:center;gap:1rem;margin-bottom:1.25rem">
      <span style="font-family:var(--mono);font-size:22px;color:var(--green2)">${escHtml(ip)}</span>
      <span style="font-family:var(--mono);font-size:13px;color:${statusColor}">${h.status?.toUpperCase()}</span>
      ${suspBadge}
    </div>
    <div class="lr-grid">
      <div>
        <div class="lr-group"><div class="lr-key">First Seen</div><div class="lr-val highlight">${h.first_seen||'?'}</div></div>
        <div class="lr-group"><div class="lr-key">Last Seen</div><div class="lr-val">${h.last_seen||'?'}</div></div>
        <div class="lr-group"><div class="lr-key">ASN</div><div class="lr-val highlight">AS${h.asn||'?'} — ${escHtml(h.asn_name||'?')}</div></div>
        <div class="lr-group"><div class="lr-key">Country</div><div class="lr-val">${escHtml(h.country_name||'?')} (${h.country_code||'?'})</div></div>
        <div class="lr-group"><div class="lr-key">City / Org</div><div class="lr-val">${escHtml(h.city||'?')} / ${escHtml(h.org||'?')}</div></div>
      </div>
      <div>
        <div class="lr-group"><div class="lr-key">SSL CN</div><div class="lr-val highlight">${escHtml(h.ssl_cn||'n/a')}</div></div>
        <div class="lr-group"><div class="lr-key">SSL Issuer</div><div class="lr-val">${escHtml(h.ssl_issuer_cn||'n/a')}</div></div>
        <div class="lr-group"><div class="lr-key">Self-signed</div><div class="lr-val ${h.ssl_is_selfsig ? 'warn' : ''}">${h.ssl_is_selfsig ? 'YES' : 'No'}</div></div>
        <div class="lr-group"><div class="lr-key">SSL Fingerprint</div><div class="lr-val cn" style="font-size:10px;word-break:break-all">${escHtml(h.ssl_fingerprint||'n/a')}</div></div>
      </div>
      <div>
        <div class="lr-group"><div class="lr-key">HTTP Server</div><div class="lr-val highlight">${escHtml(h.http_server||'n/a')}</div></div>
        <div class="lr-group"><div class="lr-key">Open Ports</div><div class="lr-val">${JSON.stringify(h.open_ports||[])}</div></div>
        <div class="lr-group"><div class="lr-key">Discovered By</div><div class="lr-val highlight">${escHtml(h.source_name||'?')}</div></div>
        <div class="lr-group"><div class="lr-key">Query</div><div class="lr-val cn" style="font-size:10px">${escHtml(h.source_query||'?')}</div></div>
      </div>
    </div>`;

  // ASN history
  if (d.asn_history?.length > 1) {
    html += `<div class="section-head" style="margin-top:1rem">ASN Migration History</div>
      <table class="data-table" style="margin-bottom:1rem">
        <thead><tr><th>ASN</th><th>Name</th><th>First Seen</th><th>Last Seen</th></tr></thead>
        <tbody>${d.asn_history.map(r => `
          <tr><td class="asn">AS${r.asn}</td><td>${escHtml(r.asn_name||'')}</td><td class="cn">${r.first_seen}</td><td class="cn">${r.last_seen}</td></tr>
        `).join('')}</tbody>
      </table>`;
  }

  // SSL Cluster
  if (d.ssl_cluster?.length) {
    html += `<div class="section-head" style="margin-top:1rem">🔗 SSL Cluster — ${d.ssl_cluster.length} other host(s) share the same certificate</div>
      <table class="data-table" style="margin-bottom:1rem">
        <thead><tr><th>IP</th><th>ASN</th><th>Country</th><th>First Seen</th><th>Status</th></tr></thead>
        <tbody>${d.ssl_cluster.map(r => `
          <tr>
            <td><span class="ip" style="cursor:pointer" onclick="gotoLookup('${escHtml(r.ip)}')">${escHtml(r.ip)}</span></td>
            <td class="cn">${escHtml(r.asn_name||'')}</td>
            <td>${r.country_code||'?'}</td>
            <td class="cn">${r.first_seen||'?'}</td>
            <td>${r.status==='active' ? '<span class="badge badge-new">active</span>' : '<span class="badge badge-dead">dead</span>'}</td>
          </tr>`).join('')}
        </tbody>
      </table>`;
  }

  // Change events
  if (d.events?.length) {
    html += `<div class="section-head" style="margin-top:1rem">Change Events</div>
      <table class="data-table">
        <thead><tr><th>Date</th><th>Type</th><th>Detail</th></tr></thead>
        <tbody>${d.events.map(e => `
          <tr>
            <td class="cn">${e.event_date}</td>
            <td>${e.event_type}</td>
            <td class="cn">${escHtml(e.detail||'')} ${e.old_value ? escHtml(e.old_value)+'→'+escHtml(e.new_value||'') : ''}</td>
          </tr>`).join('')}
        </tbody>
      </table>`;
  }

  el.innerHTML = html;
}

// ── Init ──────────────────────────────────────────────────────────────────
loadOverview();
loadPanel('feed');
loaded['feed'] = true;

// Auto-refresh overview every 5 minutes
setInterval(loadOverview, 5 * 60 * 1000);
</script>
</body>
</html>"""


@app.route("/")
def index():
    return render_template_string(TEMPLATE)


if __name__ == "__main__":
    if not DB_PATH.exists():
        print(f"⚠  Datenbank nicht gefunden: {DB_PATH}")
        print("   Erst ns_hunter.py laufen lassen.")
    else:
        print(f"✓  DB: {DB_PATH}")
    print("▸  Dashboard: http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
