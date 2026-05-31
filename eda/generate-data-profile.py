"""
generate_cyber_dashboard.py
============================
Generates a fully interactive, self-contained HTML cybersecurity
threat intelligence dashboard from a CSV file.

Expected CSV columns (Global_Cybersecurity_Threats_2015-2024.csv format):
  Country, Year, Attack Type, Target Industry,
  Financial Loss (in Million $)
  Attack Source, Security Vulnerability Type,
  Defense Mechanism Used, Incident Resolution Time (in Hours)

Usage:
  python generate-data-profile.py  ../data/raw/Global_Cybersecurity_Threats_2015-2024.csv

The output is a single self-contained HTML file. No server needed —
open it directly in any browser.
"""

import csv
import json
import os
import random
import sys
from collections import defaultdict
from datetime import datetime, timedelta
 
# ─── Configuration ──────────────────────────────────────────────────────────
CSV_FILENAME    = "Global_Cybersecurity_Threats_2015-2024.csv"
OUTPUT_FILENAME = "dashboard.html"
RANDOM_SEED     = 42   # reproducible synthetic fields
 
COUNTRY_FLAGS = {
    "Australia": "🇦🇺", "Brazil": "🇧🇷", "China": "🇨🇳",
    "France":    "🇫🇷", "Germany":"🇩🇪", "India": "🇮🇳",
    "Japan":     "🇯🇵", "Russia": "🇷🇺", "UK":    "🇬🇧", "USA": "🇺🇸",
}
COUNTRY_COORDS = {
    "Australia": [-25.27, 133.78], "Brazil":  [-14.24, -51.93],
    "China":     [ 35.86, 104.20], "France":  [ 46.23,   2.21],
    "Germany":   [ 51.17,  10.45], "India":   [ 20.59,  78.96],
    "Japan":     [ 36.20, 138.25], "Russia":  [ 61.52, 105.32],
    "UK":        [ 55.38,  -3.44], "USA":     [ 37.09, -95.71],
}
 
 
# ─── Data-processing helpers ─────────────────────────────────────────────────
 
def quartiles(vals):
    """Return (Q25, Q50, Q75) of a numeric list."""
    s = sorted(vals)
    n = len(s)
    if n == 0:
        return 0.0, 0.0, 0.0
    return s[n // 4], s[n // 2], s[3 * n // 4]
 
 
def severity_from_loss(loss, q25, q50, q75):
    """Map financial-loss value to a severity label using quartile thresholds."""
    if loss >= q75:
        return "Critical"
    if loss >= q50:
        return "High"
    if loss >= q25:
        return "Medium"
    return "Low"
 
 
def compute_cvss(loss, users, max_loss, max_users):
    """Derive a CVSS-style score 0–10 from financial impact + user scope."""
    ls = (loss  / max_loss  * 6.0) if max_loss  else 0.0
    us = (users / max_users * 4.0) if max_users else 0.0
    return round(min(10.0, ls + us), 1)
 
 
def fake_timestamp(year_str, seq):
    """Generate a plausible datetime string spread across the given year."""
    y = int(year_str) if year_str.isdigit() else 2020
    doy = (seq * 17 + seq // 6) % 365
    dt  = datetime(y, 1, 1) + timedelta(
        days=doy, hours=(seq * 7) % 24, minutes=(seq * 13) % 60)
    return dt.strftime("%Y-%m-%d %H:%M")
 
 
def status_from_hours(hours):
    """Classify incident status by resolution time."""
    if hours > 72:
        return "Resolved"
    if hours > 24:
        return "Contained"
    return "Active"
 
 
def dark_web_count(sev, seed):
    """Generate synthetic dark-web mention count weighted by severity."""
    random.seed(seed)
    ranges = {"Critical": (50, 200), "High": (10, 60),
              "Medium": (2, 15), "Low": (0, 5)}
    lo, hi = ranges.get(sev, (0, 3))
    return random.randint(lo, hi)
 
 
# ─── CSV Reader ──────────────────────────────────────────────────────────────
 
def read_csv(path):
    """Read, validate, sanitize and enrich the CSV.  Returns a list of dicts."""
    if not os.path.exists(path):
        print(f"[ERROR] CSV file not found: '{path}'")
        sys.exit(1)
 
    raw = []
    with open(path, encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            print("[ERROR] CSV file is empty or has no header row.")
            sys.exit(1)
 
        for i, row in enumerate(reader):
            def sf(k, default="Unknown"):
                v = (row.get(k) or "").strip()
                return v if v else default
            def nf(k):
                try: return float(row.get(k) or 0)
                except (ValueError, TypeError): return 0.0
            def ni(k):
                try: return int(float(row.get(k) or 0))
                except (ValueError, TypeError): return 0
 
            raw.append({
                "idx":      i,
                "country":  sf("Country"),
                "year":     sf("Year", "2020"),
                "type":     sf("Attack Type"),
                "industry": sf("Target Industry"),
                "loss":     nf("Financial Loss (in Million $)"),
                "users":    ni("Number of Affected Users"),
                "source":   sf("Attack Source"),
                "vuln":     sf("Security Vulnerability Type"),
                "defense":  sf("Defense Mechanism Used"),
                "res":      ni("Incident Resolution Time (in Hours)"),
            })
 
    if not raw:
        print("[ERROR] No valid rows found in CSV.")
        sys.exit(1)
 
    print(f"[INFO] Loaded {len(raw)} rows from '{path}'")
 
    losses    = [r["loss"]  for r in raw]
    users_all = [r["users"] for r in raw]
    q25, q50, q75 = quartiles(losses)
    max_loss  = max(losses)    if losses    else 1.0
    max_users = max(users_all) if users_all else 1
 
    year_seq = defaultdict(int)
    out = []
    random.seed(RANDOM_SEED)
 
    for r in raw:
        seq = year_seq[r["year"]]
        year_seq[r["year"]] += 1
 
        sev  = severity_from_loss(r["loss"], q25, q50, q75)
        coords = COUNTRY_COORDS.get(r["country"], [0.0, 0.0])
 
        out.append({
            "ts":       fake_timestamp(r["year"], seq),
            "year":     r["year"],
            "country":  r["country"],
            "flag":     COUNTRY_FLAGS.get(r["country"], "🌐"),
            "lat":      coords[0],
            "lng":      coords[1],
            "type":     r["type"],
            "industry": r["industry"],
            "loss":     round(r["loss"], 2),
            "users":    r["users"],
            "source":   r["source"],
            "vuln":     r["vuln"],
            "defense":  r["defense"],
            "res":      r["res"],
            "severity": sev,
            "cvss":     compute_cvss(r["loss"], r["users"], max_loss, max_users),
            "status":   status_from_hours(r["res"]),
            "dw":       dark_web_count(sev, r["idx"] * 31 + 7),
        })
 
    return out
 
 
# ─── HTML Template ───────────────────────────────────────────────────────────
TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Global Cyber Threat Intelligence Dashboard</title>
 
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
  <link rel="stylesheet" href="https://cdn.datatables.net/1.13.7/css/dataTables.bootstrap5.min.css">
  <link rel="stylesheet" href="https://cdn.datatables.net/buttons/2.4.2/css/buttons.bootstrap5.min.css">
 
<style>
/* ══════════════════════════════════════════════════════
   THEME TOKENS
   ══════════════════════════════════════════════════════ */
:root {
  --bg0:      #05080f;
  --bg1:      #090e1c;
  --bg2:      #0c1425;
  --bgcard:   #0f1a2e;
  --cyan:     #00f5ff;
  --cyandim:  #00c5cc;
  --cyanglow: rgba(0,245,255,.14);
  --green:    #39ff14;
  --magenta:  #d958f7;
  --crit:     #ff2d55;
  --high:     #ff6b35;
  --medium:   #ffd60a;
  --low:      #30d158;
  --amber:    #f59e0b;
  --txt1:     #dde6f5;
  --txt2:     #7f8faa;
  --txt3:     #3d4f68;
  --border:   rgba(0,245,255,.12);
  --borderbr: rgba(0,245,255,.38);
  --fdisplay: 'Orbitron',  monospace;
  --fmono:    'Share Tech Mono', monospace;
  --fui:      'Rajdhani',  sans-serif;
  --r:        8px;
  --rl:       12px;
  --shadowc:  0 0 22px rgba(0,245,255,.22);
  --shadowcard: 0 6px 28px rgba(0,0,0,.55);
}
 
/* ══════════════════════════════════════════════════════
   BASE
   ══════════════════════════════════════════════════════ */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
 
body {
  background-color: var(--bg0);
  background-image:
    linear-gradient(rgba(0,245,255,.025) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,245,255,.025) 1px, transparent 1px);
  background-size: 44px 44px;
  color: var(--txt1);
  font-family: var(--fui);
  font-size: 14px;
  line-height: 1.55;
  overflow-x: hidden;
}
 
/* ══════════════════════════════════════════════════════
   HEADER
   ══════════════════════════════════════════════════════ */
.dash-header {
  background: linear-gradient(135deg, var(--bg1) 0%, var(--bg2) 100%);
  border-bottom: 1px solid var(--borderbr);
  box-shadow: 0 0 50px rgba(0,245,255,.09);
  padding: 14px 26px;
  position: sticky; top: 0; z-index: 1100;
  display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;
}
.h-brand { display: flex; align-items: center; gap: 14px; }
.h-icon { font-size: 26px; color: var(--cyan); filter: drop-shadow(0 0 8px var(--cyan)); }
.h-title { font-family: var(--fdisplay); font-size: 17px; font-weight: 700;
  color: var(--cyan); text-shadow: 0 0 18px rgba(0,245,255,.45);
  letter-spacing: 2px; text-transform: uppercase; line-height: 1.2; }
.h-sub { font-family: var(--fdisplay); font-size: 9px; color: var(--txt3);
  letter-spacing: 3px; display: block; text-transform: uppercase; }
.h-right { display: flex; align-items: center; gap: 20px; }
.live-ind { display: inline-flex; align-items: center; gap: 7px;
  font-family: var(--fmono); font-size: 11px; color: var(--txt3); }
.live-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--txt3); }
.live-ind.on .live-dot { background: var(--green); box-shadow: 0 0 8px var(--green); animation: pulse 1.1s infinite; }
.live-ind.on { color: var(--green); }
@keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.55;transform:scale(1.25)} }
.clock { font-family: var(--fmono); font-size: 22px; color: var(--green);
  text-shadow: 0 0 10px rgba(57,255,20,.45); letter-spacing: 2px; }
.loadts { font-family: var(--fmono); font-size: 10px; color: var(--txt3); text-align: right; }
.loadts span { color: var(--cyandim); }
 
/* ══════════════════════════════════════════════════════
   MAIN LAYOUT & FILTERS
   ══════════════════════════════════════════════════════ */
.dash-main { padding: 18px 24px; max-width: 1920px; margin: 0 auto; }
 
.fbar {
  background: var(--bgcard); border: 1px solid var(--border); border-radius: var(--rl);
  padding: 14px 18px; margin-bottom: 18px;
  display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-end;
}
.fbarlabel { font-family: var(--fmono); font-size: 11px; color: var(--cyan);
  text-transform: uppercase; letter-spacing: 2px; white-space: nowrap;
  align-self: center; border-right: 1px solid var(--border); padding-right: 14px; }
.fg { display: flex; flex-direction: column; gap: 3px; min-width: 130px; }
.fg label { font-size: 9px; color: var(--txt3); font-family: var(--fmono);
  text-transform: uppercase; letter-spacing: 1px; }
.fsel {
  background: var(--bg1); border: 1px solid var(--border); border-radius: var(--r);
  color: var(--txt1); font-family: var(--fui); font-size: 13px; padding: 6px 10px;
  transition: border-color .18s, box-shadow .18s; width: 100%;
}
.fsel:focus { border-color: var(--cyan); box-shadow: 0 0 8px var(--cyanglow); outline: none; }
.fsel option { background: var(--bg2); }
 
/* ── Multi-select dropdown ── */
.msel { position: relative; min-width: 130px; }
.msel-btn {
  background: var(--bg1); border: 1px solid var(--border); border-radius: var(--r);
  color: var(--txt1); font-family: var(--fui); font-size: 13px; padding: 6px 10px;
  transition: border-color .18s, box-shadow .18s; width: 100%;
  text-align: left; cursor: pointer; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  display: flex; align-items: center; justify-content: space-between; gap: 6px;
}
.msel-btn::after { content: '▾'; font-size: 10px; color: var(--txt3); flex-shrink: 0; transition: transform .18s; }
.msel-btn.open { border-color: var(--cyan); box-shadow: 0 0 8px var(--cyanglow); outline: none; }
.msel-btn.open::after { transform: rotate(180deg); }
.msel-panel {
  display: none; position: absolute; top: calc(100% + 4px); left: 0; z-index: 2000;
  background: var(--bg2); border: 1px solid var(--borderbr); border-radius: var(--r);
  min-width: 100%; max-height: 220px; overflow-y: auto;
  box-shadow: 0 8px 24px rgba(0,0,0,.65);
}
.msel-panel.open { display: block; }
.msel-item {
  display: flex; align-items: center; gap: 9px;
  padding: 7px 12px; cursor: pointer; font-family: var(--fui); font-size: 13px;
  color: var(--txt1); transition: background .12s; user-select: none;
}
.msel-item:hover { background: var(--cyanglow); }
.msel-item input[type="checkbox"] { accent-color: var(--cyan); width: 13px; height: 13px; cursor: pointer; flex-shrink: 0; }
.msel-count { display: inline-block; background: var(--cyan); color: #000;
  font-size: 10px; font-family: var(--fmono); font-weight: 700;
  padding: 1px 5px; border-radius: 3px; flex-shrink: 0; }
 
.factions { display: flex; gap: 8px; }
.btn-cyber {
  background: transparent; border: 1px solid var(--cyan); border-radius: var(--r);
  color: var(--cyan); font-family: var(--fmono); font-size: 11px; letter-spacing: 1px;
  padding: 7px 14px; cursor: pointer; text-transform: uppercase; transition: all .2s; white-space: nowrap;
}
.btn-cyber:hover { background: var(--cyanglow); box-shadow: var(--shadowc); }
.btn-cyber.btn-reset { border-color: var(--txt3); color: var(--txt2); }
.btn-cyber.btn-reset:hover { border-color: var(--cyan); color: var(--cyan); background: var(--cyanglow); }
.btn-live.on { background: rgba(57,255,20,.14); border-color: var(--green); color: var(--green); box-shadow: 0 0 14px rgba(57,255,20,.28); }
 
/* ══════════════════════════════════════════════════════
   SUMMARY CARDS
   ══════════════════════════════════════════════════════ */
.cards { display: grid; grid-template-columns: repeat(6,1fr); gap: 14px; margin-bottom: 18px; }
@media(max-width:1400px){.cards{grid-template-columns:repeat(3,1fr)}}
@media(max-width:800px) {.cards{grid-template-columns:repeat(2,1fr)}}
 
.scard {
  background: var(--bgcard); border: 1px solid var(--border); border-radius: var(--rl);
  padding: 18px 20px; position: relative; overflow: hidden;
  transition: transform .2s, box-shadow .2s, border-color .2s; cursor: default;
}
.scard::before {
  content:''; position:absolute; top:0; left:0; right:0; height:2px;
  background: linear-gradient(90deg, transparent, var(--cac, var(--cyan)), transparent);
}
.scard:hover { border-color: var(--borderbr); box-shadow: var(--shadowcard), var(--shadowc); transform: translateY(-2px); }
.ci { font-size: 22px; margin-bottom: 10px; opacity: .85; }
.clabel { font-family: var(--fmono); font-size: 9px; color: var(--txt3); text-transform: uppercase; letter-spacing: 2px; margin-bottom: 5px; }
.cval { font-family: var(--fdisplay); font-size: 30px; font-weight: 700; color: var(--txt1); line-height: 1; transition: all .35s; }
.csub { font-family: var(--fmono); font-size: 10px; color: var(--txt3); margin-top: 5px; }
 
.sc-total    { --cac: var(--cyan); }
.sc-critical { --cac: var(--crit); } .sc-critical .cval { color: var(--crit); text-shadow: 0 0 12px rgba(255,45,85,.35); }
.sc-loss     { --cac: var(--amber); } .sc-loss .cval { color: var(--amber); }
.sc-countries{ --cac: var(--medium); }
.sc-actors   { --cac: var(--magenta); }
.sc-cvss     { --cac: var(--high); } .sc-cvss .cval { color: var(--high); }
 
/* ══════════════════════════════════════════════════════
   CHART PANELS
   ══════════════════════════════════════════════════════ */
.cpanel {
  background: var(--bgcard); border: 1px solid var(--border); border-radius: var(--rl); padding: 18px;
}
.ptitle {
  font-family: var(--fdisplay); font-size: 11px; font-weight: 700; color: var(--cyan);
  text-transform: uppercase; letter-spacing: 2px; margin-bottom: 14px;
  display: flex; align-items: center; gap: 8px;
}
.ptitle::after { content:''; flex:1; height:1px; background:var(--border); }
.cc { position: relative; }
 
/* Layout rows */
.grid-main   { display: grid; grid-template-columns: 1fr 370px; gap: 14px; margin-bottom: 14px; }
.grid-side   { display: flex; flex-direction: column; gap: 14px; }
.grid-mid    { display: grid; grid-template-columns: 2fr 1.1fr; gap: 14px; margin-bottom: 14px; }
.grid-finance{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-bottom: 14px; }
/* Modified grid-bot: three columns for financial heatmap, attack sources, count heatmap */
.grid-bot    { display: grid; grid-template-columns: 2fr 1fr 1.2fr; gap: 14px; margin-bottom: 18px; }
 
@media(max-width:1300px){
  .grid-main{grid-template-columns:1fr;}
  .grid-mid{grid-template-columns:1fr;}
  .grid-finance{grid-template-columns:1fr;}
  .grid-bot{grid-template-columns:1fr;}  /* stack vertically on narrow screens */
}
 
/* Map */
#mapWrap { height: 420px; border-radius: var(--r); overflow: hidden; border: 1px solid var(--border); }
.leaflet-container { background: #05080f !important; }
.leaflet-popup-content-wrapper {
  background: var(--bgcard) !important; border: 1px solid var(--borderbr) !important;
  border-radius: var(--r) !important; color: var(--txt1) !important;
  font-family: var(--fui) !important; box-shadow: var(--shadowc) !important;
}
.leaflet-popup-tip { background: var(--bgcard) !important; }
.mpop h4 { font-family: var(--fdisplay); font-size: 12px; color: var(--cyan); margin-bottom: 6px; }
.mpop table { width:100%; font-family: var(--fmono); font-size: 11px; }
.mpop td { padding: 2px 4px; }
.mpop td:first-child { color: var(--txt3); }
.mpop td:last-child  { color: var(--txt1); text-align: right; }
 
/* Heatmaps */
.hmtable { width: 100%; border-collapse: separate; border-spacing: 3px; font-family: var(--fmono); font-size: 11px; }
.hmtable th { color: var(--txt3); font-weight: 400; padding: 3px 5px; text-align: center; white-space: nowrap; font-size: 10px; }
.hmtable td { border-radius: 4px; padding: 7px 3px; text-align: center; font-weight: 600; transition: transform .15s; cursor: default; min-width: 42px; }
.hmtable td:hover { transform: scale(1.1); z-index: 1; position: relative; }
.hmtable .rlabel { color: var(--txt2); text-align: right; padding-right: 8px; white-space: nowrap; font-weight: 400; font-size: 10px; }
 
/* Datatables */
.tsection { background: var(--bgcard); border: 1px solid var(--border); border-radius: var(--rl); padding: 18px; margin-bottom: 18px; }
.dataTables_wrapper { color: var(--txt1); }
.dataTables_filter input, .dataTables_length select { background: var(--bg1) !important; border: 1px solid var(--border) !important; color: var(--txt1) !important; border-radius: var(--r) !important; padding: 4px 8px !important; }
.dataTables_filter label, .dataTables_length label, .dataTables_info { color: var(--txt2) !important; font-family: var(--fmono) !important; font-size: 12px !important; }
table.dataTable { border-collapse: separate !important; border-spacing: 0 2px !important; }
table.dataTable thead th { background: var(--bg2) !important; border-bottom: 1px solid var(--border) !important; color: var(--cyan) !important; font-family: var(--fmono) !important; font-size: 10px !important; text-transform: uppercase !important; letter-spacing: 1px !important; white-space: nowrap; }
table.dataTable tbody tr { background: var(--bg1) !important; transition: background .12s; }
table.dataTable tbody tr:hover td { background: var(--bg2) !important; }
table.dataTable tbody td { border-bottom: 1px solid rgba(255,255,255,.028) !important; color: var(--txt1) !important; font-family: var(--fui) !important; font-size: 12px !important; vertical-align: middle !important; background-color: transparent !important; box-shadow: none !important; }
table.dataTable tbody tr.row-crit td  { background: rgba(255,45,85,.07)  !important; }
table.dataTable tbody tr.row-high td  { background: rgba(255,107,53,.055) !important; }
.dataTables_paginate .page-link { background: var(--bg2) !important; border-color: var(--border) !important; color: var(--txt2) !important; }
.dataTables_paginate .page-item.active .page-link { background: var(--cyan) !important; border-color: var(--cyan) !important; color: #000 !important; }
.dt-buttons .btn { background: transparent !important; border: 1px solid var(--border) !important; color: var(--txt2) !important; font-family: var(--fmono) !important; font-size: 11px !important; }
.dt-buttons .btn:hover { border-color: var(--cyan) !important; color: var(--cyan) !important; }
 
/* Badges */
.sbadge { font-family: var(--fmono); font-size: 10px; padding: 2px 7px; border-radius: 3px; font-weight: 600; letter-spacing: 1px; white-space: nowrap; }
.s-Critical{ background:rgba(255,45,85,.18); color:var(--crit);   border:1px solid var(--crit); }
.s-High    { background:rgba(255,107,53,.18);color:var(--high);   border:1px solid var(--high); }
.s-Medium  { background:rgba(255,214,10,.18); color:var(--medium);border:1px solid var(--medium); }
.s-Low     { background:rgba(48,209,88,.18);  color:var(--low);   border:1px solid var(--low); }
.stbadge { font-family: var(--fmono); font-size: 10px; padding: 1px 6px; border-radius: 3px; }
.st-Active    { color:var(--crit); }
.st-Contained { color:var(--medium); }
.st-Resolved  { color:var(--low); }
 
/* Ticker */
.ticker {
  background: var(--bgcard); border: 1px solid rgba(255,45,85,.28); border-radius: var(--r);
  padding: 9px 16px; margin-top: 4px; display: flex; align-items: center; gap: 14px; overflow: hidden;
}
.ticklabel { font-family: var(--fmono); font-size: 10px; color: var(--crit);
  text-transform: uppercase; letter-spacing: 2px; white-space: nowrap;
  border-right: 1px solid var(--border); padding-right: 14px; flex-shrink: 0;
  animation: blink 1.6s infinite; }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:.35} }
.tickscroll { overflow: hidden; flex: 1; }
.tickinner { display: flex; gap: 56px; white-space: nowrap; animation: scrolll 35s linear infinite; }
@keyframes scrolll { from{transform:translateX(0)} to{transform:translateX(-50%)} }
.tickitem { font-family: var(--fmono); font-size: 12px; color: var(--txt2); flex-shrink: 0; }
.tickitem strong { color: var(--crit); }
 
.nodata { display:flex; flex-direction:column; align-items:center; justify-content:center;
  height:160px; color:var(--txt3); font-family:var(--fmono); font-size:13px; gap:10px; }
.nodata i { font-size:28px; }
 
/* ══════════════════════════════════════════════════════
   INTELLIGENCE FINDINGS
   ══════════════════════════════════════════════════════ */
.insights-panel {
  display: grid;
  grid-template-columns: repeat(8, 1fr);
  gap: 10px;
  margin-bottom: 18px;
}
@media(max-width:1600px){ .insights-panel{ grid-template-columns: repeat(4,1fr); } }
@media(max-width:1000px){ .insights-panel{ grid-template-columns: repeat(2,1fr); } }
 
.insight-card {
  background: var(--bgcard);
  border: 1px solid var(--border);
  border-radius: var(--rl);
  padding: 13px 15px;
  display: flex; flex-direction: column; gap: 5px;
  position: relative; overflow: hidden;
  transition: border-color .2s, box-shadow .2s;
}
.insight-card::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
  background: linear-gradient(90deg, transparent, var(--ic-ac, var(--cyan)), transparent);
}
.insight-card:hover { border-color: var(--borderbr); box-shadow: var(--shadowcard); }
 
.ic-header { display: flex; align-items: center; gap: 7px; }
.ic-icon   { font-size: 14px; opacity: .85; }
.ic-label  {
  font-family: var(--fmono); font-size: 9px; color: var(--txt3);
  text-transform: uppercase; letter-spacing: 1.5px;
}
.ic-text {
  font-family: var(--fui); font-size: 13px; font-weight: 600;
  color: var(--txt1); line-height: 1.35;
  min-height: 2.7em;          /* keep cards same height even with short values */
}
.ic-hi { font-family: var(--fmono); font-weight: 700; }
.ic-sub { font-family: var(--fmono); font-size: 10px; color: var(--txt3); }
 
/* Scrollbar & Footer */
::-webkit-scrollbar { width:6px; height:6px; }
::-webkit-scrollbar-track { background:var(--bg0); }
::-webkit-scrollbar-thumb { background:var(--borderbr); border-radius:3px; }
::-webkit-scrollbar-thumb:hover { background:var(--cyandim); }
.dash-footer { text-align:center; padding:22px; font-family:var(--fmono); font-size:10px; color:var(--txt3); letter-spacing:2px; text-transform:uppercase; border-top:1px solid var(--border); margin-top:10px; }
</style>
</head>
<body>
 
<header class="dash-header">
  <div class="h-brand">
    <i class="fas fa-shield-halved h-icon"></i>
    <div>
      <div class="h-title">Global Cyber Threat Intelligence</div>
      <span class="h-sub">Operational Security Dashboard — Threat Monitoring Platform</span>
    </div>
  </div>
  <div class="h-right">
    <div class="live-ind" id="liveInd"><div class="live-dot"></div><span id="liveLabel">OFFLINE</span></div>
    <div class="clock" id="clock">00:00:00</div>
    <div class="loadts">CSV LOADED<br><span id="loadTs">—</span></div>
  </div>
</header>
 
<main class="dash-main">
 
  <div class="fbar">
    <div class="fbarlabel"><i class="fas fa-sliders"></i>&nbsp; Filters</div>
    <div class="fg"><label>Year From</label><select id="fyFrom" class="fsel"></select></div>
    <div class="fg"><label>Year To</label><select id="fyTo"   class="fsel"></select></div>
    <div class="fg">
      <label>Severity</label>
      <div class="msel" id="fsev">
        <button class="msel-btn" type="button">All</button>
        <div class="msel-panel">
          <label class="msel-item"><input type="checkbox" value="Critical"> Critical</label>
          <label class="msel-item"><input type="checkbox" value="High"> High</label>
          <label class="msel-item"><input type="checkbox" value="Medium"> Medium</label>
          <label class="msel-item"><input type="checkbox" value="Low"> Low</label>
        </div>
      </div>
    </div>
    <div class="fg">
      <label>Attack Type</label>
      <div class="msel" id="ftype"><button class="msel-btn" type="button">All</button><div class="msel-panel"></div></div>
    </div>
    <div class="fg">
      <label>Country</label>
      <div class="msel" id="fcountry"><button class="msel-btn" type="button">All</button><div class="msel-panel"></div></div>
    </div>
    <div class="fg">
      <label>Source</label>
      <div class="msel" id="fsource"><button class="msel-btn" type="button">All</button><div class="msel-panel"></div></div>
    </div>
    <div class="factions">
      <button class="btn-cyber btn-reset" id="btnReset"><i class="fas fa-rotate-left"></i> Reset</button>
      <button class="btn-cyber btn-live"  id="btnLive"><i class="fas fa-rss"></i> Live Feed</button>
    </div>
  </div>
 
  <!-- ── Intelligence Findings ────────────────────────────── -->
  <div class="insights-panel" id="insightsPanel">
 
    <div class="insight-card" style="--ic-ac:var(--crit)">
      <div class="ic-header">
        <div class="ic-icon"><i class="fas fa-skull-crossbones" style="color:var(--crit)"></i></div>
        <div class="ic-label">Top Attack Vector</div>
      </div>
      <div class="ic-text" id="if-atk">—</div>
      <div class="ic-sub"  id="if-atk-sub">by cumulative financial loss</div>
    </div>
 
    <div class="insight-card" style="--ic-ac:var(--amber)">
      <div class="ic-header">
        <div class="ic-icon"><i class="fas fa-sack-dollar" style="color:var(--amber)"></i></div>
        <div class="ic-label">Highest-Loss Country</div>
      </div>
      <div class="ic-text" id="if-ctry-loss">—</div>
      <div class="ic-sub"  id="if-ctry-loss-sub">by total financial damage</div>
    </div>
 
    <div class="insight-card" style="--ic-ac:var(--magenta)">
      <div class="ic-header">
        <div class="ic-icon"><i class="fas fa-users" style="color:var(--magenta)"></i></div>
        <div class="ic-label">Widest User Impact</div>
      </div>
      <div class="ic-text" id="if-ctry-users">—</div>
      <div class="ic-sub"  id="if-ctry-users-sub">country by affected users</div>
    </div>
 
    <div class="insight-card" style="--ic-ac:var(--high)">
      <div class="ic-header">
        <div class="ic-icon"><i class="fas fa-bug" style="color:var(--high)"></i></div>
        <div class="ic-label">Top Vulnerability</div>
      </div>
      <div class="ic-text" id="if-vuln">—</div>
      <div class="ic-sub"  id="if-vuln-sub">most frequently exploited</div>
    </div>
 
    <div class="insight-card" style="--ic-ac:var(--low)">
      <div class="ic-header">
        <div class="ic-icon"><i class="fas fa-shield-halved" style="color:var(--low)"></i></div>
        <div class="ic-label">Defense Effectiveness</div>
      </div>
      <div class="ic-text" id="if-defense">—</div>
      <div class="ic-sub"  id="if-defense-sub">fastest vs slowest avg resolution</div>
    </div>
 
    <div class="insight-card" style="--ic-ac:var(--medium)">
      <div class="ic-header">
        <div class="ic-icon"><i class="fas fa-industry" style="color:var(--medium)"></i></div>
        <div class="ic-label">Hardest-Hit Sector</div>
      </div>
      <div class="ic-text" id="if-industry">—</div>
      <div class="ic-sub"  id="if-industry-sub">by incident count</div>
    </div>
 
    <div class="insight-card" style="--ic-ac:var(--cyan)">
      <div class="ic-header">
        <div class="ic-icon"><i class="fas fa-calendar-days" style="color:var(--cyan)"></i></div>
        <div class="ic-label">Peak Threat Year</div>
      </div>
      <div class="ic-text" id="if-year">—</div>
      <div class="ic-sub"  id="if-year-sub">highest annual incident volume</div>
    </div>
 
    <div class="insight-card" style="--ic-ac:#0a84ff">
      <div class="ic-header">
        <div class="ic-icon"><i class="fas fa-satellite-dish" style="color:#0a84ff"></i></div>
        <div class="ic-label">Most Active Source</div>
      </div>
      <div class="ic-text" id="if-source">—</div>
      <div class="ic-sub"  id="if-source-sub">dominant threat actor type</div>
    </div>
 
  </div><!-- /insights-panel -->
 
  <div class="cards">
    <div class="scard sc-total">
      <div class="ci"><i class="fas fa-database" style="color:var(--cyan)"></i></div>
      <div class="clabel">Total Threats</div>
      <div class="cval" id="cvTotal">0</div>
      <div class="csub">incidents logged</div>
    </div>
    <div class="scard sc-critical">
      <div class="ci"><i class="fas fa-triangle-exclamation" style="color:var(--crit)"></i></div>
      <div class="clabel">Critical / High</div>
      <div class="cval" id="cvCritHigh">0</div>
      <div class="csub">severe events</div>
    </div>
    <div class="scard sc-loss">
      <div class="ci"><i class="fas fa-sack-dollar" style="color:var(--amber)"></i></div>
      <div class="clabel">Financial Damage</div>
      <div class="cval">$<span id="cvLoss">0</span><span id="cvLossUnit" style="font-size:18px;margin-left:2px">M</span></div>
      <div class="csub">cumulative estimated loss</div>
    </div>
    <div class="scard sc-countries">
      <div class="ci"><i class="fas fa-globe" style="color:var(--medium)"></i></div>
      <div class="clabel">Source Countries</div>
      <div class="cval" id="cvCountries">0</div>
      <div class="csub">unique nations</div>
    </div>
    <div class="scard sc-actors">
      <div class="ci"><i class="fas fa-user-secret" style="color:var(--magenta)"></i></div>
      <div class="clabel">Threat Sources</div>
      <div class="cval" id="cvActors">0</div>
      <div class="csub">actor groups</div>
    </div>
    <div class="scard sc-cvss">
      <div class="ci"><i class="fas fa-chart-line" style="color:var(--high)"></i></div>
      <div class="clabel">Avg CVSS</div>
      <div class="cval" id="cvCvss">0.0</div>
      <div class="csub">vulnerability score</div>
    </div>
  </div>
 
  <div class="grid-main">
    <div class="cpanel">
      <div class="ptitle"><i class="fas fa-map-location-dot"></i> Threat Origin Map</div>
      <div id="mapWrap"></div>
    </div>
    <div class="grid-side">
      <div class="cpanel" style="flex:1">
        <div class="ptitle"><i class="fas fa-chart-bar"></i> Top Attack Types</div>
        <div class="cc" style="height:155px"><canvas id="chAtk"></canvas></div>
      </div>
      <div class="cpanel" style="flex:1">
        <div class="ptitle"><i class="fas fa-chart-pie"></i> Severity Distribution</div>
        <div class="cc" style="height:175px;display:flex;align-items:center;justify-content:center">
          <canvas id="chSev" style="max-height:175px;max-width:280px"></canvas>
        </div>
      </div>
    </div>
  </div>
 
  <div class="grid-mid">
    <div class="cpanel">
      <div class="ptitle"><i class="fas fa-chart-line"></i> Incident Timeline (Annual)</div>
      <div class="cc" style="height:195px"><canvas id="chTime"></canvas></div>
    </div>
    <div class="cpanel">
      <div class="ptitle"><i class="fas fa-industry"></i> Top Industries Targeted</div>
      <div class="cc" style="height:195px"><canvas id="chInd"></canvas></div>
    </div>
  </div>
 
  <div class="grid-finance">
    <div class="cpanel">
      <div class="ptitle"><i class="fas fa-file-invoice-dollar"></i> Financial Loss by Attack Type</div>
      <div class="cc" style="height:195px"><canvas id="chLossAtk"></canvas></div>
    </div>
    <div class="cpanel">
      <div class="ptitle"><i class="fas fa-chart-area"></i> Total Financial Damage per Year</div>
      <div class="cc" style="height:195px"><canvas id="chLossYr"></canvas></div>
    </div>
    <div class="cpanel">
      <div class="ptitle"><i class="fas fa-building-columns"></i> Financial Loss by Industry</div>
      <div class="cc" style="height:195px"><canvas id="chLossInd"></canvas></div>
    </div>
  </div>
 
  <div class="grid-bot">
    <!-- Left: Existing Financial Exposure Heatmap -->
    <div class="cpanel">
      <div class="ptitle"><i class="fas fa-table-cells"></i> Attack Type × Industry Exposure ($M)</div>
      <div id="hmWrap" style="overflow-x:auto; max-height:240px; overflow-y:auto;"></div>
    </div>
    <!-- Middle: Attack Sources -->
    <div class="cpanel">
      <div class="ptitle"><i class="fas fa-users"></i> Attack Sources</div>
      <div class="cc" style="height:215px;display:flex;align-items:center;justify-content:center">
        <canvas id="chSrc" style="max-height:215px"></canvas>
      </div>
    </div>
    <!-- Right: NEW Count-based Heatmap from dashboard_generator -->
    <div class="cpanel">
      <div class="ptitle"><i class="fas fa-chart-simple"></i> Attack Type × Industry Heatmap (Count)</div>
      <div id="hmCountWrap" style="overflow-x:auto; max-height:240px; overflow-y:auto;"></div>
    </div>
  </div>
 
  <div class="tsection">
    <div class="ptitle"><i class="fas fa-list-ul"></i> Incident Log</div>
    <div class="table-responsive">
      <table id="dtTable" class="table table-hover w-100">
        <thead><tr>
          <th>Timestamp</th><th>Attack Type</th><th>Severity</th><th>Country</th>
          <th>Industry</th><th>Attack Vector</th><th>Source</th>
          <th>CVSS</th><th>Loss $M</th><th>Status</th>
        </tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </div>
 
  <div class="ticker">
    <div class="ticklabel"><i class="fas fa-bolt"></i> Critical Alerts</div>
    <div class="tickscroll"><div class="tickinner" id="tickInner"></div></div>
  </div>
 
</main>
 
<footer class="dash-footer">
  &copy; 2024 Cyber Threat Intelligence Platform &nbsp;·&nbsp;
  Global Cybersecurity Threats 2015 – 2024
</footer>
 
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
<script src="https://cdn.datatables.net/1.13.7/js/dataTables.bootstrap5.min.js"></script>
<script src="https://cdn.datatables.net/buttons/2.4.2/js/dataTables.buttons.min.js"></script>
<script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.bootstrap5.min.js"></script>
<script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.html5.min.js"></script>
<script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.print.min.js"></script>
 
<script>
/* ════════════════════════════════════════════════════════════════
   EMBEDDED DATA
   ════════════════════════════════════════════════════════════════ */
const THREAT_DATA    = __DATA_JSON__;
const LOAD_TS        = "__LOAD_TS__";
const COUNTRIES_LIST = __COUNTRIES_JSON__;
const TYPES_LIST     = __TYPES_JSON__;
const SOURCES_LIST   = __SOURCES_JSON__;
const YEARS_LIST     = __YEARS_JSON__;
const COORDS         = __COORDS_JSON__;
const FLAGS          = __FLAGS_JSON__;
 
/* ════════════════════════════════════════════════════════════════
   GLOBAL STATE
   ════════════════════════════════════════════════════════════════ */
let filtered   = [...THREAT_DATA];
let liveTimer  = null;
let dtInst     = null;
let lMap       = null;
let mapLayers  = {};
 
const CH = { atk:null, sev:null, time:null, ind:null, src:null, lossAtk:null, lossYr:null, lossInd:null };
 
/* ════════════════════════════════════════════════════════════════
   CHART.JS DEFAULTS
   ════════════════════════════════════════════════════════════════ */
const C = {
  cyan:'#00f5ff', green:'#39ff14', magenta:'#d958f7',
  orange:'#ff6b35', red:'#ff2d55', yellow:'#ffd60a',
  purple:'#bf5af2', blue:'#0a84ff', teal:'#5ac8fa', amber:'#f59e0b',
  grid:'rgba(0,245,255,.07)', txt:'#7f8faa',
};
const SEV_C = { Critical:'#ff2d55', High:'#ff6b35', Medium:'#ffd60a', Low:'#30d158' };
const PAL_A = ['#00f5ff','#39ff14','#ff6b35','#ffd60a','#bf5af2','#0a84ff','#ff2d55','#5ac8fa'];
const PAL_I = ['#00f5ff','#39ff14','#ffd60a','#bf5af2','#ff6b35','#0a84ff','#ff2d55'];
 
Chart.defaults.color              = C.txt;
Chart.defaults.font.family        = "'Share Tech Mono',monospace";
Chart.defaults.font.size          = 11;
Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(9,14,28,.96)';
Chart.defaults.plugins.tooltip.borderColor     = 'rgba(0,245,255,.3)';
Chart.defaults.plugins.tooltip.borderWidth     = 1;
Chart.defaults.plugins.tooltip.titleColor      = C.cyan;
Chart.defaults.plugins.tooltip.bodyColor       = '#dde6f5';
Chart.defaults.plugins.tooltip.padding         = 10;
 
/* ════════════════════════════════════════════════════════════════
   UTILITIES
   ════════════════════════════════════════════════════════════════ */
function countBy(arr, key) {
  const out = {};
  for (const r of arr) { const v = r[key] ?? 'Unknown'; out[v] = (out[v]||0) + 1; }
  return out;
}
function sumBy(arr, keyGroup, keySum) {
  const out = {};
  for (const r of arr) { const v = r[keyGroup] ?? 'Unknown'; out[v] = (out[v]||0) + (r[keySum]||0); }
  return out;
}
function animateNum(el, target) {
  if (!el) return;
  const raw   = el.textContent.replace(/,/g,'');
  const start = parseFloat(raw) || 0;
  const isF   = !Number.isInteger(target);
  const dur   = 550;
  let t0 = null;
  const step = (ts) => {
    if (!t0) t0 = ts;
    const p = Math.min((ts-t0)/dur, 1);
    const e = 1 - Math.pow(1-p, 3);
    const v = start + (target-start)*e;
    el.textContent = isF ? v.toFixed(1) : Math.round(v).toLocaleString();
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}
 
/* ════════════════════════════════════════════════════════════════
   CLOCK
   ════════════════════════════════════════════════════════════════ */
function startClock() {
  const ce = document.getElementById('clock');
  const le = document.getElementById('loadTs');
  if (le) le.textContent = LOAD_TS;
  const tick = () => {
    if (!ce) return;
    const n = new Date();
    ce.textContent = [n.getHours(),n.getMinutes(),n.getSeconds()]
      .map(x=>String(x).padStart(2,'0')).join(':');
  };
  tick(); setInterval(tick, 1000);
}
 
/* ════════════════════════════════════════════════════════════════
   FILTER CONFIGURATION
   Single source of truth for every filter control.
     type 'year-from' — inclusive lower-bound on r.year (lex order is
                        safe for 4-digit year strings)
     type 'year-to'   — inclusive upper-bound on r.year
     type 'multi'     — zero-or-more values; empty set = "All" (pass-through)
   list: JS array used to dynamically populate the panel;
         null = checkboxes are already present as static HTML.
   ════════════════════════════════════════════════════════════════ */
const FILTER_DEFS = [
  { id: 'fyFrom',   key: 'year',     type: 'year-from', list: null           },
  { id: 'fyTo',     key: 'year',     type: 'year-to',   list: null           },
  { id: 'fsev',     key: 'severity', type: 'multi',     list: null           },  // static checkboxes in HTML
  { id: 'ftype',    key: 'type',     type: 'multi',     list: TYPES_LIST     },
  { id: 'fcountry', key: 'country',  type: 'multi',     list: COUNTRIES_LIST },
  { id: 'fsource',  key: 'source',   type: 'multi',     list: SOURCES_LIST   },
];
 
/* ════════════════════════════════════════════════════════════════
   FILTER HELPERS
   ════════════════════════════════════════════════════════════════ */
 
/** Populate the year range <select> elements (no "All" — they are range bounds). */
function populateYearSelects() {
  const yf = document.getElementById('fyFrom');
  const yt = document.getElementById('fyTo');
  YEARS_LIST.forEach(y => {
    yf?.appendChild(new Option(y, y));
    yt?.appendChild(new Option(y, y));
  });
}
 
/** Inject checkbox items into a .msel-panel for dynamic filters. */
function populateMultiSelect(id, values) {
  const panel = document.querySelector(`#${id} .msel-panel`);
  if (!panel) return;
  values.forEach(v => {
    const lbl = document.createElement('label');
    lbl.className = 'msel-item';
    lbl.innerHTML = `<input type="checkbox" value="${v}"> ${v}`;
    panel.appendChild(lbl);
  });
}
 
/**
 * Update the trigger-button label for a multi-select:
 *   0 checked  → "All"
 *   1 checked  → that value
 *   n checked  → "n selected" badge
 */
function updateMultiLabel(id) {
  const container = document.getElementById(id);
  if (!container) return;
  const btn     = container.querySelector('.msel-btn');
  const checked = [...container.querySelectorAll('input:checked')].map(i => i.value);
  if (!btn) return;
 
  // Clear previous content, keep ::after pseudo-element via text node + optional badge
  btn.innerHTML = '';
  const textNode = document.createTextNode(
    checked.length === 0 ? 'All' : checked.length === 1 ? checked[0] : ''
  );
  btn.appendChild(textNode);
  if (checked.length > 1) {
    const badge = document.createElement('span');
    badge.className = 'msel-count';
    badge.textContent = `${checked.length}`;
    btn.appendChild(badge);
  }
}
 
/** Read every filter control into a plain object keyed by filter id. */
function getFilters() {
  return Object.fromEntries(
    FILTER_DEFS.map(({ id, type }) => {
      if (type === 'multi') {
        const vals = [...document.querySelectorAll(`#${id} input:checked`)].map(i => i.value);
        return [id, vals];
      }
      return [id, document.getElementById(id)?.value ?? ''];
    })
  );
}
 
/** Reset all filter controls to their default values. */
function resetFilters() {
  FILTER_DEFS.forEach(({ id, type }) => {
    if (type === 'year-from') {
      const el = document.getElementById(id); if (el) el.value = YEARS_LIST[0] ?? '';
    } else if (type === 'year-to') {
      const el = document.getElementById(id); if (el) el.value = YEARS_LIST[YEARS_LIST.length - 1] ?? '';
    } else if (type === 'multi') {
      document.querySelectorAll(`#${id} input:checked`).forEach(i => { i.checked = false; });
      updateMultiLabel(id);
    }
  });
}
 
/**
 * Build a single predicate function from a filters snapshot.
 * Each active filter contributes one check; all must pass (AND logic).
 * Multi filters with nothing selected are treated as "All" (pass-through).
 * Returns () => true when no filters are active.
 */
function buildPredicate(filters) {
  const checks = FILTER_DEFS.flatMap(({ id, key, type }) => {
    const val = filters[id];
    switch (type) {
      case 'year-from': return val ? [r => r[key] >= val] : [];
      case 'year-to':   return val ? [r => r[key] <= val] : [];
      case 'multi':     return val.length ? [r => val.includes(r[key])] : [];
      default:          return [];
    }
  });
  return checks.length === 0 ? () => true : r => checks.every(fn => fn(r));
}
 
/* ════════════════════════════════════════════════════════════════
   FILTER INIT + APPLY
   ════════════════════════════════════════════════════════════════ */
function initFilters() {
  // 1. Populate year range selects and apply defaults
  populateYearSelects();
  resetFilters();
 
  // 2. Populate dynamic multi-select panels (fsev is static HTML)
  FILTER_DEFS.filter(d => d.type === 'multi' && d.list)
    .forEach(({ id, list }) => populateMultiSelect(id, list));
 
  // 3. Wire each multi-select: toggle panel + react to checkbox changes
  FILTER_DEFS.filter(d => d.type === 'multi').forEach(({ id }) => {
    const container = document.getElementById(id);
    if (!container) return;
 
    container.querySelector('.msel-btn')?.addEventListener('click', e => {
      e.stopPropagation();
      const panel = container.querySelector('.msel-panel');
      const btn   = e.currentTarget;
      // Close any other open panels first
      document.querySelectorAll('.msel-panel.open').forEach(p => {
        if (p !== panel) { p.classList.remove('open'); p.previousElementSibling?.classList.remove('open'); }
      });
      const isOpen = panel.classList.toggle('open');
      btn.classList.toggle('open', isOpen);
    });
 
    container.querySelector('.msel-panel')?.addEventListener('click',  e => e.stopPropagation());
    container.querySelector('.msel-panel')?.addEventListener('change', () => {
      updateMultiLabel(id);
      applyFilters();
    });
  });
 
  // 4. Wire year range selects
  ['fyFrom', 'fyTo'].forEach(id => {
    document.getElementById(id)?.addEventListener('change', applyFilters);
  });
 
  // 5. Close any open panel when clicking outside
  document.addEventListener('click', () => {
    document.querySelectorAll('.msel-panel.open').forEach(p => {
      p.classList.remove('open');
      p.previousElementSibling?.classList.remove('open');
    });
  });
 
  // 6. Reset and live-feed buttons
  document.getElementById('btnReset')?.addEventListener('click', () => { resetFilters(); applyFilters(); });
  document.getElementById('btnLive')?.addEventListener('click', toggleLive);
}
 
function applyFilters() {
  filtered = THREAT_DATA.filter(buildPredicate(getFilters()));
  updateAll();
}
 
/* ════════════════════════════════════════════════════════════════
   INTELLIGENCE FINDINGS
   ════════════════════════════════════════════════════════════════ */
function updateFindings(d) {
  const set = (id, html)  => { const el = document.getElementById(id); if (el) el.innerHTML = html; };
  const txt = (id, str)   => { const el = document.getElementById(id); if (el) el.textContent = str; };
 
  if (!d.length) {
    ['if-atk','if-ctry-loss','if-ctry-users','if-vuln','if-defense','if-industry','if-year']
      .forEach(id => txt(id, 'No data'));
    return;
  }
 
  // ── 1. Top attack type by cumulative financial loss ──────────────────────
  const lossAtk  = sumBy(d, 'type', 'loss');
  const topAtk   = Object.entries(lossAtk).sort((a, b) => b[1] - a[1])[0];
  if (topAtk) {
    set('if-atk',      `<span class="ic-hi" style="color:var(--crit)">${topAtk[0]}</span>`);
    txt('if-atk-sub',  `$${Math.round(topAtk[1]).toLocaleString()}M cumulative loss`);
  }
 
  // ── 2. Top country by financial loss ────────────────────────────────────
  const lossCtry   = sumBy(d, 'country', 'loss');
  const topLossCtry = Object.entries(lossCtry).sort((a, b) => b[1] - a[1])[0];
  if (topLossCtry) {
    const flag = FLAGS[topLossCtry[0]] || '🌐';
    set('if-ctry-loss',     `${flag} <span class="ic-hi" style="color:var(--amber)">${topLossCtry[0]}</span>`);
    txt('if-ctry-loss-sub', `$${Math.round(topLossCtry[1]).toLocaleString()}M total damage`);
  }
 
  // ── 3. Top country by number of affected users ───────────────────────────
  const usersCtry   = sumBy(d, 'country', 'users');
  const topUsersCtry = Object.entries(usersCtry).sort((a, b) => b[1] - a[1])[0];
  if (topUsersCtry) {
    const flag = FLAGS[topUsersCtry[0]] || '🌐';
    const fmt  = topUsersCtry[1] >= 1e6
      ? (topUsersCtry[1] / 1e6).toFixed(1) + 'M'
      : topUsersCtry[1].toLocaleString();
    set('if-ctry-users',     `${flag} <span class="ic-hi" style="color:var(--magenta)">${topUsersCtry[0]}</span>`);
    txt('if-ctry-users-sub', `${fmt} users affected`);
  }
 
  // ── 4. Most frequently exploited vulnerability type ──────────────────────
  const vulnCount = countBy(d, 'vuln');
  const topVuln   = Object.entries(vulnCount).sort((a, b) => b[1] - a[1])[0];
  if (topVuln) {
    set('if-vuln',     `<span class="ic-hi" style="color:var(--high)">${topVuln[0]}</span>`);
    txt('if-vuln-sub', `${topVuln[1].toLocaleString()} incidents`);
  }
 
  // ── 5. Fastest and slowest defense mechanism (mean resolution hours) ──────
  const defSum = {}, defN = {};
  d.forEach(r => {
    const k = r.defense || 'Unknown';
    defSum[k] = (defSum[k] || 0) + r.res;
    defN[k]   = (defN[k]   || 0) + 1;
  });
  const defMeans = Object.entries(defSum)
    .filter(([k]) => defN[k] >= 2)
    .map(([k, v]) => [k, Math.round(v / defN[k])])
    .sort((a, b) => a[1] - b[1]);
 
  if (defMeans.length >= 2) {
    const [fast, slow] = [defMeans[0], defMeans[defMeans.length - 1]];
    set('if-defense',
      `<span class="ic-hi" style="color:var(--low)">${fast[0]}</span>` +
      `<span style="color:var(--txt3);font-size:11px"> vs </span>` +
      `<span class="ic-hi" style="color:var(--crit)">${slow[0]}</span>`);
    txt('if-defense-sub', `${fast[1]}h fastest · ${slow[1]}h slowest avg`);
  } else if (defMeans.length === 1) {
    set('if-defense',     `<span class="ic-hi" style="color:var(--low)">${defMeans[0][0]}</span>`);
    txt('if-defense-sub', `${defMeans[0][1]}h avg resolution`);
  } else {
    txt('if-defense',     'Insufficient data');
  }
 
  // ── 6. Hardest-hit industry by incident count ─────────────────────────────
  const indCount  = countBy(d, 'industry');
  const topInd    = Object.entries(indCount).sort((a, b) => b[1] - a[1])[0];
  if (topInd) {
    set('if-industry',     `<span class="ic-hi" style="color:var(--medium)">${topInd[0]}</span>`);
    txt('if-industry-sub', `${topInd[1].toLocaleString()} incidents`);
  }
 
  // ── 7. Peak year by incident count ───────────────────────────────────────
  const yearCount = countBy(d, 'year');
  const topYear   = Object.entries(yearCount).sort((a, b) => b[1] - a[1])[0];
  if (topYear) {
    set('if-year',     `<span class="ic-hi" style="color:var(--cyan)">${topYear[0]}</span>`);
    txt('if-year-sub', `${topYear[1].toLocaleString()} incidents recorded`);
  }
 
  // ── 8. Most active threat source by incident count ───────────────────────
  const srcCount = countBy(d, 'source');
  const topSrc   = Object.entries(srcCount).sort((a, b) => b[1] - a[1])[0];
  if (topSrc) {
    const pct = ((topSrc[1] / d.length) * 100).toFixed(0);
    set('if-source',     `<span class="ic-hi" style="color:#0a84ff">${topSrc[0]}</span>`);
    txt('if-source-sub', `${topSrc[1].toLocaleString()} incidents · ${pct}% of total`);
  }
}
 
/* ════════════════════════════════════════════════════════════════
   UPDATE ALL
   ════════════════════════════════════════════════════════════════ */
function updateAll() {
  const fns = [updateFindings, updateCards, updateMap, updateAtkChart, updateSevChart,
               updateTimeChart, updateIndChart, updateLossAtkChart,
               updateLossYrChart, updateLossIndChart,
               updateSrcChart, updateHeatmap, updateCountHeatmap,
               updateTable, updateTicker];
  fns.forEach(fn => { try { fn(filtered); } catch(e) { console.warn(fn.name, e); } });
}
 
/* ════════════════════════════════════════════════════════════════
   CARDS
   ════════════════════════════════════════════════════════════════ */
function updateCards(d) {
  const total    = d.length;
  const critHigh = d.filter(r => r.severity==='Critical'||r.severity==='High').length;
  const totalLoss = d.reduce((s,r) => s+r.loss, 0);
  const nations  = new Set(d.map(r=>r.country)).size;
  const actors   = new Set(d.map(r=>r.source)).size;
  const avgCvss  = total ? d.reduce((s,r)=>s+r.cvss,0)/total : 0;
 
  animateNum(document.getElementById('cvTotal'),    total);
  animateNum(document.getElementById('cvCritHigh'), critHigh);
  
  let dispLoss = totalLoss, unit = 'M';
  if (totalLoss >= 1000) { dispLoss = totalLoss / 1000; unit = 'B'; }
  document.getElementById('cvLossUnit').textContent = unit;
  animateNum(document.getElementById('cvLoss'), dispLoss);
 
  animateNum(document.getElementById('cvCountries'),nations);
  animateNum(document.getElementById('cvActors'),   actors);
  animateNum(document.getElementById('cvCvss'),     parseFloat(avgCvss.toFixed(1)));
}
 
/* ════════════════════════════════════════════════════════════════
   LEAFLET MAP
   ════════════════════════════════════════════════════════════════ */
function initMap() {
  try {
    lMap = L.map('mapWrap',{center:[20,10],zoom:2,zoomControl:true,attributionControl:false});
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
      {subdomains:'abcd',maxZoom:10}).addTo(lMap);
    L.control.attribution({prefix:false}).addTo(lMap);
    lMap.attributionControl.addAttribution('© CARTO');
    updateMap(THREAT_DATA);
  } catch(e) {
    console.warn('Map init failed:', e);
    document.getElementById('mapWrap').innerHTML =
      '<div class="nodata"><i class="fas fa-map-location-dot"></i><span>Map unavailable</span></div>';
  }
}
 
function updateMap(d) {
  if (!lMap) return;
  const cnt    = countBy(d, 'country');
  const topTyp = {}, totLoss = {};
  d.forEach(r => {
    if (!topTyp[r.country]) topTyp[r.country] = {};
    topTyp[r.country][r.type] = (topTyp[r.country][r.type]||0)+1;
    totLoss[r.country] = (totLoss[r.country]||0) + r.loss;
  });
  const maxC = Math.max(1, ...Object.values(cnt));
 
  Object.values(mapLayers).forEach(m => { try { m.remove(); } catch(e){} });
  mapLayers = {};
 
  Object.entries(COORDS).forEach(([country, coords]) => {
    const c = cnt[country] || 0; if (!c) return;
    const ratio  = c / maxC;
    const radius = 10 + ratio * 38;
    const g      = Math.round(140 + ratio * 115);
    const b      = Math.round(200 + ratio * 55);
    const top    = Object.entries(topTyp[country]||{}).sort((a,b)=>b[1]-a[1])[0];
    const loss   = (totLoss[country]||0).toFixed(1);
 
    const m = L.circleMarker(coords, {
      radius, fillColor:`rgba(0,${g},${b},.7)`, fillOpacity:.65,
      color: C.cyan, weight:1.5, opacity:.85,
    });
    m.bindPopup(`<div class="mpop">
      <h4>${country}</h4>
      <table>
        <tr><td>Incidents</td><td><strong>${c.toLocaleString()}</strong></td></tr>
        <tr><td>Top Threat</td><td>${top ? top[0] : 'N/A'}</td></tr>
        <tr><td>Total Loss</td><td>$${loss}M</td></tr>
       </table>
      </div>`, {className:'cpop'});
    m.on('click', () => {
      // Toggle the matching country checkbox on; clear the rest — same as a quick single-select
      document.querySelectorAll('#fcountry input').forEach(i => { i.checked = (i.value === country); });
      updateMultiLabel('fcountry');
      applyFilters();
    });
    m.addTo(lMap);
    mapLayers[country] = m;
  });
}
 
/* ════════════════════════════════════════════════════════════════
   CHART INIT HELPERS
   ════════════════════════════════════════════════════════════════ */
const scaleOpts = () => ({
  x: { grid:{color:C.grid}, ticks:{color:C.txt}, border:{color:'transparent'} },
  y: { grid:{color:C.grid}, ticks:{color:C.txt}, border:{color:'transparent'} },
});
const noLegend  = { legend:{display:false} };
const baseBar   = (id) => {
  const ctx = document.getElementById(id)?.getContext('2d');
  if (!ctx) return null;
  return new Chart(ctx, {
    type:'bar',
    data:{labels:[],datasets:[{data:[],backgroundColor:[],borderRadius:4,borderWidth:1}]},
    options:{
      indexAxis:'y', responsive:true, maintainAspectRatio:false,
      plugins: noLegend, scales: scaleOpts(),
    },
  });
};
 
/* ─ Counts Charts (Top) ─ */
function initAtkChart()  { CH.atk  = baseBar('chAtk'); }
function updateAtkChart(d) {
  if (!CH.atk) return;
  const e = Object.entries(countBy(d,'type')).sort((a,b)=>b[1]-a[1]);
  CH.atk.data.labels = e.map(x=>x[0]);
  CH.atk.data.datasets[0].data = e.map(x=>x[1]);
  CH.atk.data.datasets[0].backgroundColor = e.map((_,i)=>PAL_A[i%PAL_A.length]+'99');
  CH.atk.data.datasets[0].borderColor = e.map((_,i)=>PAL_A[i%PAL_A.length]);
  CH.atk.update('active');
}
 
function initSevChart() {
  const ctx = document.getElementById('chSev')?.getContext('2d'); if (!ctx) return;
  CH.sev = new Chart(ctx, {
    type:'doughnut',
    data:{
      labels:['Critical','High','Medium','Low'],
      datasets:[{
        data:[0,0,0,0],
        backgroundColor:['rgba(255,45,85,.78)','rgba(255,107,53,.78)','rgba(255,214,10,.78)','rgba(48,209,88,.78)'],
        borderColor:['#ff2d55','#ff6b35','#ffd60a','#30d158'],
        borderWidth:1.5, hoverOffset:8,
      }],
    },
    options:{
      responsive:true, maintainAspectRatio:false, cutout:'65%',
      plugins:{
        legend:{position:'bottom',labels:{padding:9,boxWidth:9,font:{size:10}}},
        tooltip:{callbacks:{label:c=>{
          const tot = c.dataset.data.reduce((a,b)=>a+b,0);
          const pct = tot ? ((c.parsed/tot)*100).toFixed(1) : '0.0';
          return ` ${c.label}: ${c.parsed.toLocaleString()} (${pct}%)`;
        }}},
      },
    },
  });
}
function updateSevChart(d) {
  if (!CH.sev) return;
  const c = countBy(d,'severity');
  CH.sev.data.datasets[0].data = ['Critical','High','Medium','Low'].map(s=>c[s]||0);
  CH.sev.update('active');
}
 
function initTimeChart() {
  const ctx = document.getElementById('chTime')?.getContext('2d'); if (!ctx) return;
  CH.time = new Chart(ctx, {
    type:'line',
    data:{labels:[],datasets:[{
      label:'Incidents', data:[],
      borderColor: C.cyan,
      backgroundColor: (ctx2) => {
        const {ctx:c, chartArea} = ctx2.chart;
        if (!chartArea) return 'transparent';
        const g = c.createLinearGradient(0,chartArea.top,0,chartArea.bottom);
        g.addColorStop(0,'rgba(0,245,255,.32)'); g.addColorStop(1,'rgba(0,245,255,0)');
        return g;
      },
      borderWidth:2, fill:true, tension:.4,
      pointBackgroundColor:C.cyan, pointRadius:4, pointHoverRadius:7,
    }]},
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{...noLegend, tooltip:{callbacks:{label:c=>` ${c.parsed.y.toLocaleString()} incidents`}}},
      scales: scaleOpts(),
    },
  });
}
function updateTimeChart(d) {
  if (!CH.time) return;
  const c = countBy(d,'year');
  const ys = Object.keys(c).sort();
  CH.time.data.labels = ys;
  CH.time.data.datasets[0].data = ys.map(y=>c[y]);
  CH.time.update('active');
}
 
function initIndChart()  { CH.ind = baseBar('chInd'); }
function updateIndChart(d) {
  if (!CH.ind) return;
  const e = Object.entries(countBy(d,'industry')).sort((a,b)=>b[1]-a[1]).slice(0,7);
  CH.ind.data.labels = e.map(x=>x[0]);
  CH.ind.data.datasets[0].data = e.map(x=>x[1]);
  CH.ind.data.datasets[0].backgroundColor = e.map((_,i)=>PAL_I[i%PAL_I.length]+'99');
  CH.ind.data.datasets[0].borderColor = e.map((_,i)=>PAL_I[i%PAL_I.length]);
  CH.ind.update('active');
}
 
/* ─ Financial Charts (Middle) ─ */
function initLossAtkChart() { CH.lossAtk = baseBar('chLossAtk'); }
function updateLossAtkChart(d) {
  if (!CH.lossAtk) return;
  const e = Object.entries(sumBy(d,'type','loss')).sort((a,b)=>b[1]-a[1]);
  CH.lossAtk.data.labels = e.map(x=>x[0]);
  CH.lossAtk.data.datasets[0].data = e.map(x=>x[1]);
  CH.lossAtk.data.datasets[0].backgroundColor = e.map((_,i)=>PAL_A[i%PAL_A.length]+'99');
  CH.lossAtk.data.datasets[0].borderColor = e.map((_,i)=>PAL_A[i%PAL_A.length]);
  CH.lossAtk.options.plugins.tooltip = { callbacks: { label: c => ` $${c.parsed.x.toLocaleString()}M` } };
  CH.lossAtk.update('active');
}
 
function initLossYrChart() {
  const ctx = document.getElementById('chLossYr')?.getContext('2d'); if(!ctx) return;
  CH.lossYr = new Chart(ctx, {
    type:'bar',
    data:{labels:[],datasets:[{label:'Loss $M',data:[],backgroundColor:C.amber+'99',borderColor:C.amber,borderWidth:1}]},
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{...noLegend, tooltip:{callbacks:{label:c=>` $${c.parsed.y.toLocaleString()}M`}}},
      scales: scaleOpts()
    }
  });
}
function updateLossYrChart(d) {
  if (!CH.lossYr) return;
  const c = sumBy(d,'year','loss');
  const ys = Object.keys(c).sort();
  CH.lossYr.data.labels = ys;
  CH.lossYr.data.datasets[0].data = ys.map(y=>c[y]);
  CH.lossYr.update('active');
}
 
function initLossIndChart() { CH.lossInd = baseBar('chLossInd'); }
function updateLossIndChart(d) {
  if (!CH.lossInd) return;
  const e = Object.entries(sumBy(d,'industry','loss')).sort((a,b)=>b[1]-a[1]).slice(0,7);
  CH.lossInd.data.labels = e.map(x=>x[0]);
  CH.lossInd.data.datasets[0].data = e.map(x=>x[1]);
  CH.lossInd.data.datasets[0].backgroundColor = e.map((_,i)=>PAL_I[i%PAL_I.length]+'99');
  CH.lossInd.data.datasets[0].borderColor = e.map((_,i)=>PAL_I[i%PAL_I.length]);
  CH.lossInd.options.plugins.tooltip = { callbacks: { label: c => ` $${c.parsed.x.toLocaleString()}M` } };
  CH.lossInd.update('active');
}
 
 
/* ─ Sources (Bottom) ─ */
function initSrcChart() {
  const ctx = document.getElementById('chSrc')?.getContext('2d'); if (!ctx) return;
  CH.src = new Chart(ctx, {
    type:'polarArea',
    data:{labels:[],datasets:[{data:[],
      backgroundColor:['rgba(0,245,255,.5)','rgba(57,255,20,.5)','rgba(255,107,53,.5)','rgba(191,90,242,.5)'],
      borderColor:[C.cyan,C.green,C.orange,C.purple], borderWidth:1.5}]},
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{legend:{position:'bottom',labels:{padding:8,boxWidth:8,font:{size:10}}}},
      scales:{r:{grid:{color:C.grid},ticks:{display:false}}},
    },
  });
}
function updateSrcChart(d) {
  if (!CH.src) return;
  const e = Object.entries(countBy(d,'source')).sort((a,b)=>b[1]-a[1]);
  CH.src.data.labels = e.map(x=>x[0]);
  CH.src.data.datasets[0].data = e.map(x=>x[1]);
  CH.src.update('active');
}
 
/* ════════════════════════════════════════════════════════════════
   FINANCIAL EXPOSURE HEATMAP (Loss $M)
   ════════════════════════════════════════════════════════════════ */
function updateHeatmap(d) {
  const wrap = document.getElementById('hmWrap'); if (!wrap) return;
  const types = [...new Set(d.map(r=>r.type))].sort();
  const inds  = [...new Set(d.map(r=>r.industry))].sort();
  if (!types.length || !inds.length) {
    wrap.innerHTML = '<div class="nodata"><i class="fas fa-table-cells"></i><span>No data</span></div>';
    return;
  }
  const mx = {};
  types.forEach(t => { mx[t] = {}; inds.forEach(i => { mx[t][i]=0; }); });
  d.forEach(r => { if (mx[r.type]) mx[r.type][r.industry] = (mx[r.type][r.industry]||0) + r.loss; });
  const allV = types.flatMap(t => inds.map(i => mx[t][i]));
  const maxV = Math.max(1,...allV);
 
  const cellBg = v => {
    const x = v / maxV;
    return `rgba(${Math.round(200+x*55)},${Math.round(100+x*50)},${Math.round(10+x*20)},${0.1+x*0.9})`;
  };
  const cellFg = v => (v/maxV) > 0.4 ? '#05080f' : '#dde6f5';
  const abbr   = s => s.length > 7 ? s.substring(0,6)+'…' : s;
 
  let h = '<table class="hmtable"><thead><tr><th></th>';
  inds.forEach(i => { h += `<th title="${i}">${abbr(i)}</th>`; });
  h += '</thead><tbody>';
  types.forEach(t => {
    h += `<tr><td class="rlabel">${t}</td>`;
    inds.forEach(i => {
      const v = mx[t][i];
      const disp = v > 0 ? '$'+Math.round(v)+'M' : '';
      h += `<td style="background:${v>0?cellBg(v):'transparent'};color:${cellFg(v)}" title="${t} → ${i}: $${v.toFixed(1)}M">${disp}</td>`;
    });
    h += '</tr>';
  });
  h += '</tbody></table>';
  wrap.innerHTML = h;
}
 
/* ════════════════════════════════════════════════════════════════
   ATTACK TYPE × INDUSTRY HEATMAP (COUNT) - from dashboard_generator
   ════════════════════════════════════════════════════════════════ */
function updateCountHeatmap(d) {
  const wrap = document.getElementById('hmCountWrap'); if (!wrap) return;
  const types = [...new Set(d.map(r=>r.type))].sort();
  const inds  = [...new Set(d.map(r=>r.industry))].sort();
  if (!types.length || !inds.length) {
    wrap.innerHTML = '<div class="nodata"><i class="fas fa-table-cells"></i><span>No data</span></div>';
    return;
  }
  const mx = {};
  types.forEach(t => { mx[t] = {}; inds.forEach(i => { mx[t][i]=0; }); });
  // Count incidents (not financial)
  d.forEach(r => { if (mx[r.type]) mx[r.type][r.industry] = (mx[r.type][r.industry]||0) + 1; });
  const allV = types.flatMap(t => inds.map(i => mx[t][i]));
  const maxV = Math.max(1,...allV);
 
  const cellBg = v => {
    const x = v / maxV;
    return `rgba(${Math.round(40+x*215)},${Math.round(80+x*175)},${Math.round(200+x*55)},${0.1+x*0.9})`;
  };
  const cellFg = v => (v/maxV) > 0.5 ? '#05080f' : '#dde6f5';
  const abbr   = s => s.length > 7 ? s.substring(0,6)+'…' : s;
 
  let h = '<table class="hmtable"><thead><tr><th></th>';
  inds.forEach(i => { h += `<th title="${i}">${abbr(i)}</th>`; });
  h += '</thead><tbody>';
  types.forEach(t => {
    h += `<tr><td class="rlabel">${t}</td>`;
    inds.forEach(i => {
      const v = mx[t][i];
      h += `<td style="background:${v>0?cellBg(v):'transparent'};color:${cellFg(v)}" title="${t} → ${i}: ${v} incidents">${v || ''}</td>`;
    });
    h += '</tr>';
  });
  h += '</tbody></table>';
  wrap.innerHTML = h;
}
 
/* ════════════════════════════════════════════════════════════════
   DATA TABLE
   ════════════════════════════════════════════════════════════════ */
function rowArr(r) {
  return [
    r.ts,
    r.type,
    `<span class="sbadge s-${r.severity}">${r.severity}</span>`,
    `${r.flag} ${r.country}`,
    r.industry,
    r.vuln,
    r.source,
    r.cvss.toFixed(1),
    `$${r.loss.toFixed(1)}M`,
    `<span class="stbadge st-${r.status}">${r.status}</span>`,
  ];
}
 
function initTable() {
  try {
    dtInst = $('#dtTable').DataTable({
      data: filtered.map(rowArr),
      columns:[
        {title:'Timestamp'}, {title:'Attack Type'}, {title:'Severity'},
        {title:'Country'},   {title:'Industry'},     {title:'Attack Vector'},
        {title:'Source'},    {title:'CVSS',className:'dt-center'},
        {title:'Loss $M',className:'dt-center text-warning'}, {title:'Status'},
      ],
      pageLength: 15, lengthMenu:[10,15,25,50],
      order:[[0,'desc']],
      dom:'<"row"<"col-sm-6"B><"col-sm-6"f>>rt<"row"<"col-sm-6"l><"col-sm-6"p>>',
      buttons:[
        {extend:'csv',   className:'btn btn-sm', text:'<i class="fas fa-download"></i> CSV'},
        {extend:'print', className:'btn btn-sm', text:'<i class="fas fa-print"></i> Print'},
      ],
      language:{
        search:'', searchPlaceholder:'Search incidents…',
        info:'Showing _START_ to _END_ of _TOTAL_ incidents',
        paginate:{ previous:'<i class="fas fa-chevron-left"></i>', next:'<i class="fas fa-chevron-right"></i>' },
      },
      createdRow(row, data) {
        if (data[2] && data[2].includes('s-Critical')) $(row).addClass('row-crit');
        else if (data[2] && data[2].includes('s-High')) $(row).addClass('row-high');
      },
    });
  } catch(e) { console.warn('DataTable init failed:', e); }
}
 
function updateTable(d) {
  if (!dtInst) return;
  try {
    dtInst.clear();
    dtInst.rows.add(d.map(rowArr));
    dtInst.rows().every(function() {
      const data = this.data();
      $(this.node()).removeClass('row-crit row-high');
      if (data[2] && data[2].includes('s-Critical')) $(this.node()).addClass('row-crit');
      else if (data[2] && data[2].includes('s-High')) $(this.node()).addClass('row-high');
    });
    dtInst.draw();
  } catch(e) { console.warn('Table update failed:', e); }
}
 
/* ════════════════════════════════════════════════════════════════
   TICKER
   ════════════════════════════════════════════════════════════════ */
function updateTicker(d) {
  const el = document.getElementById('tickInner'); if (!el) return;
  const crits = d.filter(r=>r.severity==='Critical')
    .sort((a,b)=>b.ts.localeCompare(a.ts)).slice(0,10);
  if (!crits.length) {
    el.innerHTML = '<span class="tickitem">No critical incidents in current filter</span>';
    return;
  }
  const items = [...crits,...crits].map(r =>
    `<span class="tickitem"><strong>[CRITICAL]</strong> ${r.ts} · ${r.flag} ${r.country} · ${r.type} → ${r.industry} · CVSS ${r.cvss} · $${r.loss}M</span>`
  ).join('');
  el.innerHTML = items;
}
 
/* ════════════════════════════════════════════════════════════════
   LIVE FEED SIMULATION
   ════════════════════════════════════════════════════════════════ */
const L_TYPES  = ['Phishing','Ransomware','DDoS','Malware','SQL Injection','Man-in-the-Middle'];
const L_CTRS   = ['USA','China','Russia','UK','Germany','India','Brazil','France','Japan','Australia'];
const L_SRCS   = ['Nation-state','Hacker Group','Insider','Unknown'];
const L_VULNS  = ['Zero-day','Unpatched Software','Weak Passwords','Social Engineering'];
const L_DEFS   = ['Firewall','VPN','Encryption','Antivirus','AI-based Detection'];
const L_INDS   = ['Banking','Healthcare','Government','IT','Education','Retail','Telecommunications'];
const L_SEVS   = ['Critical','Critical','High','High','High','Medium','Medium','Low'];
const L_STATS  = ['Active','Active','Contained','Resolved'];
function rnd(a) { return a[Math.floor(Math.random()*a.length)]; }
 
function genLive() {
  const country = rnd(L_CTRS);
  const sev     = rnd(L_SEVS);
  const loss    = parseFloat((Math.random()*99+0.5).toFixed(2));
  const users   = Math.floor(Math.random()*999000+424);
  const cvss    = parseFloat((3+Math.random()*7).toFixed(1));
  const dw      = sev==='Critical' ? Math.floor(50+Math.random()*150) : sev==='High' ? Math.floor(10+Math.random()*50) : Math.floor(Math.random()*10);
  const now     = new Date();
  const ts      = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-${String(now.getDate()).padStart(2,'0')} ${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}`;
  const coords  = COORDS[country] || [0,0];
  return {
    ts, year: String(now.getFullYear()), country,
    flag: FLAGS[country]||'🌐', lat:coords[0], lng:coords[1],
    type: rnd(L_TYPES), industry: rnd(L_INDS), loss, users,
    source: rnd(L_SRCS), vuln: rnd(L_VULNS), defense: rnd(L_DEFS),
    res: Math.floor(Math.random()*168), severity: sev, cvss,
    status: rnd(L_STATS), dw,
  };
}
 
function toggleLive() {
  const btn  = document.getElementById('btnLive');
  const ind  = document.getElementById('liveInd');
  const lbl  = document.getElementById('liveLabel');
 
  if (liveTimer) {
    clearInterval(liveTimer); liveTimer = null;
    btn?.classList.remove('on');
    ind?.classList.remove('on');
    if (lbl) lbl.textContent = 'OFFLINE';
  } else {
    btn?.classList.add('on');
    ind?.classList.add('on');
    if (lbl) lbl.textContent = 'LIVE';
 
    liveTimer = setInterval(() => {
      const inc = genLive();
      THREAT_DATA.unshift(inc);
      filtered.unshift(inc);
      updateAll();
      if (dtInst) {
        try { dtInst.row.add(rowArr(inc)).draw(false); } catch(e) {}
      }
    }, 7000);
  }
}
 
/* ════════════════════════════════════════════════════════════════
   BOOT
   ════════════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {
  const safe = (fn, name) => { try { fn(); } catch(e) { console.warn(name, e); } };
  safe(startClock,      'clock');
  safe(initFilters,     'filters');
  safe(initMap,         'map');
  safe(initAtkChart,    'atkChart');
  safe(initSevChart,    'sevChart');
  safe(initTimeChart,   'timeChart');
  safe(initIndChart,    'indChart');
  safe(initLossAtkChart,'lossAtkChart');
  safe(initLossYrChart, 'lossYrChart');
  safe(initLossIndChart,'lossIndChart');
  safe(initSrcChart,    'srcChart');
  safe(initTable,       'table');
  safe(updateAll,       'initialRender');
});
</script>
</body>
</html>
"""
 
 
# ─── HTML Generator ──────────────────────────────────────────────────────────
 
def generate_html(data, load_time):
    """Build the complete self-contained HTML by injecting JSON into the template."""
    load_ts        = load_time.strftime("%Y-%m-%d %H:%M:%S")
    countries      = sorted({r["country"] for r in data})
    types_list     = sorted({r["type"]    for r in data})
    sources_list   = sorted({r["source"]  for r in data})
    years_list     = sorted({r["year"]    for r in data})
 
    html = TEMPLATE
    html = html.replace("__DATA_JSON__",     json.dumps(data,           ensure_ascii=False))
    html = html.replace("__LOAD_TS__",       load_ts)
    html = html.replace("__COUNTRIES_JSON__",json.dumps(countries,      ensure_ascii=False))
    html = html.replace("__TYPES_JSON__",    json.dumps(types_list,     ensure_ascii=False))
    html = html.replace("__SOURCES_JSON__",  json.dumps(sources_list,   ensure_ascii=False))
    html = html.replace("__YEARS_JSON__",    json.dumps(years_list,     ensure_ascii=False))
    html = html.replace("__COORDS_JSON__",   json.dumps(COUNTRY_COORDS, ensure_ascii=False))
    html = html.replace("__FLAGS_JSON__",    json.dumps(COUNTRY_FLAGS,  ensure_ascii=False))
    return html
 
 
# ─── Entry Point ─────────────────────────────────────────────────────────────
 
if __name__ == "__main__":
    csv_path = sys.argv[1] if len(sys.argv) > 1 else CSV_FILENAME
 
    data     = read_csv(csv_path)
    html     = generate_html(data, datetime.utcnow())
 
    with open(OUTPUT_FILENAME, "w", encoding="utf-8") as f:
        f.write(html)
 
    abs_path = os.path.abspath(OUTPUT_FILENAME)
    print(f"[SUCCESS] Dashboard generated → '{OUTPUT_FILENAME}'")
    print(f"          Open in browser: file://{abs_path}")
    print(f"          Total incidents embedded: {len(data)}")

    print(f"          Total incidents embedded: {len(data)}")
