"""
generate_cyber_dashboard.py
============================
Generates a fully interactive, self-contained HTML cybersecurity
threat intelligence dashboard from a CSV file.

Expected CSV columns (Global_Cybersecurity_Threats_2015-2024.csv format):
  Country, Year, Attack Type, Target Industry,
  Financial Loss (in Million $), Number of Affected Users,
  Attack Source, Security Vulnerability Type,
  Defense Mechanism Used, Incident Resolution Time (in Hours)

Usage:
  python generate-data-profile.py  ../data/raw/Global_Cybersecurity_Threats_2015-2024.csv
  python generate-data-profile.py  ../data/raw/Global_Cybersecurity_Threats_2015-2024.csv -o my_dashboard.html
  python generate-data-profile.py  ../data/raw/Global_Cybersecurity_Threats_2015-2024.csv --delimiter ";"

The output is a single self-contained HTML file. No server needed —
open it directly in any browser.
"""

import pandas as pd
import json
import argparse
import os
import sys


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate an interactive cybersecurity threat dashboard from a CSV file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("csv", help="Path to the input CSV file")
    parser.add_argument(
        "-o", "--output",
        default="cybersecurity_dashboard.html",
        help="Output HTML file path (default: cybersecurity_dashboard.html)",
    )
    parser.add_argument(
        "-d", "--delimiter",
        default=",",
        help='CSV delimiter (default: ",")',
    )
    return parser.parse_args()


# ─────────────────────────────────────────────────────────────
# DATA ENCODING
# Each row is stored as a compact integer-indexed array:
#   [countryIdx, yearOffset, attackIdx, industryIdx,
#    loss(float), users(int), sourceIdx, vulnIdx,
#    defenseIdx, restime(int)]
# Year offset is relative to the minimum year in the dataset.
# ─────────────────────────────────────────────────────────────
COLUMN_MAP = {
    "country":   "Country",
    "year":      "Year",
    "attack":    "Attack Type",
    "industry":  "Target Industry",
    "loss":      "Financial Loss (in Million $)",
    "users":     "Number of Affected Users",
    "source":    "Attack Source",
    "vuln":      "Security Vulnerability Type",
    "defense":   "Defense Mechanism Used",
    "restime":   "Incident Resolution Time (in Hours)",
}

def encode_data(df):
    col = COLUMN_MAP
    countries  = sorted(df[col["country"]].unique().tolist())
    attacks    = sorted(df[col["attack"]].unique().tolist())
    industries = sorted(df[col["industry"]].unique().tolist())
    sources    = sorted(df[col["source"]].unique().tolist())
    vulns      = sorted(df[col["vuln"]].unique().tolist())
    defenses   = sorted(df[col["defense"]].unique().tolist())
    years      = sorted(df[col["year"]].unique().tolist())
    min_year   = int(years[0])

    rows = []
    for _, r in df.iterrows():
        rows.append([
            countries.index(r[col["country"]]),
            int(r[col["year"]]) - min_year,
            attacks.index(r[col["attack"]]),
            industries.index(r[col["industry"]]),
            round(float(r[col["loss"]]), 2),
            int(r[col["users"]]),
            sources.index(r[col["source"]]),
            vulns.index(r[col["vuln"]]),
            defenses.index(r[col["defense"]]),
            int(r[col["restime"]]),
        ])

    return {
        "countries":  countries,
        "attacks":    attacks,
        "industries": industries,
        "sources":    sources,
        "vulns":      vulns,
        "defenses":   defenses,
        "years":      years,
        "minYear":    min_year,
        "rows":       rows,
    }


# ─────────────────────────────────────────────────────────────
# HTML TEMPLATE
# Uses __PLACEHOLDER__ tokens instead of f-strings to avoid
# conflicts with the many JavaScript curly braces in the template.
# ─────────────────────────────────────────────────────────────
HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Global Cybersecurity Threat Intelligence · Interactive Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@600;700;800&family=DM+Sans:wght@400;500&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
:root{
  --bg:#05101e;--surf:#0c1828;--surf2:#132034;--surf3:#1a2a44;
  --bdr:rgba(0,210,155,0.16);--bdr2:rgba(0,210,155,0.08);
  --acc:#00d4a0;--acc-dim:rgba(0,212,160,0.12);
  --red:#ef4565;--amber:#f59e0b;--purple:#b48cf4;--orange:#fb923c;
  --t1:#d8eaf8;--t2:#93aec8;--t3:#5c7a96;
}
body{background:var(--bg);color:var(--t1);font-family:'DM Sans',sans-serif;font-size:14px;line-height:1.55;min-height:100vh;}
/* Header */
.hdr{background:var(--surf);border-bottom:1px solid var(--bdr);padding:20px 32px;display:flex;align-items:flex-start;justify-content:space-between;gap:20px;}
.hdr-badge{display:inline-flex;align-items:center;gap:7px;background:var(--acc-dim);border:1px solid var(--bdr);border-radius:20px;padding:4px 12px;font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--acc);letter-spacing:.1em;text-transform:uppercase;margin-bottom:10px;}
.hdr-badge::before{content:'';width:6px;height:6px;border-radius:50%;background:var(--acc);animation:blink 2.4s infinite;}
@keyframes blink{0%,100%{opacity:1;}55%{opacity:.25;}}
.hdr h1{font-family:'Syne',sans-serif;font-size:25px;font-weight:800;color:var(--t1);letter-spacing:-.025em;line-height:1.2;}
.hdr h1 span{color:var(--acc);}
.hdr-sub{color:var(--t2);font-size:13px;margin-top:6px;}
.meta{display:grid;grid-template-columns:auto auto;gap:2px 18px;font-family:'JetBrains Mono',monospace;font-size:10.5px;color:var(--t2);text-align:right;flex-shrink:0;}
.meta span{color:var(--acc);}
/* Filter bar */
.fbar{background:var(--surf);border-bottom:1px solid var(--bdr);padding:14px 32px;position:sticky;top:0;z-index:50;}
.fbar-inner{display:flex;flex-direction:column;gap:10px;max-width:1640px;margin:0 auto;}
.fbar-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap;}
.f-label{font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--t2);white-space:nowrap;min-width:68px;}
.pills{display:flex;flex-wrap:wrap;gap:6px;}
.pill{cursor:pointer;border:1px solid var(--bdr);border-radius:20px;padding:4px 12px;font-size:12px;color:var(--t2);background:transparent;transition:background .12s,color .12s,border-color .12s;font-family:'DM Sans',sans-serif;user-select:none;}
.pill:hover{border-color:var(--acc);color:var(--acc);}
.pill.on{background:var(--acc);color:#002a1c;border-color:var(--acc);font-weight:500;}
.yr-select{background:var(--surf2);border:1px solid var(--bdr);border-radius:8px;color:var(--t1);font-family:'JetBrains Mono',monospace;font-size:12px;padding:5px 10px;cursor:pointer;outline:none;}
.yr-select:focus{border-color:var(--acc);}
.yr-select option{background:var(--surf2);}
.f-divider{width:1px;height:20px;background:var(--bdr);flex-shrink:0;}
.stat-badge{display:flex;align-items:center;gap:6px;background:var(--acc-dim);border:1px solid var(--bdr);border-radius:20px;padding:4px 14px;font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--acc);white-space:nowrap;}
.reset-btn{cursor:pointer;border:1px solid var(--bdr);border-radius:20px;padding:4px 14px;font-size:11px;color:var(--t2);background:transparent;font-family:'DM Sans',sans-serif;margin-left:auto;transition:border-color .12s,color .12s;}
.reset-btn:hover{border-color:var(--acc);color:var(--acc);}
/* Main */
.main{padding:22px 32px;max-width:1640px;margin:0 auto;}
/* KPIs */
.kpi-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px;}
.kpi{background:var(--surf);border:1px solid var(--bdr);border-radius:12px;padding:18px 20px;position:relative;overflow:hidden;}
.kpi::after{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--acc),transparent);}
.kpi.red::after{background:linear-gradient(90deg,var(--red),transparent);}
.kpi.amb::after{background:linear-gradient(90deg,var(--amber),transparent);}
.kpi.pur::after{background:linear-gradient(90deg,var(--purple),transparent);}
.kpi-label{font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--t2);font-family:'JetBrains Mono',monospace;margin-bottom:8px;}
.kpi-num{font-family:'Syne',sans-serif;font-size:32px;font-weight:800;color:var(--t1);line-height:1;}
.kpi.red .kpi-num{color:var(--red);}.kpi.amb .kpi-num{color:var(--amber);}.kpi.pur .kpi-num{color:var(--purple);}
.kpi-unit{font-family:'DM Sans',sans-serif;font-size:13px;font-weight:400;color:var(--t2);margin-left:3px;}
.kpi-sub{margin-top:7px;font-size:11.5px;color:var(--t2);}
/* Section headers */
.sh{display:flex;align-items:center;gap:10px;margin-bottom:12px;margin-top:20px;}
.sh-t{font-family:'Syne',sans-serif;font-size:12px;font-weight:700;color:var(--t1);letter-spacing:.05em;text-transform:uppercase;white-space:nowrap;}
.sh-l{flex:1;height:1px;background:var(--bdr);}
.sh-tag{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--acc);background:var(--acc-dim);padding:2px 9px;border-radius:10px;letter-spacing:.04em;white-space:nowrap;}
/* Insight cards */
.ins-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:4px;}
.ins{background:var(--surf2);border:1px solid var(--bdr2);border-left:3px solid var(--acc);border-radius:0 8px 8px 0;padding:12px 15px;}
.ins.r{border-left-color:var(--red);}.ins.a{border-left-color:var(--amber);}.ins.p{border-left-color:var(--purple);}
.ins-lbl{font-size:9.5px;text-transform:uppercase;letter-spacing:.12em;color:var(--t2);font-family:'JetBrains Mono',monospace;margin-bottom:5px;}
.ins-txt{font-size:12px;color:var(--t1);line-height:1.55;}
.ins-txt b{color:var(--acc);font-weight:600;}.ins.r .ins-txt b{color:var(--red);}.ins.a .ins-txt b{color:var(--amber);}.ins.p .ins-txt b{color:var(--purple);}
/* Chart cards */
.cc{background:var(--surf);border:1px solid var(--bdr);border-radius:12px;padding:18px;}
.cc-t{font-family:'Syne',sans-serif;font-size:11.5px;font-weight:700;color:var(--t1);letter-spacing:.05em;text-transform:uppercase;margin-bottom:3px;}
.cc-s{font-size:11.5px;color:var(--t2);margin-bottom:12px;}
/* Grids */
.g2{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px;}
.g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:12px;}
.g31{display:grid;grid-template-columns:3fr 2fr;gap:12px;margin-bottom:12px;}
.mb12{margin-bottom:12px;}
/* Legend */
.leg{display:flex;flex-wrap:wrap;gap:8px 14px;font-size:11px;color:var(--t2);margin-bottom:10px;}
.li{display:flex;align-items:center;gap:6px;}
.ld{width:10px;height:10px;border-radius:2px;flex-shrink:0;}
/* Heatmap */
.hm-wrap{overflow-x:auto;}
.hm{width:100%;border-collapse:separate;border-spacing:3px;font-family:'JetBrains Mono',monospace;font-size:11px;}
.hm th{color:var(--t2);font-weight:500;padding:6px 8px;text-align:center;font-size:10px;letter-spacing:.04em;border-bottom:1px solid var(--bdr);}
.hm th.rh{text-align:left;padding-left:0;}
.hm td{padding:7px 8px;text-align:center;border-radius:5px;font-size:11px;font-weight:500;white-space:nowrap;}
.hm td:first-child{text-align:left;color:var(--t2);background:transparent !important;padding-left:0;}
.hm td.rtot{color:var(--acc);font-weight:600;background:transparent !important;}
.hm .nd{color:var(--t3);background:var(--surf2) !important;font-style:italic;}
.scale-bar{display:flex;align-items:center;gap:8px;margin-top:12px;font-size:10.5px;color:var(--t2);font-family:'JetBrains Mono',monospace;}
.scale-sw{display:flex;gap:2px;}
.ssw{width:22px;height:12px;border-radius:2px;}
/* Footer */
.footer{background:var(--surf);border-top:1px solid var(--bdr);padding:13px 32px;display:flex;justify-content:space-between;align-items:center;margin-top:22px;}
.foot-l{font-size:10.5px;color:var(--t3);font-family:'JetBrains Mono',monospace;letter-spacing:.04em;}
.foot-r{font-size:11.5px;color:var(--t2);}
</style>
</head>
<body>

<header class="hdr">
  <div>
    <div class="hdr-badge">Threat Intelligence · Interactive</div>
    <h1>Global Cybersecurity <span>Threat</span> Intelligence</h1>
    <p class="hdr-sub">Interactive analysis — use filters below to explore the dataset</p>
  </div>
  <div class="meta">
    <div>Dataset</div><div><span>__SOURCE_FILE__</span></div>
    <div>Records</div><div><span>__TOTAL_RECORDS__ incidents</span></div>
    <div>Generated</div><div><span id="genDate">—</span></div>
  </div>
</header>

<div class="fbar">
  <div class="fbar-inner">
    <div class="fbar-row">
      <span class="f-label">Year range</span>
      <div style="display:flex;align-items:center;gap:8px;">
        <select class="yr-select" id="yrFrom"></select>
        <span style="color:var(--t2);font-size:12px;">→</span>
        <select class="yr-select" id="yrTo"></select>
      </div>
      <div class="f-divider"></div>
      <span class="f-label">Country</span>
      <div class="pills" id="pillCountry"></div>
      <div class="f-divider"></div>
      <div class="stat-badge" id="incBadge">__TOTAL_RECORDS__ incidents</div>
      <button class="reset-btn" id="resetBtn">Reset all filters</button>
    </div>
    <div class="fbar-row">
      <span class="f-label">Attack type</span>
      <div class="pills" id="pillAttack"></div>
      <div class="f-divider"></div>
      <span class="f-label">Industry</span>
      <div class="pills" id="pillIndustry"></div>
    </div>
  </div>
</div>

<main class="main">
  <div class="kpi-grid">
    <div class="kpi"><div class="kpi-label">Filtered Incidents</div><div class="kpi-num" id="kpi-count">—</div><div class="kpi-sub" id="kpi-count-sub">—</div></div>
    <div class="kpi red"><div class="kpi-label">Financial Loss</div><div class="kpi-num"><span id="kpi-loss">—</span><span class="kpi-unit">B USD</span></div><div class="kpi-sub" id="kpi-loss-sub">—</div></div>
    <div class="kpi amb"><div class="kpi-label">Users Affected</div><div class="kpi-num"><span id="kpi-users">—</span><span class="kpi-unit" id="kpi-users-unit">—</span></div><div class="kpi-sub" id="kpi-users-sub">—</div></div>
    <div class="kpi pur"><div class="kpi-label">Avg. Resolution Time</div><div class="kpi-num"><span id="kpi-rt">—</span><span class="kpi-unit">Hours</span></div><div class="kpi-sub">Across all defense mechanisms</div></div>
  </div>

  <div class="sh"><div class="sh-t">Intelligence Findings</div><div class="sh-l"></div><div class="sh-tag">updates with filters</div></div>
  <div class="ins-grid mb12">
    <div class="ins"><div class="ins-lbl">Top Threat Vector</div><div class="ins-txt" id="ins1">—</div></div>
    <div class="ins a"><div class="ins-lbl">Geographic Exposure</div><div class="ins-txt" id="ins2">—</div></div>
    <div class="ins r"><div class="ins-lbl">Critical Vulnerability</div><div class="ins-txt" id="ins3">—</div></div>
    <div class="ins p"><div class="ins-lbl">Defense Gap</div><div class="ins-txt" id="ins4">—</div></div>
    <div class="ins a"><div class="ins-lbl">Hardest-Hit Sector</div><div class="ins-txt" id="ins5">—</div></div>
    <div class="ins"><div class="ins-lbl">Peak Year</div><div class="ins-txt" id="ins6">—</div></div>
  </div>

  <div class="sh"><div class="sh-t">Attack Trends &amp; Financial Impact</div><div class="sh-l"></div><div class="sh-tag" id="sh-yr">—</div></div>
  <div class="g2">
    <div class="cc"><div class="cc-t">Incident volume by attack type</div><div class="cc-s">Annual incident count per vector</div><div class="leg" id="leg-trend"></div><div style="position:relative;height:260px;"><canvas id="cTrend"></canvas></div></div>
    <div class="cc"><div class="cc-t">Financial loss by attack type</div><div class="cc-s">Cumulative losses (USD millions)</div><div style="position:relative;height:295px;"><canvas id="cAtkLoss"></canvas></div></div>
  </div>

  <div class="sh"><div class="sh-t">Year-on-Year Financial Losses</div><div class="sh-l"></div><div class="sh-tag">USD Millions</div></div>
  <div class="cc mb12"><div class="cc-t">Total financial damage per year</div><div class="cc-s">Highest year highlighted in red — hover bars for exact values</div><div style="position:relative;height:185px;"><canvas id="cYrLoss"></canvas></div></div>

  <div class="sh"><div class="sh-t">Geographic &amp; Sector Exposure</div><div class="sh-l"></div><div class="sh-tag" id="sh-geo">—</div></div>
  <div class="g31">
    <div class="cc"><div class="cc-t">Financial loss by country</div><div class="cc-s">Cumulative losses per nation (USD millions)</div><div style="position:relative;height:310px;"><canvas id="cCtry"></canvas></div></div>
    <div class="cc"><div class="cc-t">Loss by target sector</div><div class="cc-s">Share of cumulative financial exposure</div><div style="position:relative;height:310px;"><canvas id="cInd"></canvas></div></div>
  </div>

  <div class="sh"><div class="sh-t">Threat Attribution &amp; Defense Performance</div><div class="sh-l"></div><div class="sh-tag">Source · Vulnerability · Response</div></div>
  <div class="g3">
    <div class="cc"><div class="cc-t">Attack source attribution</div><div class="cc-s">Incident share by threat actor type</div><div style="position:relative;height:200px;"><canvas id="cSrc"></canvas></div><div class="leg" id="leg-src" style="margin-top:10px;"></div></div>
    <div class="cc"><div class="cc-t">Security vulnerability types</div><div class="cc-s">Exploited weaknesses across incidents</div><div style="position:relative;height:200px;"><canvas id="cVln"></canvas></div><div class="leg" id="leg-vln" style="margin-top:10px;"></div></div>
    <div class="cc"><div class="cc-t">Defense mechanism response</div><div class="cc-s">Avg. resolution time in hours — lower is better</div><div style="position:relative;height:200px;"><canvas id="cDef"></canvas></div><div style="font-size:10.5px;color:var(--t2);margin-top:6px;font-family:'JetBrains Mono',monospace;">↓ Lower = faster resolution</div></div>
  </div>

  <div class="sh"><div class="sh-t">Population Exposure by Country</div><div class="sh-l"></div><div class="sh-tag">Cumulative Users</div></div>
  <div class="cc mb12"><div class="cc-t">Total affected users per nation</div><div class="cc-s">Cumulative user count across all filtered incidents</div><div style="position:relative;height:195px;"><canvas id="cUsers"></canvas></div></div>

  <div class="sh"><div class="sh-t">Country × Attack Type Heatmap</div><div class="sh-l"></div><div class="sh-tag">Financial Loss $M</div></div>
  <div class="cc mb12">
    <div class="cc-s" style="margin-bottom:14px;">Cumulative financial loss per country-attack combination — brighter cells = higher exposure. Grey = no data under current filters.</div>
    <div class="hm-wrap"><table class="hm" id="hmTable"></table></div>
    <div class="scale-bar"><span>Lower</span><div class="scale-sw" id="scaleSw"></div><span>Higher</span></div>
  </div>
</main>

<footer class="footer">
  <div class="foot-l">SOURCE: __SOURCE_FILE_UPPER__ &nbsp;·&nbsp; __TOTAL_RECORDS__ RECORDS</div>
  <div class="foot-r">Threat Intelligence Dashboard &nbsp;·&nbsp; Generated <span id="genDate2">—</span></div>
</footer>

<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<script>
/* ── EMBEDDED DATA (all __TOTAL_RECORDS__ rows, index-encoded) ── */
const RAW = __DATA_JSON__;
/* Row layout: [countryIdx, yearOffset, attackIdx, industryIdx,
               loss($M float), users(int), sourceIdx, vulnIdx,
               defenseIdx, restime(int)] */
const C=0,Y=1,A=2,I=3,L=4,U=5,S=6,V=7,D=8,R=9;

/* ── DATE ── */
const _ds=new Date().toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'});
['genDate','genDate2'].forEach(id=>document.getElementById(id).textContent=_ds);

/* ── COLOUR PALETTES ── */
// Up to 10 colours for each dimension (extend if your data has more)
const ATK_C =['#00d4a0','#3da3e8','#f59e0b','#b48cf4','#ef4565','#fb923c','#34d399','#f472b6','#a3e635','#38bdf8'];
const ATK_D =[[],[4,3],[2,2],[8,3],[5,2],[1,2],[6,2],[3,1],[7,2],[2,4]];
const IND_C =['#00d4a0','#3da3e8','#b48cf4','#ef4565','#f59e0b','#fb923c','#34d399','#f472b6','#a3e635','#38bdf8'];
const SRC_C =['#ef4565','#3da3e8','#f59e0b','#93aec8','#b48cf4','#34d399','#fb923c','#f472b6'];
const VLN_C =['#b48cf4','#ef4565','#00d4a0','#3da3e8','#f59e0b','#fb923c','#34d399','#f472b6'];
const DEF_C =['#00d4a0','#29bfad','#1faa98','#159583','#0a806e','#006b5e','#005549'];
const CTRY_C=['#00d4a0','#00bf90','#00ab81','#009872','#008563','#007354','#006246','#005139','#00412d','#003221'];
function clr(arr,i){return arr[i%arr.length];}

/* ── FILTER STATE ── */
const YEARS=RAW.years;
let selC=new Set(RAW.countries.map((_,i)=>i));
let selA=new Set(RAW.attacks.map((_,i)=>i));
let selI=new Set(RAW.industries.map((_,i)=>i));
let yrFrom=YEARS[0], yrTo=YEARS[YEARS.length-1];
const TOTAL=RAW.rows.length;

/* ── FILTER UI HELPERS ── */
function makePills(id,labels,sel,cb){
  const w=document.getElementById(id);w.innerHTML='';
  labels.forEach((l,i)=>{
    const b=document.createElement('button');
    b.className='pill'+(sel.has(i)?' on':'');
    b.textContent=l;
    b.addEventListener('click',()=>{
      if(sel.has(i)){if(sel.size>1){sel.delete(i);b.classList.remove('on');}}
      else{sel.add(i);b.classList.add('on');}
      cb();
    });
    w.appendChild(b);
  });
}
function makeYrSel(id,val){
  const el=document.getElementById(id);el.innerHTML='';
  YEARS.forEach(y=>{
    const o=document.createElement('option');
    o.value=y;o.textContent=y;if(y===val)o.selected=true;
    el.appendChild(o);
  });
  el.addEventListener('change',()=>{
    if(id==='yrFrom')yrFrom=parseInt(el.value);else yrTo=parseInt(el.value);
    if(yrFrom>yrTo){
      if(id==='yrFrom')yrTo=yrFrom;else yrFrom=yrTo;
      makeYrSel('yrFrom',yrFrom);makeYrSel('yrTo',yrTo);
    }
    refresh();
  });
}

makePills('pillCountry',RAW.countries,selC,refresh);
makePills('pillAttack',RAW.attacks,selA,refresh);
makePills('pillIndustry',RAW.industries,selI,refresh);
makeYrSel('yrFrom',YEARS[0]);
makeYrSel('yrTo',YEARS[YEARS.length-1]);

document.getElementById('resetBtn').addEventListener('click',()=>{
  RAW.countries.forEach((_,i)=>selC.add(i));
  RAW.attacks.forEach((_,i)=>selA.add(i));
  RAW.industries.forEach((_,i)=>selI.add(i));
  yrFrom=YEARS[0];yrTo=YEARS[YEARS.length-1];
  ['pillCountry','pillAttack','pillIndustry'].forEach(id=>
    document.getElementById(id).querySelectorAll('.pill').forEach(p=>p.classList.add('on')));
  makeYrSel('yrFrom',YEARS[0]);
  makeYrSel('yrTo',YEARS[YEARS.length-1]);
  refresh();
});

/* ── COMPUTE AGGREGATIONS FROM RAW DATA ── */
function compute(){
  let cnt=0,tL=0,tU=0,tR=0;
  const nC=RAW.countries.length,nA=RAW.attacks.length,nI=RAW.industries.length;
  const nS=RAW.sources.length,nV=RAW.vulns.length,nD=RAW.defenses.length,nY=YEARS.length;
  const byC=Array.from({length:nC},()=>({loss:0,users:0,cnt:0}));
  const byA=Array.from({length:nA},()=>({loss:0,cnt:0}));
  const byI=Array.from({length:nI},()=>({loss:0}));
  const byS=new Int32Array(nS),byV=new Int32Array(nV);
  const byD=Array.from({length:nD},()=>({rt:0,cnt:0}));
  const byY=Array.from({length:nY},()=>({loss:0,cnt:0,atk:new Int32Array(nA)}));
  const hm=Array.from({length:nC},()=>new Float64Array(nA));

  for(const r of RAW.rows){
    const yr=RAW.minYear+r[Y];
    if(!selC.has(r[C])||!selA.has(r[A])||!selI.has(r[I])||yr<yrFrom||yr>yrTo) continue;
    cnt++;tL+=r[L];tU+=r[U];tR+=r[R];
    byC[r[C]].loss+=r[L];byC[r[C]].users+=r[U];byC[r[C]].cnt++;
    byA[r[A]].loss+=r[L];byA[r[A]].cnt++;
    byI[r[I]].loss+=r[L];
    byS[r[S]]++;byV[r[V]]++;
    byD[r[D]].rt+=r[R];byD[r[D]].cnt++;
    byY[r[Y]].loss+=r[L];byY[r[Y]].cnt++;byY[r[Y]].atk[r[A]]++;
    hm[r[C]][r[A]]+=r[L];
  }
  return {cnt,tL,tU,avgRT:cnt?tR/cnt:0,byC,byA,byI,byS,byV,byD,byY,hm};
}

/* ── CHART.JS DEFAULTS ── */
Chart.defaults.color='#93aec8';
Chart.defaults.borderColor='rgba(0,210,155,0.09)';
Chart.defaults.font.family="'JetBrains Mono', monospace";
Chart.defaults.font.size=11;
Chart.defaults.plugins.tooltip.backgroundColor='#0c1828';
Chart.defaults.plugins.tooltip.borderColor='rgba(0,212,160,0.35)';
Chart.defaults.plugins.tooltip.borderWidth=1;
Chart.defaults.plugins.tooltip.padding=10;
Chart.defaults.plugins.tooltip.titleColor='#d8eaf8';
Chart.defaults.plugins.tooltip.bodyColor='#93aec8';

/* ── CHART INSTANCES ── */
const CH={};
let initialized=false;

function initCharts(g){
  /* trend legend */
  const lt=document.getElementById('leg-trend');lt.innerHTML='';
  RAW.attacks.forEach((n,i)=>{
    const d=document.createElement('div');d.className='li';
    d.innerHTML=`<div class="ld" style="background:${clr(ATK_C,i)}"></div>${n}`;
    lt.appendChild(d);
  });

  /* 1 — Trend line */
  CH.trend=new Chart(document.getElementById('cTrend'),{
    type:'line',
    data:{
      labels:YEARS,
      datasets:RAW.attacks.map((nm,i)=>({
        label:nm, data:g.byY.map(y=>y.atk[i]),
        borderColor:clr(ATK_C,i), backgroundColor:'transparent',
        borderWidth:2, pointRadius:3, pointBackgroundColor:clr(ATK_C,i),
        tension:0.3, borderDash:ATK_D[i]||[],
      }))
    },
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{
        x:{grid:{color:'rgba(0,210,155,0.07)'},ticks:{autoSkip:false,maxRotation:0}},
        y:{grid:{color:'rgba(0,210,155,0.07)'},min:0,
           title:{display:true,text:'Incidents',color:'#93aec8',font:{size:10}}}
      }
    }
  });

  /* 2 — Attack loss h-bar */
  const sA=[...RAW.attacks.map((n,i)=>({n,i,loss:g.byA[i].loss}))].sort((a,b)=>b.loss-a.loss);
  CH.atkLoss=new Chart(document.getElementById('cAtkLoss'),{
    type:'bar',
    data:{labels:sA.map(x=>x.n),datasets:[{
      label:'Loss $M', data:sA.map(x=>x.loss),
      backgroundColor:sA.map(x=>clr(ATK_C,x.i)),
      borderRadius:4, borderSkipped:false,
    }]},
    options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>` $${(ctx.raw/1000).toFixed(2)}B`}}},
      scales:{
        x:{grid:{color:'rgba(0,210,155,0.07)'},ticks:{callback:v=>`$${(v/1000).toFixed(0)}B`}},
        y:{grid:{display:false}}
      }
    }
  });

  /* 3 — Yearly loss bar */
  const yl=g.byY.map(y=>y.loss),mxY=Math.max(...yl);
  CH.yrLoss=new Chart(document.getElementById('cYrLoss'),{
    type:'bar',
    data:{labels:YEARS,datasets:[{
      label:'Loss $M', data:yl,
      backgroundColor:yl.map(v=>Math.round(v)===Math.round(mxY)&&v>0?'#ef4565':'#00d4a0'),
      borderRadius:4, borderSkipped:false,
    }]},
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>` $${(ctx.raw/1000).toFixed(2)}B`}}},
      scales:{
        x:{grid:{display:false},ticks:{autoSkip:false,maxRotation:0}},
        y:{grid:{color:'rgba(0,210,155,0.07)'},ticks:{callback:v=>`$${(v/1000).toFixed(0)}B`}}
      }
    }
  });

  /* 4 — Country h-bar */
  const cS=[...g.byC.map((d,i)=>({n:RAW.countries[i],i,loss:d.loss}))].sort((a,b)=>b.loss-a.loss);
  CH.ctry=new Chart(document.getElementById('cCtry'),{
    type:'bar',
    data:{labels:cS.map(x=>x.n),datasets:[{
      label:'Loss $M', data:cS.map(x=>x.loss),
      backgroundColor:cS.map((_,i)=>clr(CTRY_C,i)),
      borderRadius:4, borderSkipped:false,
    }]},
    options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>` $${(ctx.raw/1000).toFixed(2)}B`}}},
      scales:{
        x:{grid:{color:'rgba(0,210,155,0.07)'},ticks:{callback:v=>`$${(v/1000).toFixed(0)}B`}},
        y:{grid:{display:false}}
      }
    }
  });

  /* 5 — Industry donut */
  CH.ind=new Chart(document.getElementById('cInd'),{
    type:'doughnut',
    data:{labels:RAW.industries,datasets:[{
      data:g.byI.map(x=>x.loss),
      backgroundColor:RAW.industries.map((_,i)=>clr(IND_C,i)),
      borderWidth:0, hoverOffset:10,
    }]},
    options:{responsive:true,maintainAspectRatio:false,cutout:'60%',
      plugins:{
        legend:{display:true,position:'bottom',labels:{
          color:'#93aec8',font:{size:10.5},padding:8,
          usePointStyle:true,pointStyleWidth:10,
          generateLabels:chart=>{
            const d=chart.data;
            const tot=d.datasets[0].data.reduce((a,b)=>a+b,0)||1;
            return d.labels.map((lbl,i)=>({
              text:`${lbl}  ${((d.datasets[0].data[i]/tot)*100).toFixed(1)}%`,
              fillStyle:d.datasets[0].backgroundColor[i],
              strokeStyle:'transparent',pointStyle:'rect',index:i,
            }));
          }
        }},
        tooltip:{callbacks:{label:ctx=>{
          const tot=ctx.dataset.data.reduce((a,b)=>a+b,0)||1;
          return ` $${(ctx.raw/1000).toFixed(1)}B (${((ctx.raw/tot)*100).toFixed(1)}%)`;
        }}}
      }
    }
  });

  /* 6 — Source donut */
  CH.src=new Chart(document.getElementById('cSrc'),{
    type:'doughnut',
    data:{labels:RAW.sources,datasets:[{
      data:[...g.byS],
      backgroundColor:RAW.sources.map((_,i)=>clr(SRC_C,i)),
      borderWidth:0, hoverOffset:10,
    }]},
    options:{responsive:true,maintainAspectRatio:false,cutout:'60%',
      plugins:{legend:{display:false},
        tooltip:{callbacks:{label:ctx=>{
          const t=ctx.dataset.data.reduce((a,b)=>a+b,0)||1;
          return ` ${ctx.label}: ${ctx.raw} (${((ctx.raw/t)*100).toFixed(1)}%)`;
        }}}
      }
    }
  });

  /* 7 — Vuln donut */
  CH.vln=new Chart(document.getElementById('cVln'),{
    type:'doughnut',
    data:{labels:RAW.vulns,datasets:[{
      data:[...g.byV],
      backgroundColor:RAW.vulns.map((_,i)=>clr(VLN_C,i)),
      borderWidth:0, hoverOffset:10,
    }]},
    options:{responsive:true,maintainAspectRatio:false,cutout:'60%',
      plugins:{legend:{display:false},
        tooltip:{callbacks:{label:ctx=>{
          const t=ctx.dataset.data.reduce((a,b)=>a+b,0)||1;
          return ` ${ctx.label}: ${ctx.raw} (${((ctx.raw/t)*100).toFixed(1)}%)`;
        }}}
      }
    }
  });

  /* 8 — Defense h-bar */
  const dS=g.byD.map((d,i)=>({n:RAW.defenses[i],avg:d.cnt?d.rt/d.cnt:0})).sort((a,b)=>a.avg-b.avg);
  CH.def=new Chart(document.getElementById('cDef'),{
    type:'bar',
    data:{labels:dS.map(x=>x.n),datasets:[{
      label:'Avg Hours', data:dS.map(x=>x.avg),
      backgroundColor:dS.map((_,i)=>clr(DEF_C,i)),
      borderRadius:4, borderSkipped:false,
    }]},
    options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>` ${ctx.raw.toFixed(2)} hrs avg`}}},
      scales:{
        x:{grid:{color:'rgba(0,210,155,0.07)'},min:0,ticks:{callback:v=>`${v.toFixed(0)}h`}},
        y:{grid:{display:false}}
      }
    }
  });

  /* 9 — Users h-bar */
  const uS=[...g.byC.map((d,i)=>({n:RAW.countries[i],i,users:d.users}))].sort((a,b)=>b.users-a.users);
  CH.users=new Chart(document.getElementById('cUsers'),{
    type:'bar',
    data:{labels:uS.map(x=>x.n),datasets:[{
      label:'Users', data:uS.map(x=>x.users),
      backgroundColor:uS.map((_,i)=>clr(CTRY_C,i)),
      borderRadius:4, borderSkipped:false,
    }]},
    options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>` ${(ctx.raw/1e6).toFixed(1)}M users`}}},
      scales:{
        x:{grid:{color:'rgba(0,210,155,0.07)'},ticks:{callback:v=>`${(v/1e6).toFixed(0)}M`}},
        y:{grid:{display:false}}
      }
    }
  });
}

/* ── UPDATE CHARTS (called on each filter change) ── */
function updateCharts(g){
  /* trend */
  RAW.attacks.forEach((_,i)=>{CH.trend.data.datasets[i].data=g.byY.map(y=>y.atk[i]);});
  CH.trend.update();

  /* attack loss */
  const sA=[...RAW.attacks.map((n,i)=>({n,i,loss:g.byA[i].loss}))].sort((a,b)=>b.loss-a.loss);
  CH.atkLoss.data.labels=sA.map(x=>x.n);
  CH.atkLoss.data.datasets[0].data=sA.map(x=>x.loss);
  CH.atkLoss.data.datasets[0].backgroundColor=sA.map(x=>clr(ATK_C,x.i));
  CH.atkLoss.update();

  /* yearly loss */
  const yl=g.byY.map(y=>y.loss),mxY=Math.max(...yl);
  CH.yrLoss.data.datasets[0].data=yl;
  CH.yrLoss.data.datasets[0].backgroundColor=yl.map(v=>Math.round(v)===Math.round(mxY)&&v>0?'#ef4565':'#00d4a0');
  CH.yrLoss.update();

  /* country */
  const cS=[...g.byC.map((d,i)=>({n:RAW.countries[i],i,loss:d.loss}))].sort((a,b)=>b.loss-a.loss);
  CH.ctry.data.labels=cS.map(x=>x.n);
  CH.ctry.data.datasets[0].data=cS.map(x=>x.loss);
  CH.ctry.data.datasets[0].backgroundColor=cS.map((_,i)=>clr(CTRY_C,i));
  CH.ctry.update();

  /* industry */
  CH.ind.data.datasets[0].data=g.byI.map(x=>x.loss);CH.ind.update();

  /* source */
  CH.src.data.datasets[0].data=[...g.byS];CH.src.update();

  /* vuln */
  CH.vln.data.datasets[0].data=[...g.byV];CH.vln.update();

  /* defense */
  const dS=g.byD.map((d,i)=>({n:RAW.defenses[i],avg:d.cnt?d.rt/d.cnt:0})).sort((a,b)=>a.avg-b.avg);
  CH.def.data.labels=dS.map(x=>x.n);
  CH.def.data.datasets[0].data=dS.map(x=>x.avg);
  CH.def.update();

  /* users */
  const uS=[...g.byC.map((d,i)=>({n:RAW.countries[i],i,users:d.users}))].sort((a,b)=>b.users-a.users);
  CH.users.data.labels=uS.map(x=>x.n);
  CH.users.data.datasets[0].data=uS.map(x=>x.users);
  CH.users.data.datasets[0].backgroundColor=uS.map((_,i)=>clr(CTRY_C,i));
  CH.users.update();
}

/* ── KPI UPDATE ── */
function updateKPI(g){
  document.getElementById('kpi-count').textContent=g.cnt.toLocaleString();
  document.getElementById('kpi-count-sub').textContent=`of ${TOTAL.toLocaleString()} total (${((g.cnt/TOTAL)*100).toFixed(1)}%)`;
  const lB=g.tL/1000;
  document.getElementById('kpi-loss').textContent=lB>=100?lB.toFixed(1):lB.toFixed(2);
  document.getElementById('kpi-loss-sub').textContent=g.cnt?`~$${(g.tL/g.cnt).toFixed(1)}M avg per incident`:'—';
  const uB=g.tU/1e9,uM=g.tU/1e6;
  document.getElementById('kpi-users').textContent=uB>=1?uB.toFixed(2):uM.toFixed(0);
  document.getElementById('kpi-users-unit').textContent=uB>=1?'Billion':'Million';
  document.getElementById('kpi-users-sub').textContent=g.cnt?`~${((g.tU/g.cnt)/1000).toFixed(0)}K avg per incident`:'—';
  document.getElementById('kpi-rt').textContent=g.avgRT?g.avgRT.toFixed(1):'—';
}

/* ── INSIGHTS UPDATE ── */
function updateInsights(g){
  const topA=[...g.byA].map((d,i)=>({n:RAW.attacks[i],loss:d.loss})).filter(x=>x.loss>0).sort((a,b)=>b.loss-a.loss);
  document.getElementById('ins1').innerHTML=topA.length
    ?`<b>${topA[0].n}</b> caused the most financial damage ($${(topA[0].loss/1000).toFixed(1)}B) in the current selection.`
    :'No data for current filters.';

  const topC=[...g.byC].map((d,i)=>({n:RAW.countries[i],loss:d.loss})).filter(x=>x.loss>0).sort((a,b)=>b.loss-a.loss);
  const topCu=[...g.byC].map((d,i)=>({n:RAW.countries[i],users:d.users})).filter(x=>x.users>0).sort((a,b)=>b.users-a.users);
  document.getElementById('ins2').innerHTML=topC.length
    ?`<b>${topC[0].n}</b> leads in losses ($${(topC[0].loss/1000).toFixed(1)}B).${topCu.length?` <b>${topCu[0].n}</b> has the most affected users (${(topCu[0].users/1e6).toFixed(1)}M).`:''}`
    :'No data for current filters.';

  const topV=[...g.byV].map((cnt,i)=>({n:RAW.vulns[i],cnt})).filter(x=>x.cnt>0).sort((a,b)=>b.cnt-a.cnt);
  const totV=topV.reduce((a,b)=>a+b.cnt,0)||1;
  document.getElementById('ins3').innerHTML=topV.length
    ?`<b>${topV[0].n}</b> is the most exploited weakness (${((topV[0].cnt/totV)*100).toFixed(1)}% of incidents).`
    :'No data for current filters.';

  const dp=g.byD.map((d,i)=>({n:RAW.defenses[i],avg:d.cnt?d.rt/d.cnt:null})).filter(x=>x.avg!==null).sort((a,b)=>a.avg-b.avg);
  document.getElementById('ins4').innerHTML=dp.length>=2
    ?`<b>${dp[0].n}</b> resolves fastest (${dp[0].avg.toFixed(1)}h avg). <b>${dp[dp.length-1].n}</b> is slowest (${dp[dp.length-1].avg.toFixed(1)}h).`
    :dp.length===1?`<b>${dp[0].n}</b>: ${dp[0].avg.toFixed(1)}h avg.`
    :'No data for current filters.';

  const topI=[...g.byI].map((d,i)=>({n:RAW.industries[i],loss:d.loss})).filter(x=>x.loss>0).sort((a,b)=>b.loss-a.loss);
  document.getElementById('ins5').innerHTML=topI.length
    ?`<b>${topI[0].n}</b> suffered the greatest losses ($${(topI[0].loss/1000).toFixed(1)}B).`
    :'No data for current filters.';

  const topY=g.byY.map((d,i)=>({yr:RAW.minYear+i,cnt:d.cnt,loss:d.loss})).filter(x=>x.cnt>0).sort((a,b)=>b.cnt-a.cnt);
  document.getElementById('ins6').innerHTML=topY.length
    ?`<b>${topY[0].yr}</b> had the most incidents (${topY[0].cnt}) with $${(topY[0].loss/1000).toFixed(1)}B in losses.`
    :'No data for current filters.';

  /* section tags */
  const eY=document.getElementById('sh-yr');if(eY)eY.textContent=`${yrFrom}–${yrTo}`;
  const eG=document.getElementById('sh-geo');if(eG)eG.textContent=`${selC.size} Countries · ${selI.size} Industries`;
}

/* ── HEATMAP UPDATE ── */
function updateHeatmap(g){
  const allV=g.hm.map(row=>[...row]).flat().filter(v=>v>0);
  const minV=allV.length?Math.min(...allV):0;
  const maxV=allV.length?Math.max(...allV):1;

  function hmBg(v){
    if(v<=0) return null;
    const t=(v-minV)/(maxV-minV||1);
    return `rgb(${Math.round(10*(1-t))},${Math.round(42+t*170)},${Math.round(32+t*128)})`;
  }
  // Text colour: light on dark cells, dark on bright cells
  function hmFg(v){
    const t=(v-minV)/(maxV-minV||1);
    return t<0.55?'#c0e8d8':'#002a1a';
  }

  const tbl=document.getElementById('hmTable');tbl.innerHTML='';
  const thead=document.createElement('thead');
  const hr=document.createElement('tr');
  hr.innerHTML='<th class="rh">Country</th>';
  RAW.attacks.forEach(a=>{
    hr.innerHTML+=`<th>${a.replace('Man-in-the-Middle','MitM').replace('SQL Injection','SQL Inj.')}</th>`;
  });
  hr.innerHTML+='<th>Row Total</th>';
  thead.appendChild(hr);tbl.appendChild(thead);

  const tb=document.createElement('tbody');
  RAW.countries.forEach((c,ci)=>{
    const row=document.createElement('tr');
    const tot=Array.from(g.hm[ci]).reduce((a,b)=>a+b,0);
    row.innerHTML=`<td>${c}</td>`;
    g.hm[ci].forEach(v=>{
      if(v<=0) row.innerHTML+=`<td class="nd">—</td>`;
      else     row.innerHTML+=`<td style="background:${hmBg(v)};color:${hmFg(v)};">$${(v/1000).toFixed(1)}B</td>`;
    });
    row.innerHTML+=`<td class="${tot>0?'rtot':'nd'}">${tot>0?'$'+(tot/1000).toFixed(1)+'B':'—'}</td>`;
    tb.appendChild(row);
  });
  tbl.appendChild(tb);

  /* scale bar */
  const sw=document.getElementById('scaleSw');sw.innerHTML='';
  if(allV.length){
    for(let i=0;i<8;i++){
      const t=i/7;
      const el=document.createElement('div');el.className='ssw';
      el.style.background=hmBg(minV+t*(maxV-minV));
      sw.appendChild(el);
    }
  }
}

/* ── LEGEND REFRESH (source + vuln donuts) ── */
function refreshLegends(g){
  [
    ['leg-src', RAW.sources,  SRC_C, [...g.byS]],
    ['leg-vln', RAW.vulns,    VLN_C, [...g.byV]],
  ].forEach(([id,labels,colors,data])=>{
    const w=document.getElementById(id);w.innerHTML='';
    const tot=data.reduce((a,b)=>a+b,0)||1;
    labels.forEach((l,i)=>{
      const d=document.createElement('div');d.className='li';
      d.innerHTML=`<div class="ld" style="background:${clr(colors,i)}"></div>${l}&nbsp;<span style="color:var(--t1)">${((data[i]/tot)*100).toFixed(1)}%</span>`;
      w.appendChild(d);
    });
  });
}

/* ── BADGE ── */
function updateBadge(cnt){
  document.getElementById('incBadge').textContent=cnt.toLocaleString()+' incidents';
}

/* ── MAIN REFRESH (called on every filter change) ── */
function refresh(){
  const g=compute();
  updateKPI(g);
  updateInsights(g);
  updateHeatmap(g);
  updateBadge(g.cnt);
  refreshLegends(g);
  if(!initialized){initCharts(g);initialized=true;}
  else{updateCharts(g);}
}

refresh();
</script>
</body>
</html>"""


def build_html(data_json: str, source_filename: str, total_records: int) -> str:
    """Inject data and metadata into the HTML template using safe string replacement."""
    return (
        HTML_TEMPLATE
        .replace("__DATA_JSON__",        data_json)
        .replace("__SOURCE_FILE__",      source_filename)
        .replace("__SOURCE_FILE_UPPER__", source_filename.upper())
        .replace("__TOTAL_RECORDS__",    f"{total_records:,}")
    )


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
def main():
    args = parse_args()

    if not os.path.exists(args.csv):
        print(f"File not found: {args.csv}")
        sys.exit(1)

    output_dir = os.path.dirname(args.output)
    if output_dir and not os.path.exists(output_dir):
        print(f"Output directory does not exist: {output_dir}")
        sys.exit(1)

    print(f"📥  Loading: {args.csv}")
    try:
        df = pd.read_csv(args.csv, sep=args.delimiter)
        print(f"Loaded {len(df):,} rows × {len(df.columns)} columns")
    except Exception as e:
        print(f"Failed to read CSV: {e}")
        sys.exit(1)

    required = list(COLUMN_MAP.values())
    missing = [c for c in required if c not in df.columns]
    if missing:
        print(f"Missing columns: {missing}")
        print(f"Found: {df.columns.tolist()}")
        sys.exit(1)

    print("Encoding data...")
    encoded   = encode_data(df)
    data_json = json.dumps(encoded, separators=(",", ":"))
    print(f"Encoded {len(encoded['rows']):,} records · {len(data_json)/1024:.1f} KB")

    print("Building dashboard...")
    html = build_html(data_json, os.path.basename(args.csv), len(df))

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(html)

    size_kb = os.path.getsize(args.output) / 1024
    print(f"Dashboard saved: {args.output}  ({size_kb:.1f} KB)")
    print(f"Open in any browser — no server required")


if __name__ == "__main__":
    main()
