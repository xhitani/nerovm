"""
NERO Dashboard — dashboard.py
Full web UI: devices, network map, top talkers,
alert log, blocklist, evolution log, threat DB.
"""
from flask import Flask, render_template_string, jsonify, request
import time, json, threading

app = Flask(__name__)

import sensors, brain, actions, memory, evolution, recon, proximity

try:
    import masscan_scan as _masscan
except ImportError:
    _masscan = None

try:
    import nikto_scan as _nikto
except ImportError:
    _nikto = None

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NERO</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');
*{margin:0;padding:0;box-sizing:border-box;}
:root{
  --bg:#0B0F14;--bg2:#0F1620;--bg3:#121B26;
  --green:#5DD6A7;--cyan:#5AA7FF;--amber:#FFC44D;
  --red:#FF4D4D;--purple:#7C5CFF;
  --text:#E6EDF6;--muted:rgba(230,237,246,0.72);--muted2:rgba(230,237,246,0.50);
  --border:rgba(255,255,255,0.08);
}
body{background:radial-gradient(1200px 600px at 12% -10%, rgba(124,92,255,0.16), transparent 55%),radial-gradient(900px 500px at 92% 0%, rgba(90,167,255,0.14), transparent 55%),radial-gradient(900px 500px at 50% 110%, rgba(93,214,167,0.08), transparent 55%),var(--bg);color:var(--text);font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;min-height:100vh;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;}
.hdr{position:sticky;top:0;z-index:20;padding:14px 20px 0;border-bottom:1px solid var(--border);background:rgba(11,15,20,0.72);backdrop-filter:saturate(120%) blur(12px);}
.logo{color:var(--text);letter-spacing:3px;font-size:16px;font-weight:700;}
.sub{color:var(--muted2);font-size:12px;letter-spacing:0.4px;margin:4px 0 12px;display:flex;align-items:center;gap:10px;}
.pulse{width:6px;height:6px;border-radius:50%;background:var(--green);animation:pulse 2s infinite;}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.2}}
.tabs{display:flex;gap:8px;overflow-x:auto;padding-bottom:12px;}
.tab{padding:9px 12px;font-size:12px;letter-spacing:0.2px;cursor:pointer;
     color:var(--muted);background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);
     border-radius:999px;white-space:nowrap;
     font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;transition:all .15s ease;}
.tab:hover{color:var(--text);background:rgba(255,255,255,0.05);border-color:rgba(255,255,255,0.12);}
.tab.active{color:var(--text);border-color:rgba(124,92,255,0.35);background:rgba(124,92,255,0.14);}
.brand-mark{color:#B66DFF;font-size:10px;letter-spacing:1.5px;margin-left:auto;font-weight:600;}
.content{padding:16px 20px;}
.panel{display:none;}.panel.active{display:block;}
.stats{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin-bottom:16px;}
.sbox{background:linear-gradient(180deg, rgba(18,27,38,0.92), rgba(15,22,32,0.88));border:1px solid rgba(255,255,255,0.08);border-radius:14px;padding:14px 12px;text-align:left;box-shadow:0 10px 26px rgba(0,0,0,0.14);}
.sval{font-size:26px;font-weight:750;letter-spacing:-0.4px;line-height:1;margin-bottom:6px;}
.slbl{font-size:12px;letter-spacing:0.2px;color:var(--muted2);}
.sec{font-size:12px;letter-spacing:0.2px;color:rgba(230,237,246,0.55);margin:18px 0 10px;
     display:flex;align-items:center;gap:10px;font-weight:600;}
.sec::after{content:'';flex:1;height:1px;background:var(--border);}
.card{background:linear-gradient(180deg, rgba(18,27,38,0.92), rgba(15,22,32,0.88));border:1px solid rgba(255,255,255,0.08);border-radius:14px;
      padding:14px 14px;margin-bottom:10px;position:relative;overflow:hidden;
      cursor:pointer;transition:border-color .15s ease, transform .15s ease, background .15s ease;}
.card:hover{border-color:rgba(255,255,255,0.14);transform:translateY(-1px);}
.card::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;}
.trusted::before{background:var(--green);}
.normal::before{background:var(--cyan);}
.suspicious::before{background:var(--amber);}
.dangerous::before,.blocked-card::before{background:var(--red);}
.ctop{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:8px;}
.cname{font-size:18px;font-weight:bold;color:var(--green);}
.cip{font-size:11px;color:var(--muted);margin-top:2px;}
.cmac{font-size:10px;color:var(--muted);}
.cright{display:flex;flex-direction:column;align-items:flex-end;gap:4px;}
.tbadge{font-size:11px;font-weight:bold;padding:3px 10px;border-radius:4px;}
.bwbadge{font-size:9px;padding:2px 7px;border-radius:3px;
         background:rgba(0,212,255,0.07);color:var(--cyan);
         border:1px solid rgba(0,212,255,0.15);}
.tbar{height:3px;background:rgba(255,255,255,0.06);border-radius:2px;overflow:hidden;margin-bottom:6px;}
.tfill{height:100%;border-radius:2px;}
.chips{display:flex;gap:4px;flex-wrap:wrap;}
.chip{font-size:9px;padding:2px 7px;border-radius:3px;
      background:rgba(255,255,255,0.05);color:rgba(200,220,255,0.5);
      border:1px solid rgba(255,255,255,0.06);}
.chip-os{background:rgba(0,212,255,0.07);color:var(--cyan);border-color:rgba(0,212,255,0.15);}
.chip-warn{background:rgba(255,51,102,0.1);color:var(--red);border-color:rgba(255,51,102,0.2);}
.chip-ai{background:rgba(0,255,136,0.07);color:var(--green);border-color:rgba(0,255,136,0.15);}
.chip-port{background:rgba(153,102,255,0.1);color:var(--purple);border-color:rgba(153,102,255,0.2);}
.dns-tags{display:flex;flex-wrap:wrap;gap:4px;margin-top:6px;}
.dns-tag{font-size:9px;padding:2px 7px;border-radius:3px;
         background:rgba(0,255,136,0.07);color:var(--green);
         border:1px solid rgba(0,255,136,0.12);}
.abox{background:linear-gradient(180deg, rgba(18,27,38,0.92), rgba(15,22,32,0.88));border:1px solid rgba(255,255,255,0.08);border-radius:14px;
      max-height:520px;overflow-y:auto;}
.arow{display:flex;align-items:center;gap:10px;padding:10px 12px;
      border-bottom:1px solid rgba(255,255,255,0.06);font-size:12px;}
.arow:last-child{border-bottom:none;}
.atime{color:rgba(230,237,246,0.50);min-width:72px;font-family:'JetBrains Mono',ui-monospace,monospace;font-size:11px;}
.atype{min-width:92px;padding:3px 8px;border-radius:999px;text-align:center;font-size:11px;border:1px solid rgba(255,255,255,0.10);font-family:'JetBrains Mono',ui-monospace,monospace;}
.sev-high,.sev-critical{background:rgba(255,77,77,0.10);color:var(--red);border-color:rgba(255,77,77,0.22);}
.sev-warning{background:rgba(255,196,77,0.10);color:var(--amber);border-color:rgba(255,196,77,0.20);}
.sev-info{background:rgba(90,167,255,0.10);color:var(--cyan);border-color:rgba(90,167,255,0.18);}
.aip{color:var(--cyan);min-width:120px;font-family:'JetBrains Mono',ui-monospace,monospace;font-size:11px;}
.amsg{color:rgba(230,237,246,0.55);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.aoutcome{font-size:11px;padding:3px 8px;border-radius:999px;margin-left:6px;cursor:pointer;border:1px solid rgba(255,255,255,0.10);background:rgba(255,255,255,0.04);}
.trow{display:flex;align-items:center;gap:12px;padding:9px 14px;border-bottom:1px solid var(--border);}
.tip{color:var(--cyan);min-width:160px;font-size:11px;}
.tbarw{flex:1;height:6px;background:rgba(255,255,255,0.06);border-radius:3px;overflow:hidden;}
.tbar2{height:100%;border-radius:3px;}
.tval{min-width:80px;text-align:right;font-size:10px;}
.analysis-grid{display:grid;grid-template-columns:1.2fr 1fr;gap:12px;}
.analysis-card{background:linear-gradient(145deg,rgba(25,32,65,.94),rgba(15,22,40,.94));border:1px solid rgba(124,92,255,.22);border-radius:14px;padding:16px;box-shadow:0 12px 28px rgba(0,0,0,.16);}
.analysis-card h3{font-size:13px;font-weight:600;margin-bottom:5px;}
.analysis-muted{font-size:10px;color:var(--muted2);margin-bottom:14px;}
.analysis-list{display:flex;flex-direction:column;gap:10px;}
.analysis-row{display:grid;grid-template-columns:145px 1fr 80px;align-items:center;gap:10px;font-size:11px;}
.analysis-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text);}
.analysis-bar{height:8px;background:rgba(255,255,255,.07);border-radius:8px;overflow:hidden;}
.analysis-fill{height:100%;border-radius:8px;background:linear-gradient(90deg,#7C5CFF,#5AA7FF);}
.analysis-value{text-align:right;color:var(--cyan);font-family:'JetBrains Mono',monospace;font-size:10px;}
.metric-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;}
.metric{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:12px;}
.metric-value{font-size:20px;font-weight:700;color:var(--green);}
.metric-label{font-size:10px;color:var(--muted2);margin-top:4px;}
.block-row{display:flex;gap:8px;margin-bottom:12px;}
.block-in{flex:1;background:rgba(18,27,38,0.75);border:1px solid rgba(255,255,255,0.10);border-radius:12px;
          padding:10px 12px;color:var(--text);font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;
          font-size:13px;outline:none;}
.block-in:focus{border-color:rgba(255,51,102,0.4);}
.btn-red{padding:10px 14px;border-radius:12px;cursor:pointer;
         border:1px solid rgba(255,77,77,0.30);background:rgba(255,77,77,0.10);
         color:var(--red);font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;font-size:12px;font-weight:600;transition:.15s;}
.btn-red:hover{background:rgba(255,77,77,0.14);border-color:rgba(255,77,77,0.36);}
.bitem{display:flex;align-items:center;justify-content:space-between;
       padding:9px 13px;background:rgba(255,51,102,0.05);
       border:1px solid rgba(255,51,102,0.15);border-radius:6px;margin-bottom:6px;}
.bip{color:var(--red);font-size:12px;}
.evo-row{background:var(--bg2);border:1px solid var(--border);border-radius:6px;
         padding:10px 14px;margin-bottom:6px;}
.evo-header{display:flex;align-items:center;gap:10px;margin-bottom:4px;}
.evo-type{font-size:9px;padding:1px 6px;border-radius:3px;
          background:rgba(153,102,255,0.1);color:var(--purple);
          border:1px solid rgba(153,102,255,0.2);}
.evo-time{font-size:9px;color:var(--muted);}
.evo-desc{font-size:11px;margin-bottom:6px;}
.evo-diff{font-size:9px;color:var(--muted);background:var(--bg3);
          padding:6px;border-radius:4px;max-height:120px;overflow-y:auto;
          white-space:pre;font-family:'Share Tech Mono',monospace;display:none;}
.evo-diff.open{display:block;}
.threat-row{background:var(--bg2);border:1px solid var(--border);border-radius:6px;
            padding:10px 14px;margin-bottom:6px;}
.threat-name{color:var(--red);font-size:13px;font-weight:bold;margin-bottom:3px;}
.threat-desc{font-size:10px;color:var(--muted);}
.threat-badge{font-size:9px;padding:1px 6px;border-radius:3px;
              background:rgba(255,51,102,0.1);color:var(--red);
              border:1px solid rgba(255,51,102,0.2);}
#map-canvas{width:100%;height:420px;background:var(--bg2);
            border:1px solid var(--border);border-radius:8px;display:block;}

/* POPUP */
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.8);
         z-index:100;align-items:center;justify-content:center;}
.overlay.open{display:flex;}
.popup{background:var(--bg2);border:1px solid rgba(255,51,102,0.3);
       border-radius:12px;padding:26px 30px;width:90%;max-width:440px;position:relative;}
.popup-close{position:absolute;top:12px;right:16px;background:none;
             border:none;color:var(--muted);font-size:18px;cursor:pointer;}
.popup-close:hover{color:var(--text);}
.popup-name{font-size:20px;font-weight:bold;color:var(--green);margin-bottom:2px;}
.popup-ip{font-size:11px;color:var(--muted);margin-bottom:16px;}
.popup-sec{font-size:9px;letter-spacing:3px;color:var(--muted);margin:12px 0 7px;}
.popup-in{width:100%;background:var(--bg3);border:1px solid var(--border);
          border-radius:6px;padding:9px 11px;color:var(--text);
          font-family:'Share Tech Mono',monospace;font-size:12px;outline:none;
          margin-bottom:7px;}
.popup-in:focus{border-color:rgba(255,51,102,0.4);}
textarea.popup-in{resize:vertical;min-height:72px;}
.popup-btns{display:flex;gap:8px;margin-top:4px;}
.pbtn{flex:1;padding:9px;border-radius:6px;cursor:pointer;
      font-family:'Share Tech Mono',monospace;font-size:10px;
      letter-spacing:1px;transition:.2s;border:1px solid;}
.pbtn-send{border-color:rgba(0,255,136,0.3);background:rgba(0,255,136,0.07);color:var(--green);}
.pbtn-send:hover{background:rgba(0,255,136,0.2);}
.pbtn-block{border-color:rgba(255,51,102,0.3);background:rgba(255,51,102,0.07);color:var(--red);}
.pbtn-block:hover{background:rgba(255,51,102,0.2);}
.pbtn-restore{border-color:rgba(0,212,255,0.3);background:rgba(0,212,255,0.07);color:var(--cyan);}
.pbtn-restore:hover{background:rgba(0,212,255,0.2);}
.popup-status{font-size:10px;color:var(--green);margin-top:7px;min-height:14px;text-align:center;}
.empty{text-align:center;padding:40px;color:var(--muted);}
.footer{text-align:center;font-size:9px;color:rgba(200,220,255,0.15);letter-spacing:2px;padding:14px;}
@media(max-width:800px){.analysis-grid{grid-template-columns:1fr;}}
@media(max-width:600px){.stats{grid-template-columns:repeat(3,1fr);}.analysis-row{grid-template-columns:100px 1fr 70px;}}
</style>
</head>
<body>
<div class="hdr">
  <div class="logo">NERO</div>
  <div class="sub"><span class="pulse"></span> SELF-EVOLVING NETWORK SECURITY v5.0 — LIVE</div>
  <div class="brand-mark">MADE BY KARIM</div>
  <div class="tabs">
    <button class="tab active" onclick="sw('devices',this)">DEVICES ({{ total }})</button>
    <button class="tab" onclick="sw('analysis',this)">ANALYSIS</button>
    <button class="tab" onclick="sw('map',this)">NETWORK MAP</button>
    <button class="tab" onclick="sw('talkers',this)">TOP TALKERS</button>
    <button class="tab" onclick="sw('alerts',this)">ALERTS ({{ alerts_count }})</button>
    <button class="tab" onclick="sw('blocklist',this)">BLOCKLIST ({{ blocked_count }})</button>
    <button class="tab" onclick="sw('evolution',this)">EVOLUTION</button>
    <button class="tab" onclick="sw('threats',this)">THREATS ({{ threats_count }})</button>
  </div>
</div>

<!-- DEVICES -->
<div id="panel-devices" class="panel active">
  <div class="stats">
    <div class="sbox"><div class="sval" style="color:var(--green)">{{ total }}</div><div class="slbl">DEVICES</div></div>
    <div class="sbox"><div class="sval" style="color:var(--green)">{{ trusted }}</div><div class="slbl">TRUSTED</div></div>
    <div class="sbox"><div class="sval" style="color:var(--cyan)">{{ normal }}</div><div class="slbl">NORMAL</div></div>
    <div class="sbox"><div class="sval" style="color:var(--amber)">{{ suspicious }}</div><div class="slbl">SUSPICIOUS</div></div>
    <div class="sbox"><div class="sval" style="color:var(--red)">{{ dangerous }}</div><div class="slbl">DANGEROUS</div></div>
    <div class="sbox"><div class="sval" style="color:var(--red)">{{ blocked_count }}</div><div class="slbl">BLOCKED</div></div>
  </div>
  <div class="sec">Live Device Intelligence</div>
  {% for d in devs %}
  <div class="card {{ d.cls }}" onclick="openPopup('{{ d.ip }}','{{ d.display_name }}',{{ d.is_blocked|lower }})">
    <div class="ctop">
      <div>
        {% if d.display_name and d.display_name != d.ip %}
        <div class="cname">{{ d.display_name }}</div>
        <div class="cip">{{ d.ip }}</div>
        {% else %}
        <div class="cname">{{ d.ip }}</div>
        <div class="cip">name not detected yet</div>
        {% endif %}
        <div class="cmac">{{ d.mac }}{% if d.is_random_mac %} (randomized){% endif %}</div>
      </div>
      <div class="cright">
        <div class="tbadge" style="background:{{ d.bg }};color:{{ d.col }}">{{ d.emoji }} {{ d.score }}/100</div>
        <div class="bwbadge">⇅ {{ d.bw }}</div>
      </div>
    </div>
    <div class="tbar"><div class="tfill" style="width:{{ d.score }}%;background:{{ d.col }}"></div></div>
    <div class="chips">
      <span class="chip">{{ d.label }}</span>
      <span class="chip">{{ d.packets }} pkts</span>
      {% if d.os %}<span class="chip chip-os">{{ d.os }}</span>{% endif %}
      {% if d.ai_trained %}<span class="chip chip-ai">AI MODEL</span>{% endif %}
      {% if d.is_random_mac %}<span class="chip chip-warn">rMAC</span>{% endif %}
      {% if d.spoofed %}<span class="chip chip-warn">⚠ MAC SPOOFED</span>{% endif %}
    </div>
    {% if d.open_ports %}
    <div style="display:flex;flex-wrap:wrap;gap:3px;margin-top:5px;">
      {% for p in d.open_ports[:8] %}<span class="chip chip-port">:{{ p }}</span>{% endfor %}
    </div>
    {% endif %}
    {% if d.sec_issues %}
    <div style="margin-top:3px;">{% for i in d.sec_issues %}<span class="chip chip-warn" style="font-size:8px;">{{ i[:45] }}</span>{% endfor %}</div>
    {% endif %}
    {% if d.vuln_level in ['critical','high','medium'] %}
    <div style="margin-top:4px;">
      <span class="chip chip-warn" style="{% if d.vuln_level == 'critical' %}color:#ff0055;{% elif d.vuln_level == 'high' %}color:var(--red);{% else %}color:var(--amber);{% endif %}">
        🔍 {{ d.vuln_level|upper }} VULNS
      </span>
      {% for f in d.nikto_top %}<div style="font-size:9px;color:rgba(255,100,100,0.65);margin-top:1px;">· {{ f.finding[:55] }}</div>{% endfor %}
    </div>
    {% endif %}
    {% if d.vendor or d.model or d.http_title %}
    <div style="font-size:10px;color:rgba(0,212,255,0.6);margin-top:5px;">
      {% if d.vendor %}{{ d.vendor }}{% endif %}
      {% if d.model %} · {{ d.model }}{% endif %}
      {% if d.http_title %} · {{ d.http_title }}{% endif %}
    </div>
    {% endif %}
    {% if d.apps %}
    <div class="dns-tags" style="margin-top:5px;">
      {% for app in d.apps[:8] %}
      <span class="dns-tag" style="background:rgba(153,102,255,0.08);color:var(--purple);border-color:rgba(153,102,255,0.18);">{{ app }}</span>
      {% endfor %}
    </div>
    {% endif %}
    {% if d.services %}
    <div class="dns-tags" style="margin-top:4px;">
      {% for svc in d.services[:5] %}
      <span class="dns-tag" style="background:rgba(0,212,255,0.06);color:var(--cyan);border-color:rgba(0,212,255,0.12);font-size:8px;">{{ svc }}</span>
      {% endfor %}
    </div>
    {% endif %}
    {% if d.domains %}
    <div class="dns-tags">
      {% for dom in d.domains[:6] %}<span class="dns-tag">{{ dom }}</span>{% endfor %}
    </div>
    {% endif %}
  </div>
  {% endfor %}
  {% if not devs %}<div class="empty">Waiting for devices on the network...</div>{% endif %}
</div>

<!-- NETWORK MAP -->
<div id="panel-map" class="panel">
  <div class="sec">Network Topology</div>
  <canvas id="map-canvas"></canvas>
</div>
<!-- ANALYSIS -->
<div id="panel-analysis" class="panel">
  <div class="sec">Traffic Analysis</div>
  <div class="analysis-grid">
    <div class="analysis-card">
      <h3>Devices sending the most packets</h3>
      <div class="analysis-muted">Outbound packets observed from each device</div>
      <div class="analysis-list">
        {% for item in packet_senders %}
        <div class="analysis-row">
          <div class="analysis-name">{{ item.name }}<br><span style="color:var(--muted2);font-size:9px;">{{ item.ip }}</span></div>
          <div class="analysis-bar"><div class="analysis-fill" style="width:{{ item.pct }}%"></div></div>
          <div class="analysis-value">{{ item.packets }}</div>
        </div>
        {% endfor %}
        {% if not packet_senders %}<div class="empty">Waiting for outbound packet data...</div>{% endif %}
      </div>
    </div>
    <div class="analysis-card">
      <h3>Devices receiving the most packets</h3>
      <div class="analysis-muted">Inbound packets observed by each device</div>
      <div class="analysis-list">
        {% for item in packet_receivers %}
        <div class="analysis-row">
          <div class="analysis-name">{{ item.name }}<br><span style="color:var(--muted2);font-size:9px;">{{ item.ip }}</span></div>
          <div class="analysis-bar"><div class="analysis-fill" style="width:{{ item.pct }}%;background:linear-gradient(90deg,#5DD6A7,#5AA7FF)"></div></div>
          <div class="analysis-value">{{ item.packets }}</div>
        </div>
        {% endfor %}
        {% if not packet_receivers %}<div class="empty">Waiting for inbound packet data...</div>{% endif %}
      </div>
    </div>
  </div>
  <div class="sec">Traffic Summary</div>
  <div class="metric-grid">
    <div class="metric"><div class="metric-value">{{ packet_summary.sent }}</div><div class="metric-label">PACKETS SENT</div></div>
    <div class="metric"><div class="metric-value">{{ packet_summary.received }}</div><div class="metric-label">PACKETS RECEIVED</div></div>
    <div class="metric"><div class="metric-value">{{ packet_summary.sender }}</div><div class="metric-label">TOP SENDER</div></div>
    <div class="metric"><div class="metric-value">{{ packet_summary.receiver }}</div><div class="metric-label">TOP RECEIVER</div></div>
  </div>
</div>
<!-- TOP TALKERS -->
<div id="panel-talkers" class="panel">
  <div class="sec">Bandwidth — Live</div>
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;overflow:hidden;">
    {% for t in talkers %}
    <div class="trow">
      <div class="tip">{{ t.name }}</div>
      <div class="tbarw"><div class="tbar2" style="width:{{ t.pct }}%;background:{{ t.col }}"></div></div>
      <div class="tval">{{ t.bw }}</div>
    </div>
    {% endfor %}
    {% if not talkers %}<div class="empty">No bandwidth data yet</div>{% endif %}
  </div>
</div>

<!-- ALERTS -->
<div id="panel-alerts" class="panel">
  <div class="sec">Security Event Log</div>
  <div class="abox">
    {% for a in alerts %}
    <div class="arow">
      <span class="atime">{{ a.time_str }}</span>
      <span class="atype sev-{{ a.severity }}">{{ a.type[:12] }}</span>
      <span class="aip">{{ a.ip }}</span>
      <span class="amsg">{{ a.message[:80] }}</span>
      {% if a.outcome == 'pending' %}
      <span class="aoutcome" style="background:rgba(255,170,0,0.1);color:var(--amber);border:1px solid rgba(255,170,0,0.2);"
            onclick="event.stopPropagation();markOutcome({{ a.id }},'confirmed_threat')">✓ threat</span>
      <span class="aoutcome" style="background:rgba(0,255,136,0.07);color:var(--green);border:1px solid rgba(0,255,136,0.15);"
            onclick="event.stopPropagation();markOutcome({{ a.id }},'false_positive')">✗ FP</span>
      {% else %}
      <span class="aoutcome" style="background:rgba(255,255,255,0.05);color:var(--muted);">{{ a.outcome }}</span>
      {% endif %}
    </div>
    {% endfor %}
    {% if not alerts %}<div class="empty">No alerts yet</div>{% endif %}
  </div>
</div>
<div class="panel" id="proximity-panel">📡 Nearby Wireless Devices (Not Connected)</div>
<div class="proximity-container">
    <table>
        <thead>
            <tr>
                <th>MAC / Vendor</th>
                <th>Signal (RSSI)</th>
                <th>Probed Networks</th>
                <th>Last Seen</th>
            </tr>
        </thead>
        <tbody>
            {% for mac, info in proximity_devs.items() %}
            <tr>
                <td>
                    <b>{{ info.vendor }}</b><br>
                    <small>{{ mac }}</small>
                </td>
                <td style="color: {{ 'var(--green)' if info.rssi > -60 else 'var(--amber)' }}">
                    {{ info.rssi }} dBm
                </td>
                <td>
                    {% for ssid in info.probed_ssids %}
                        <span class="port-tag">{{ ssid }}</span>
                    {% endfor %}
                </td>
                <td>{{ info.last_seen|round|int }}s ago</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>
<!-- BLOCKLIST -->
<div id="panel-blocklist" class="panel">
  <div class="sec">Blocklist Manager</div>
  <div class="block-row">
    <input class="block-in" id="block-input" placeholder="IP to block — 192.168.1.x" />
    <button class="btn-red" onclick="blockFromInput()">BLOCK</button>
  </div>
  {% for ip in blocked_list %}
  <div class="bitem">
    <span class="bip">⊘ {{ ip }}</span>
    <button class="btn-red" style="border-color:rgba(0,255,136,0.3);background:rgba(0,255,136,0.07);color:var(--green);"
            onclick="unblock('{{ ip }}')">RESTORE</button>
  </div>
  {% endfor %}
  {% if not blocked_list %}<div class="empty">No blocked IPs</div>{% endif %}
</div>

<!-- EVOLUTION -->
<div id="panel-evolution" class="panel">
  <div class="sec">Self-Evolution Log</div>
  {% for e in evo_log %}
  <div class="evo-row">
    <div class="evo-header">
      <span class="evo-type">{{ e.module }}</span>
      <span class="evo-type" style="background:rgba(0,212,255,0.07);color:var(--cyan);border-color:rgba(0,212,255,0.15);">{{ e.change_type }}</span>
      <span class="evo-time">{{ e.time_str }}</span>
      {% if e.change_type == 'code_patch' and not e.applied %}
      <button onclick="approvePatch({{ e.id }})" style="margin-left:auto;padding:3px 10px;border-radius:4px;cursor:pointer;border:1px solid rgba(0,255,136,0.3);background:rgba(0,255,136,0.07);color:var(--green);font-family:'Share Tech Mono',monospace;font-size:9px;">APPROVE PATCH</button>
      <button onclick="rollback()" style="padding:3px 10px;border-radius:4px;cursor:pointer;border:1px solid rgba(255,51,102,0.3);background:rgba(255,51,102,0.07);color:var(--red);font-family:'Share Tech Mono',monospace;font-size:9px;">ROLLBACK</button>
      {% endif %}
    </div>
    <div class="evo-desc">{{ e.description }}</div>
    {% if e.diff %}
    <button onclick="this.nextElementSibling.classList.toggle('open')"
            style="font-size:9px;color:var(--muted);background:none;border:none;cursor:pointer;margin-top:2px;">
      show diff ▾
    </button>
    <div class="evo-diff">{{ e.diff[:2000] }}</div>
    {% endif %}
  </div>
  {% endfor %}
  {% if not evo_log %}<div class="empty">Evolution engine warming up...</div>{% endif %}

  <div class="sec" style="margin-top:20px;">Trust Weight Configuration</div>
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:14px;">
    {% for k, v in trust_weights.items() %}
    <div style="display:flex;align-items:center;justify-content:space-between;padding:5px 0;border-bottom:1px solid var(--border);font-size:11px;">
      <span style="color:var(--muted);">{{ k }}</span>
      <span style="color:{{ 'var(--green)' if v > 0 else 'var(--red)' }}">{{ v }}</span>
    </div>
    {% endfor %}
  </div>
</div>

<!-- THREATS -->
<div id="panel-threats" class="panel">
  <div class="sec">Learned Threat Patterns</div>
  {% for t in threats %}
  <div class="threat-row">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:5px;">
      <div class="threat-name">{{ t.name }}</div>
      <span class="threat-badge">seen {{ t.seen_count }}x</span>
    </div>
    <div class="threat-desc">{{ t.description }}</div>
    {% if t.indicators_parsed %}
    <div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:4px;">
      {% for k, v in t.indicators_parsed.items() %}
      {% if k != 'ips' %}
      <span class="chip">{{ k }}: {{ v }}</span>
      {% endif %}
      {% endfor %}
    </div>
    {% endif %}
  </div>
  {% endfor %}
  {% if not threats %}<div class="empty">No threat patterns learned yet — auto-detection builds over time</div>{% endif %}
</div>

<!-- DEVICE POPUP -->
<div class="overlay" id="overlay">
  <div class="popup">
    <button class="popup-close" onclick="closePopup()">✕</button>
    <div class="popup-name" id="p-name"></div>
    <div class="popup-ip"   id="p-ip"></div>
    <div id="p-recon" style="font-size:10px;color:rgba(0,212,255,0.6);margin:4px 0 8px;min-height:14px;"></div>
    <div id="p-apps"  style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:8px;"></div>
    <div class="popup-sec">Send Notification</div>
    <input  class="popup-in" id="p-title"   placeholder="Title — e.g. Hey!" />
    <textarea class="popup-in" id="p-msg"   placeholder="Message — e.g. Dinner is ready!"></textarea>
    <div class="popup-btns">
      <button class="pbtn pbtn-send"    onclick="sendNotif()">📡 SEND</button>
      <button class="pbtn pbtn-block"   id="p-block-btn"   onclick="popupBlock()">ISOLATE</button>
      <button class="pbtn pbtn-restore" id="p-restore-btn" onclick="popupRestore()" style="display:none">RESTORE</button>
    </div>
    <div class="popup-status" id="p-status"></div>
  </div>
</div>

<div class="footer">NERO v5.0 — {{ cur_time }} — {{ total }} devices — Self-Evolving AI Active — Made by Karim</div>

<script>
const mapData = {{ map_json|safe }};
let _ip="", _name="", _blocked=false;

function sw(name, el) {
  sessionStorage.setItem('nero_tab', name);
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById('panel-'+name).classList.add('active');
  el.classList.add('active');
  if (name==='map') setTimeout(drawMap,60);
}
(function(){
  const t=sessionStorage.getItem('nero_tab')||'devices';
  const btn=document.querySelector(`.tab[onclick*="'${t}'"]`);
  if(btn&&t!=='devices'){sw(t,btn);}
})();

function openPopup(ip, name, blocked) {
  _ip=ip; _name=name||ip; _blocked=blocked;
  document.getElementById('p-name').textContent=_name;
  document.getElementById('p-ip').textContent=ip;
  document.getElementById('p-status').textContent='';
  document.getElementById('p-title').value='';
  document.getElementById('p-msg').value='';
  document.getElementById('p-block-btn').style.display   = blocked?'none':'flex';
  document.getElementById('p-restore-btn').style.display = blocked?'flex':'none';
  // Load recon data from API
  fetch('/api/device/'+ip).then(r=>r.json()).then(d=>{
    const recon = document.getElementById('p-recon');
    const parts = [];
    if(d.vendor)     parts.push(d.vendor);
    if(d.model)      parts.push(d.model);
    if(d.http_title) parts.push(d.http_title);
    if(d.ssh_banner) parts.push(d.ssh_banner.substring(0,40));
    recon.textContent = parts.join(' · ');
    const appsDiv = document.getElementById('p-apps');
    appsDiv.innerHTML = '';
    (d.apps||[]).forEach(app=>{
      const s=document.createElement('span');
      s.textContent=app;
      s.style.cssText='font-size:9px;padding:2px 7px;border-radius:3px;background:rgba(153,102,255,0.1);color:#9966ff;border:1px solid rgba(153,102,255,0.2);';
      appsDiv.appendChild(s);
    });
    (d.services||[]).forEach(svc=>{
      const s=document.createElement('span');
      s.textContent=svc;
      s.style.cssText='font-size:9px;padding:2px 7px;border-radius:3px;background:rgba(0,212,255,0.07);color:#00d4ff;border:1px solid rgba(0,212,255,0.15);';
      appsDiv.appendChild(s);
    });
  }).catch(()=>{});
  document.getElementById('overlay').classList.add('open');
}
function closePopup(){ document.getElementById('overlay').classList.remove('open'); }
document.getElementById('overlay').addEventListener('click',function(e){if(e.target===this)closePopup();});

function sendNotif(){
  const title = document.getElementById('p-title').value.trim();
  const msg   = document.getElementById('p-msg').value.trim();
  if(!msg){document.getElementById('p-status').textContent='Enter a message first.';return;}
  fetch('/api/notify/'+_ip,{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({title:title||'NERO',message:msg})
  }).then(r=>r.json()).then(()=>{
    document.getElementById('p-status').textContent='✓ Sent — they will see it on next page load';
  });
}
function popupBlock(){fetch('/api/block/'+_ip,{method:'POST'}).then(()=>location.reload());}
function popupRestore(){fetch('/api/unblock/'+_ip,{method:'POST'}).then(()=>location.reload());}
function unblock(ip){if(confirm('Restore '+ip+'?'))fetch('/api/unblock/'+ip,{method:'POST'}).then(()=>location.reload());}
function blockFromInput(){
  const ip=document.getElementById('block-input').value.trim();
  if(!ip)return;
  if(confirm('Block '+ip+'?'))fetch('/api/block/'+ip,{method:'POST'}).then(()=>location.reload());
}
function markOutcome(id,outcome){
  fetch('/api/outcome/'+id+'/'+outcome,{method:'POST'});
  event.target.textContent='✓'; event.target.style.opacity='.4';
}
function approvePatch(id){
  if(!confirm('Apply this AI-generated code patch to brain.py?'))return;
  fetch('/api/evolution/approve/'+id,{method:'POST'}).then(r=>r.json()).then(d=>{
    alert(d.message||'Done');location.reload();
  });
}
function rollback(){
  if(!confirm('Roll back brain.py to previous version?'))return;
  fetch('/api/evolution/rollback',{method:'POST'}).then(r=>r.json()).then(d=>{
    alert(d.message||'Done');location.reload();
  });
}

function drawMap(){
  const canvas=document.getElementById('map-canvas');
  const ctx=canvas.getContext('2d');
  const W=canvas.offsetWidth,H=canvas.offsetHeight;
  canvas.width=W;canvas.height=H;
  ctx.clearRect(0,0,W,H);
  const devs=mapData.devices;
  const cx=W/2,cy=H/2;
  const r=Math.min(W,H)*0.36;
  ctx.beginPath();ctx.arc(cx,cy,28,0,Math.PI*2);
  ctx.fillStyle='rgba(0,255,136,0.1)';ctx.fill();
  ctx.strokeStyle='#00ff88';ctx.lineWidth=1.5;ctx.stroke();
  ctx.fillStyle='#00ff88';ctx.font='bold 10px monospace';
  ctx.textAlign='center';ctx.textBaseline='middle';
  ctx.fillText('ROUTER',cx,cy);
  devs.forEach((dev,i)=>{
    const angle=(i/devs.length)*Math.PI*2-Math.PI/2;
    const dx=cx+Math.cos(angle)*r,dy=cy+Math.sin(angle)*r;
    const color=dev.score>=80?'#00ff88':dev.score>=60?'#00d4ff':dev.score>=40?'#ffaa00':'#ff3366';
    ctx.beginPath();ctx.moveTo(cx,cy);ctx.lineTo(dx,dy);
    ctx.strokeStyle=color+'33';ctx.lineWidth=1;ctx.setLineDash([4,4]);ctx.stroke();ctx.setLineDash([]);
    ctx.beginPath();ctx.arc(dx,dy,20,0,Math.PI*2);
    ctx.fillStyle=color+'15';ctx.fill();
    ctx.strokeStyle=color;ctx.lineWidth=1.5;ctx.stroke();
    ctx.fillStyle=color;ctx.font='11px monospace';ctx.textBaseline='middle';
    ctx.fillText(dev.name||dev.ip.split('.').pop(),dx,dy);
    ctx.fillStyle='rgba(200,220,255,0.5)';ctx.font='9px monospace';ctx.textBaseline='top';
    ctx.fillText(dev.score,dx,dy+24);
  });
}

setTimeout(()=>location.reload(), 30000);
</script>
</body>
</html>"""

# ── HELPERS ───────────────────────────────────────────────────────
def _fmt_bw(b):
    if b > 1_000_000: return f"{b/1_000_000:.1f} MB/s"
    if b > 1_000:     return f"{b/1_000:.1f} KB/s"
    if b > 0:         return f"{b:.0f} B/s"
    return "0 B/s"

def _build_devs():
    rows = []
    for ip, dev in sensors.devices.items():
        score = brain.trust_scores.get(ip, 50)
        if   score >= 80: cls,label,col,bg,emoji = "trusted",   "TRUSTED",   "#00ff88","rgba(0,255,136,0.1)","🟢"
        elif score >= 60: cls,label,col,bg,emoji = "normal",    "NORMAL",    "#00d4ff","rgba(0,212,255,0.1)","🟡"
        elif score >= 40: cls,label,col,bg,emoji = "suspicious","SUSPICIOUS","#ffaa00","rgba(255,170,0,0.1)","🟠"
        elif score >= 20: cls,label,col,bg,emoji = "dangerous", "DANGEROUS", "#ff3366","rgba(255,51,102,0.1)","🔴"
        else:             cls,label,col,bg,emoji = "blocked-card","BLOCKED", "#ff3366","rgba(255,51,102,0.15)","🔴"
        mac       = dev.get("mac","")
        macs      = sensors.mac_history.get(ip, set())
        real_macs = [m for m in macs if not sensors._is_random_mac(m)]
        apps     = sorted(recon.detected_apps.get(ip, set()))
        services = sorted(recon.mdns_services.get(ip, set()))
        rc       = dev.get("recon", {})
        rows.append({
            "ip":           ip,
            "mac":          mac,
            "display_name": dev.get("name","") or ip,
            "os":           dev.get("os",""),
            "packets":      dev.get("packets",0),
            "score":        score,
            "cls":          cls,"label":label,"col":col,"bg":bg,"emoji":emoji,
            "bw":           _fmt_bw(sensors.bandwidth_now.get(ip,0)),
            "domains":      sensors.dns_history.get(ip,[]),
            "is_blocked":   ip in actions.blocked_ips,
            "is_random_mac":sensors._is_random_mac(mac),
            "spoofed":      len(real_macs) > 1,
            "ai_trained":   ip in brain.anomaly_models,
            "apps":         apps,
            "services":     services,
            "vendor":       dev.get("vendor","") or rc.get("vendor",""),
            "model":        rc.get("model","") or rc.get("upnp",{}).get("modelName",""),
            "http_title":   rc.get("http_title",""),
            "ssh_banner":   dev.get("ssh_banner",""),
            "open_ports":   _masscan.get_open_ports(ip) if _masscan else dev.get("open_ports",[]),
            "sec_issues":   _masscan.get_security_issues(ip) if _masscan else [],
            "vuln_level":   _nikto.get_worst_severity(ip) if _nikto else "none",
            "nikto_top":    (_nikto.get_findings(ip)[:2] if _nikto else []),
        })
    return sorted(rows, key=lambda x: x["score"])

def _packet_analysis():
    def build(direction):
        key = f"packets_{direction}"
        rows = []
        for ip, dev in sensors.devices.items():
            packets = int(dev.get(key, 0) or 0)
            if packets:
                rows.append({
                    "ip": ip,
                    "name": dev.get("name", "") or ip,
                    "packets": packets,
                })
        rows.sort(key=lambda row: row["packets"], reverse=True)
        top = rows[:8]
        maximum = max((row["packets"] for row in top), default=1)
        for row in top:
            row["pct"] = max(4, int(row["packets"] / maximum * 100))
        return top

    senders = build("sent")
    receivers = build("received")
    return {
        "senders": senders,
        "receivers": receivers,
        "summary": {
            "sent": sum(int(d.get("packets_sent", 0) or 0) for d in sensors.devices.values()),
            "received": sum(int(d.get("packets_received", 0) or 0) for d in sensors.devices.values()),
            "sender": senders[0]["name"] if senders else "—",
            "receiver": receivers[0]["name"] if receivers else "—",
        },
    }

# ── ROUTES ────────────────────────────────────────────────────────
@app.route("/")
def index():
    devs       = _build_devs()
    packet_data = _packet_analysis()
    alerts_raw = memory.get_alerts(limit=150)
    for a in alerts_raw:
        a["time_str"] = time.strftime("%H:%M:%S", time.localtime(a["ts"]))

    talkers = []
    for ip, bw in sensors.bandwidth_now.items():
        if bw > 0:
            dev  = sensors.devices.get(ip,{})
            sc   = brain.trust_scores.get(ip,50)
            name = dev.get("name","") or ip
            talkers.append({
                "ip": ip,"name":name,"raw":bw,"bw":_fmt_bw(bw),
                "col":"#00ff88" if sc>=80 else "#00d4ff" if sc>=60 else "#ffaa00" if sc>=40 else "#ff3366",
            })
    talkers.sort(key=lambda x: x["raw"], reverse=True)
    maxbw = max((t["raw"] for t in talkers),default=1)
    for t in talkers: t["pct"]=int(t["raw"]/maxbw*100)

    evo_log = memory.get_evolution_log(limit=30)
    for e in evo_log:
        e["time_str"] = time.strftime("%H:%M:%S", time.localtime(e["ts"]))

    threats_raw = memory.get_threats()
    for t in threats_raw:
        try:   t["indicators_parsed"] = json.loads(t.get("indicators","{}"))
        except:t["indicators_parsed"] = {}

    map_devs = [{"ip":d["ip"],"name":d["display_name"],"score":d["score"]} for d in devs]

    return render_template_string(HTML,
        devs=devs,
        total=len(devs),
        trusted=sum(1 for d in devs if d["score"]>=80),
        normal=sum(1 for d in devs if 60<=d["score"]<80),
        suspicious=sum(1 for d in devs if 40<=d["score"]<60),
        dangerous=sum(1 for d in devs if 0<d["score"]<40),
        blocked_count=len(actions.blocked_ips),
        blocked_list=list(actions.blocked_ips),
        alerts=alerts_raw,
        alerts_count=len(alerts_raw),
        talkers=talkers[:12],
        evo_log=evo_log,
        trust_weights=evolution.trust_weights,
        threats=threats_raw,
        threats_count=len(threats_raw),
        packet_senders=packet_data["senders"],
        packet_receivers=packet_data["receivers"],
        packet_summary=packet_data["summary"],
        proximity_devs=getattr(proximity, 'nearby_devices', {}),
        map_json=json.dumps({"devices":map_devs}),
        now=time.time(),
	cur_time=time.strftime("%H:%M:%S"),
    )

@app.route("/api/block/<ip>",   methods=["POST"])
def api_block(ip):
    if not sensors._is_lan(ip) or ip not in sensors.devices:
        return jsonify({"ok":False,"error":"unknown LAN device"}), 400
    actions.block(ip, reason="dashboard"); return jsonify({"ok":True})

@app.route("/api/unblock/<ip>", methods=["POST"])
def api_unblock(ip):
    if not sensors._is_lan(ip) or ip not in sensors.devices:
        return jsonify({"ok":False,"error":"unknown LAN device"}), 400
    actions.unblock(ip); return jsonify({"ok":True})

@app.route("/api/notify/<ip>",  methods=["POST"])
def api_notify(ip):
    if not sensors._is_lan(ip) or ip not in sensors.devices:
        return jsonify({"ok":False,"error":"unknown LAN device"}), 400
    data = request.get_json(silent=True) or {}
    msg  = data.get("message","")
    if not msg: return jsonify({"error":"no message"}),400
    actions.send_notification(ip, data.get("title","NERO"), msg)
    return jsonify({"ok":True})

@app.route("/api/outcome/<int:alert_id>/<outcome>", methods=["POST"])
def api_outcome(alert_id, outcome):
    if outcome not in {"confirmed_threat", "false_positive"}:
        return jsonify({"ok":False,"error":"invalid outcome"}), 400
    memory.update_alert_outcome(alert_id, outcome)
    return jsonify({"ok":True})

@app.route("/api/evolution/approve/<int:evo_id>", methods=["POST"])
def api_approve(evo_id):
    ok, msg = evolution.apply_pending_patch(evo_id)
    return jsonify({"ok":ok,"message":msg})

@app.route("/api/evolution/rollback", methods=["POST"])
def api_rollback():
    ok, msg = evolution.rollback()
    return jsonify({"ok":ok,"message":msg})

@app.route("/api/device/<ip>")
def api_device(ip):
    if not sensors._is_lan(ip) or ip not in sensors.devices:
        return jsonify({"error":"unknown LAN device"}), 404
    dev      = sensors.devices.get(ip, {})
    rc       = dev.get("recon", {})
    apps     = sorted(list(recon.detected_apps.get(ip, set())))
    services = sorted(list(recon.mdns_services.get(ip, set())))
    svc_desc = {s: recon.SERVICE_MEANINGS.get(s, s) for s in services}
    return jsonify({
        "ip":         ip,
        "name":       dev.get("name",""),
        "mac":        dev.get("mac",""),
        "os":         dev.get("os",""),
        "vendor":     dev.get("vendor","") or rc.get("vendor",""),
        "model":      rc.get("model","") or rc.get("upnp",{}).get("modelName",""),
        "http_title": rc.get("http_title",""),
        "ssh_banner": dev.get("ssh_banner",""),
        "apps":       apps,
        "services":   services,
        "svc_descriptions": svc_desc,
        "tcp_fp":     dev.get("tcp_fp",{}),
        "dns":        sensors.dns_history.get(ip,[]),
        "packets":    dev.get("packets",0),
        "trust":      brain.trust_scores.get(ip,50),
        "blocked":    ip in actions.blocked_ips,
        "open_ports":  _masscan.get_open_ports(ip) if _masscan else dev.get("open_ports",[]),
        "nikto":       _nikto.get_findings(ip) if _nikto else [],
        "vuln_level":  _nikto.get_worst_severity(ip) if _nikto else "none",
    })

@app.route("/api/status")
def api_status():
    return jsonify({
        "devices":     len(sensors.devices),
        "blocked":     list(actions.blocked_ips),
        "trust_scores":dict(brain.trust_scores),
        "alerts":      len(memory.get_alerts(100)),
    })

def start():
    app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False)
