from flask import Flask, render_template_string
import threading
import time

app = Flask(__name__)

# import shared state from nero
try:
    from nero import devices, trust_scores, dna_store, anomaly_models, mac_history
except:
    devices = {}
    trust_scores = {}
    dna_store = {}
    anomaly_models = {}
    mac_history = {}

HTML = """
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="5">
<title>NERO Dashboard</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body {
    background: #060810;
    color: #cce0ff;
    font-family: monospace;
    padding: 16px;
}
h1 {
    color: #00ff88;
    letter-spacing: 6px;
    font-size: 24px;
    margin-bottom: 4px;
}
.subtitle {
    color: rgba(200,220,255,0.4);
    font-size: 11px;
    letter-spacing: 2px;
    margin-bottom: 20px;
}
.stats-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 10px;
    margin-bottom: 20px;
}
.stat-box {
    background: #0c1220;
    border: 1px solid rgba(255,255,255,0.07);
    border-radius: 8px;
    padding: 14px;
    text-align: center;
}
.stat-val {
    font-size: 28px;
    font-weight: bold;
    line-height: 1;
    margin-bottom: 4px;
}
.stat-lbl {
    font-size: 9px;
    letter-spacing: 2px;
    color: rgba(200,220,255,0.4);
}
.section-title {
    font-size: 9px;
    letter-spacing: 3px;
    color: rgba(200,220,255,0.35);
    margin-bottom: 10px;
    text-transform: uppercase;
}
.device-card {
    background: #0c1220;
    border: 1px solid rgba(255,255,255,0.07);
    border-radius: 8px;
    padding: 12px 14px;
    margin-bottom: 8px;
    position: relative;
    overflow: hidden;
}
.device-card::before {
    content: '';
    position: absolute;
    left: 0; top: 0; bottom: 0;
    width: 3px;
    border-radius: 1px;
}
.trusted::before  { background: #00ff88; }
.normal::before   { background: #00d4ff; }
.suspicious::before { background: #ffaa00; }
.dangerous::before  { background: #ff3366; }
.blocked::before    { background: #ff3366; }
.card-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 6px;
}
.card-ip {
    font-size: 14px;
    font-weight: bold;
}
.card-mac {
    font-size: 10px;
    color: rgba(200,220,255,0.35);
    margin-top: 2px;
}
.trust-badge {
    font-size: 11px;
    font-weight: bold;
    padding: 3px 10px;
    border-radius: 4px;
}
.trust-bar {
    height: 3px;
    background: rgba(255,255,255,0.06);
    border-radius: 2px;
    overflow: hidden;
    margin-bottom: 6px;
}
.trust-fill {
    height: 100%;
    border-radius: 2px;
}
.card-chips {
    display: flex;
    gap: 4px;
    flex-wrap: wrap;
}
.chip {
    font-size: 9px;
    padding: 2px 6px;
    border-radius: 3px;
    background: rgba(255,255,255,0.05);
    color: rgba(200,220,255,0.5);
    border: 1px solid rgba(255,255,255,0.06);
}
.chip-warn {
    background: rgba(255,51,102,0.1);
    color: #ff3366;
    border-color: rgba(255,51,102,0.2);
}
.chip-ai {
    background: rgba(0,255,136,0.07);
    color: #00ff88;
    border-color: rgba(0,255,136,0.15);
}
.footer {
    margin-top: 20px;
    text-align: center;
    font-size: 10px;
    color: rgba(200,220,255,0.2);
    letter-spacing: 2px;
}
</style>
</head>
<body>

<h1>NERO</h1>
<div class="subtitle">NETWORK SECURITY DASHBOARD — AUTO REFRESH 5s</div>

<div class="stats-row">
    <div class="stat-box">
        <div class="stat-val" style="color:#00ff88">{{ total }}</div>
        <div class="stat-lbl">DEVICES</div>
    </div>
    <div class="stat-box">
        <div class="stat-val" style="color:#00d4ff">{{ trusted }}</div>
        <div class="stat-lbl">TRUSTED</div>
    </div>
    <div class="stat-box">
        <div class="stat-val" style="color:#ffaa00">{{ suspicious }}</div>
        <div class="stat-lbl">SUSPICIOUS</div>
    </div>
    <div class="stat-box">
        <div class="stat-val" style="color:#ff3366">{{ dangerous }}</div>
        <div class="stat-lbl">DANGEROUS</div>
    </div>
</div>

<div class="section-title">Live Device Intelligence</div>

{% for d in devs %}
<div class="device-card {{ d.cls }}">
    <div class="card-top">
        <div>
            <div class="card-ip">{{ d.ip }}</div>
            <div class="card-mac">{{ d.mac }}</div>
        </div>
        <div class="trust-badge" style="background:{{ d.bg }};color:{{ d.col }}">
            {{ d.emoji }} {{ d.score }}/100
        </div>
    </div>
    <div class="trust-bar">
        <div class="trust-fill" style="width:{{ d.score }}%;background:{{ d.col }}"></div>
    </div>
    <div class="card-chips">
        <span class="chip">{{ d.label }}</span>
        <span class="chip">visits: {{ d.visits }}</span>
        <span class="chip">{{ d.dna_samples }} DNA samples</span>
        {% if d.ai_trained %}
        <span class="chip chip-ai">AI TRAINED</span>
        {% endif %}
        {% if d.spoofed %}
        <span class="chip chip-warn">⚠ MAC CHANGED</span>
        {% endif %}
    </div>
</div>
{% endfor %}

{% if not devs %}
<div style="text-align:center;padding:40px;color:rgba(200,220,255,0.3);">
    Waiting for devices to join the network...<br>
    Make sure NERO is running: sudo python3 nero.py
</div>
{% endif %}

<div class="footer">
    NERO v1.0 — {{ time }} — {{ total }} devices monitored
</div>

</body>
</html>
"""

def fmt_device(ip, dev):
    score = trust_scores.get(ip, 50)

    if score >= 80:
        cls, label, col, bg, emoji = "trusted",    "TRUSTED",    "#00ff88", "rgba(0,255,136,0.1)",  "🟢"
    elif score >= 60:
        cls, label, col, bg, emoji = "normal",     "NORMAL",     "#00d4ff", "rgba(0,212,255,0.1)",  "🟡"
    elif score >= 40:
        cls, label, col, bg, emoji = "suspicious", "SUSPICIOUS", "#ffaa00", "rgba(255,170,0,0.1)",  "🟠"
    elif score >= 20:
        cls, label, col, bg, emoji = "dangerous",  "DANGEROUS",  "#ff3366", "rgba(255,51,102,0.1)", "🔴"
    else:
        cls, label, col, bg, emoji = "blocked",    "BLOCKED",    "#ff3366", "rgba(255,51,102,0.15)","🔴"

    macs    = mac_history.get(ip, set())
    spoofed = len(macs) > 1
    dna_samples = len(dna_store.get(ip, []))
    ai_trained  = ip in anomaly_models

    return {
        "ip":          ip,
        "mac":         dev.get("mac", "unknown"),
        "score":       score,
        "cls":         cls,
        "label":       label,
        "col":         col,
        "bg":          bg,
        "emoji":       emoji,
        "visits":      dev.get("visits", 1),
        "dna_samples": dna_samples,
        "ai_trained":  ai_trained,
        "spoofed":     spoofed,
    }

@app.route("/")
def index():
    devs = [fmt_device(ip, dev) for ip, dev in devices.items()]
    devs = sorted(devs, key=lambda x: x["score"])

    trusted    = sum(1 for d in devs if d["score"] >= 80)
    suspicious = sum(1 for d in devs if 40 <= d["score"] < 60)
    dangerous  = sum(1 for d in devs if d["score"] < 40)

    return render_template_string(HTML,
        devs=devs,
        total=len(devs),
        trusted=trusted,
        suspicious=suspicious,
        dangerous=dangerous,
        time=time.strftime("%H:%M:%S")
    )

@app.route("/api")
def api():
    return {
        "devices":     len(devices),
        "trust_scores": dict(trust_scores),
        "ai_models":   list(anomaly_models.keys()),
    }

def start():
    app.run(host="0.0.0.0", port=8081, debug=False, use_reloader=False)

if __name__ == "__main__":
    start()
