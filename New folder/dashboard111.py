from __future__ import annotations

from flask import Flask, render_template_string, jsonify, request
import time, threading, json

app = Flask(__name__)

# Injected by main.py
devices           = {}
dns_history       = {}
alert_history     = []
bandwidth_samples = {}
blocked_devices   = set()
restore_device    = None
state_lock        = threading.RLock()

try:
    import notifier as _notifier
except Exception as _e:
    print(f"[DASHBOARD] notifier not loaded: {_e}")
    _notifier = None

HTML = """<!DOCTYPE html>
<html>
<head>
    <title>NERO PLATINUM</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@700&display=swap');
        :root{--bg:#050508;--neon:#00ffd2;--danger:#ff0055;--panel:rgba(15,15,30,0.95);}
        body{background:var(--bg);color:#fff;font-family:'Share Tech Mono';margin:0;}
        .header{border-bottom:1px solid var(--neon);padding:20px;display:flex;justify-content:space-between;align-items:center;background:#000;}
        .logo{font-family:'Rajdhani';font-size:24px;color:var(--neon);letter-spacing:10px;}
        .live{font-size:11px;color:var(--neon);opacity:.6;display:flex;align-items:center;gap:8px;}
        .pulse{width:7px;height:7px;border-radius:50%;background:var(--neon);animation:pulse 2s infinite;}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:.2}}
        .stats{display:flex;gap:16px;padding:16px 20px;border-bottom:1px solid #111;}
        .stat{background:rgba(0,255,210,0.05);border:1px solid #1a1a2e;border-radius:4px;padding:10px 20px;text-align:center;}
        .stat-val{font-size:22px;font-weight:bold;color:var(--neon);}
        .stat-lbl{font-size:9px;opacity:.5;letter-spacing:2px;margin-top:2px;}
        .grid{display:grid;grid-template-columns:1fr 380px;gap:20px;padding:20px;}
        .card{background:var(--panel);border:1px solid #111;padding:16px 20px;border-radius:4px;margin-bottom:12px;transition:.2s;}
        .card:hover{border-color:#1a1a3e;}
        .card.jailed{border-left:4px solid var(--danger);background:rgba(255,0,85,0.04);}
        .card-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;}
        .card-ip{font-size:18px;display:flex;align-items:center;gap:8px;}
        .badge{font-size:9px;padding:2px 7px;border-radius:3px;letter-spacing:1px;}
        .badge-ok{background:rgba(0,255,210,0.1);color:var(--neon);border:1px solid rgba(0,255,210,0.2);}
        .badge-jail{background:rgba(255,0,85,0.15);color:var(--danger);border:1px solid rgba(255,0,85,0.3);}
        .card-meta{font-size:11px;opacity:.5;line-height:1.9;}
        .card-meta span{color:var(--neon);opacity:.8;}
        .btn{padding:7px 16px;border:1px solid var(--neon);background:none;color:var(--neon);cursor:pointer;font-family:inherit;font-size:10px;letter-spacing:1px;border-radius:3px;transition:.2s;}
        .btn:hover{background:var(--neon);color:#000;}
        .btn-kill{border-color:var(--danger);color:var(--danger);}
        .btn-kill:hover{background:var(--danger);color:#fff;}
        .log{background:rgba(0,0,0,0.85);padding:16px;font-size:11px;height:80vh;overflow-y:auto;color:var(--neon);border:1px solid #1a1a2e;border-radius:4px;}
        .log-hdr{border-bottom:1px solid #222;margin-bottom:12px;padding-bottom:8px;opacity:.5;font-size:10px;letter-spacing:2px;}
        .log-row{margin-bottom:6px;line-height:1.5;}
        .log-time{opacity:.4;}
        .log-warn{color:#ffaa00;}
        .log-danger{color:var(--danger);}
        .empty{opacity:.3;text-align:center;padding:40px;font-size:13px;}
        @media(max-width:800px){.grid{grid-template-columns:1fr;}.stats{flex-wrap:wrap;}}

        /* DEVICE POPUP */
        .overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.75);
                 z-index:100;align-items:center;justify-content:center;}
        .overlay.open{display:flex;}
        .popup{background:#0c0f1a;border:1px solid #ff0055;border-radius:12px;
               padding:28px 32px;width:90%;max-width:420px;position:relative;}
        .popup-close{position:absolute;top:12px;right:16px;background:none;
                     border:none;color:rgba(255,255,255,0.4);font-size:18px;
                     cursor:pointer;font-family:inherit;}
        .popup-close:hover{color:#fff;}
        .popup-ip{font-size:11px;color:#ff0055;letter-spacing:3px;margin-bottom:4px;}
        .popup-name{font-size:20px;font-weight:bold;margin-bottom:18px;}
        .popup-section{font-size:9px;letter-spacing:3px;color:rgba(255,255,255,0.3);
                       margin:14px 0 8px;text-transform:uppercase;}
        .popup-input{width:100%;background:#050508;border:1px solid #222;
                     border-radius:6px;padding:10px 12px;color:#fff;
                     font-family:'Share Tech Mono',monospace;font-size:13px;
                     outline:none;margin-bottom:8px;}
        .popup-input:focus{border-color:#ff0055;}
        textarea.popup-input{resize:vertical;min-height:80px;}
        .popup-actions{display:flex;gap:8px;margin-top:6px;}
        .popup-btn{flex:1;padding:10px;border-radius:6px;cursor:pointer;
                   font-family:'Share Tech Mono',monospace;font-size:11px;
                   letter-spacing:1px;transition:.2s;border:1px solid;}
        .btn-send{border-color:#ff0055;background:rgba(255,0,85,0.1);color:#ff0055;}
        .btn-send:hover{background:#ff0055;color:#fff;}
        .btn-isolate-p{border-color:#00ffd2;background:rgba(0,255,210,0.07);color:#00ffd2;}
        .btn-isolate-p:hover{background:#00ffd2;color:#000;}
        .popup-status{font-size:10px;color:#00ffd2;margin-top:8px;
                      min-height:16px;text-align:center;}
    </style>
</head>
<body>
<div class="header">
    <div class="logo">NERO</div>
    <div class="live"><span class="pulse"></span> LIVE &mdash; {{ cur_time }} &mdash; {{ total }} devices</div>
</div>
<div class="stats">
    <div class="stat"><div class="stat-val" style="color:var(--neon)">{{ total }}</div><div class="stat-lbl">DEVICES</div></div>
    <div class="stat"><div class="stat-val" style="color:#ffaa00">{{ jailed }}</div><div class="stat-lbl">ISOLATED</div></div>
    <div class="stat"><div class="stat-val">{{ alerts_count }}</div><div class="stat-lbl">EVENTS</div></div>
    <div class="stat"><div class="stat-val">{{ total_bw }}</div><div class="stat-lbl">TOTAL B/s</div></div>
</div>
<div class="grid">
    <div id="nodes">
        {% if not devices %}
        <div class="empty">Waiting for devices on 192.168.1.0/24...</div>
        {% endif %}
        {% for ip, d in devices.items() %}
        <div class="card {{ 'jailed' if ip in blocked_devices }}" onclick="openPopup('{{ ip }}', '{{ d.name or ip }}')" style="cursor:pointer;">
            <div class="card-top">
                <div class="card-ip">
                    <div>
                        {% if d.name %}
                        <div style="font-size:20px;color:var(--neon);letter-spacing:1px;">{{ d.name }}</div>
                        <div style="font-size:12px;opacity:0.45;margin-top:2px;">{{ ip }}</div>
                        {% else %}
                        <div style="font-size:20px;">{{ ip }}</div>
                        <div style="font-size:11px;opacity:0.35;margin-top:2px;">name not detected yet...</div>
                        {% endif %}
                    </div>
                    {% if ip in blocked_devices %}
                    <span class="badge badge-jail">ISOLATED</span>
                    {% else %}
                    <span class="badge badge-ok">ONLINE</span>
                    {% endif %}
                </div>
                <button class="btn {{ 'btn-kill' if ip not in blocked_devices }}"
                        onclick="event.stopPropagation();toggle('{{ ip }}')">
                    {{ 'RESTORE' if ip in blocked_devices else 'ISOLATE' }}
                </button>
            </div>
            <div class="card-meta">
                OS: <span>{{ d.os }}</span> &nbsp;|&nbsp;
                MAC: <span>{{ d.mac }}</span><br>
                TRAFFIC: <span>{{ bandwidth_samples.get(ip, 0) }} B/s</span> &nbsp;|&nbsp;
                PACKETS: <span>{{ d.packets }}</span>
                {% set domains = dns_history.get(ip, []) %}
                {% if domains %}
                <div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:5px;">
                {% for domain in domains %}
                <span style="font-size:10px;padding:2px 8px;border-radius:3px;background:rgba(0,255,210,0.07);color:#00ffd2;border:1px solid rgba(0,255,210,0.15);">{{ domain }}</span>
                {% endfor %}
                </div>
                {% endif %}
            </div>
        </div>
        {% endfor %}
    </div>
    <div class="log">
        <div class="log-hdr">&gt; LIVE_NETWORK_LOG</div>
        {% if not alerts %}
        <div style="opacity:.3;font-size:12px;">No events yet...</div>
        {% endif %}
        {% for a in alerts %}
        <div class="log-row {{ 'log-danger' if 'ISOLATED' in a.message else 'log-warn' if 'WARN' in a.message else '' }}">
            <span class="log-time">[{{ a.time }}]</span> {{ a.message }}
        </div>
        {% endfor %}
    </div>
</div>
<!-- DEVICE POPUP -->
<div class="overlay" id="popup-overlay">
  <div class="popup">
    <button class="popup-close" onclick="closePopup()">✕</button>
    <div class="popup-ip" id="popup-ip-label"></div>
    <div class="popup-name" id="popup-name-label"></div>

    <div class="popup-section">Send Notification</div>
    <input  class="popup-input" id="notif-title"   placeholder="Title — e.g. Hey!" />
    <textarea class="popup-input" id="notif-msg"   placeholder="Message — e.g. Come for dinner"></textarea>
    <div class="popup-actions">
      <button class="popup-btn btn-send" onclick="sendNotif()">📡 SEND</button>
      <button class="popup-btn btn-isolate-p" id="popup-isolate-btn" onclick="popupToggleIsolate()">ISOLATE</button>
    </div>
    <div class="popup-status" id="popup-status"></div>
  </div>
</div>

<script>
    function toggle(ip) {
        fetch('/api/toggle/'+ip, {method:'POST'}).then(()=>location.reload());
    }

    let _currentIP   = "";
    let _currentName = "";
    let _blockedIPs  = {{ blocked_ips_json|safe }};

    function openPopup(ip, name) {
        _currentIP   = ip;
        _currentName = name || ip;
        document.getElementById('popup-ip-label').textContent   = ip;
        document.getElementById('popup-name-label').textContent = name || ip;
        document.getElementById('popup-status').textContent     = '';
        document.getElementById('notif-title').value            = '';
        document.getElementById('notif-msg').value              = '';
        const isBlocked = _blockedIPs.includes(ip);
        document.getElementById('popup-isolate-btn').textContent = isBlocked ? '✓ RESTORE' : 'ISOLATE';
        document.getElementById('popup-overlay').classList.add('open');
    }
    function closePopup() {
        document.getElementById('popup-overlay').classList.remove('open');
    }
    document.getElementById('popup-overlay').addEventListener('click', function(e){
        if(e.target === this) closePopup();
    });

    function sendNotif() {
        const title = document.getElementById('notif-title').value.trim();
        const msg   = document.getElementById('notif-msg').value.trim();
        if (!msg) { document.getElementById('popup-status').textContent = 'Enter a message first.'; return; }
        fetch('/api/notify/' + _currentIP, {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({title: title || 'NERO Alert', message: msg})
        }).then(r => r.json()).then(d => {
            document.getElementById('popup-status').textContent = '✓ Notification sent — they will see it on next page load';
        }).catch(() => {
            document.getElementById('popup-status').textContent = '✗ Failed to send';
        });
    }

    function popupToggleIsolate() {
        fetch('/api/toggle/' + _currentIP, {method:'POST'}).then(() => location.reload());
    }

    // Auto-refresh every 5s
    let _reload = setInterval(()=>{ if(!document.hidden) location.reload(); }, 5000);
</script>
</body>
</html>"""

@app.route("/")
def index():
    global devices, dns_history, alert_history, bandwidth_samples, blocked_devices, state_lock
    # Snapshot under lock to avoid "dict changed size during iteration"
    with state_lock:
        devices_snap = dict(devices)
        dns_snap = {k: list(v) for k, v in dns_history.items()}
        alerts_snap = list(alert_history)
        bw_snap = dict(bandwidth_samples)
        blocked_snap = set(blocked_devices)

    total_bw = sum(bw_snap.get(ip, 0) for ip in devices_snap)
    return render_template_string(HTML,
        devices=devices_snap,
        dns_history=dns_snap,
        alerts=list(reversed(alerts_snap))[:50],
        alerts_count=len(alerts_snap),
        bandwidth_samples=bw_snap,
        blocked_devices=blocked_snap,
        total=len(devices_snap),
        jailed=len(blocked_snap),
        total_bw=total_bw,
        cur_time=time.strftime("%H:%M:%S"),
        blocked_ips_json=json.dumps(list(blocked_snap)),
    )

@app.route("/api/toggle/<ip>", methods=["POST"])
def api_toggle(ip):
    global blocked_devices, state_lock
    do_restore = False
    with state_lock:
        if ip in blocked_devices:
            blocked_devices.discard(ip)
            do_restore = True
            alert_history.append({"time": time.strftime("%H:%M:%S"), "message": f"RESTORED: {ip}"})
        else:
            blocked_devices.add(ip)
            alert_history.append({"time": time.strftime("%H:%M:%S"), "message": f"ISOLATED: {ip}"})

    if do_restore and restore_device:
        threading.Thread(target=restore_device, args=(ip,), daemon=True).start()
    return jsonify({"status": "ok"})

@app.route("/api/notify/<ip>", methods=["POST"])
def api_notify(ip):
    data    = request.get_json(force=True)
    title   = data.get("title",   "NERO Alert")
    message = data.get("message", "")
    if not message:
        return jsonify({"error": "no message"}), 400
    if _notifier:
        _notifier.send_notification(ip, title, message, duration=60)
        with state_lock:
            alert_history.append({
                "time":    time.strftime("%H:%M:%S"),
                "message": f"NOTIFICATION → {ip}: {title}"
            })
        return jsonify({"ok": True})
    return jsonify({"error": "notifier module not available"}), 500

def start():
    app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False)
