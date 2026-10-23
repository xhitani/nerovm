from flask import Flask, render_template_string, jsonify, request
import time, threading, os

app = Flask(__name__)

# Memory Sync
devices = {}; trust_scores = {}; dns_history = {}; alert_history = []; bandwidth_samples = {}; blocked_devices = set()

HTML = """<!DOCTYPE html>
<html>
<head>
    <title>NERO v4.0 | COMMAND</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@600&display=swap');
        :root { --bg:#05050a; --green:#00ffcc; --red:#ff2a6d; --cyan:#05d9e8; --border:rgba(0,255,204,0.1); }
        body { background:var(--bg); color:#fff; font-family:'Share Tech Mono'; margin:0; overflow:hidden; }
        .header { background:rgba(0,0,0,0.9); padding:10px 30px; border-bottom:1px solid var(--green); display:flex; justify-content:space-between; align-items:center; }
        .grid { display:grid; grid-template-columns: 1fr 400px; gap:20px; padding:20px; height:calc(100vh - 80px); }
        .card { background:rgba(20,20,35,0.8); border:1px solid var(--border); padding:15px; border-radius:4px; margin-bottom:10px; cursor:pointer; transition:0.2s; position:relative; }
        .card:hover { border-color:var(--green); box-shadow: 0 0 15px rgba(0,255,204,0.2); }
        .card.jailed { border-left: 5px solid var(--red); background:rgba(255,42,109,0.05); }
        #modal { display:none; position:fixed; top:50%; left:50%; transform:translate(-50%, -50%); width:450px; background:#0a0a1a; border:2px solid var(--cyan); padding:25px; z-index:1000; box-shadow:0 0 80px rgba(5,217,232,0.4); border-radius:8px; }
        #overlay { display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.9); z-index:999; backdrop-filter: blur(4px); }
        .btn { padding:10px 15px; font-family:inherit; cursor:pointer; border:1px solid var(--cyan); background:none; color:var(--cyan); transition:0.2s; text-transform:uppercase; font-size:11px; }
        .btn:hover { background:var(--cyan); color:black; }
        .btn-red { border-color:var(--red); color:var(--red); }
        .btn-red:hover { background:var(--red); color:white; }
        .log { background:#0a0a15; border:1px solid var(--border); height:100%; padding:15px; overflow-y:auto; font-size:11px; color:var(--cyan); }
    </style>
</head>
<body>
    <div id="overlay" onclick="closeModal()"></div>
    <div id="modal">
        <h2 id="m-ip" style="color:var(--cyan); font-family:Rajdhani; margin-top:0; letter-spacing:2px;">NODE_ACCESS</h2>
        <div style="font-size:12px; margin-bottom:20px; opacity:0.8;">
            <div style="margin-bottom:5px;">MAC: <span id="m-mac" style="color:#fff;"></span></div>
            <div style="margin-bottom:5px;">OS: <span id="m-os" style="color:var(--green);"></span></div>
            <div style="margin-bottom:5px;">STATUS: <span id="m-status"></span></div>
        </div>
        <div style="background:rgba(255,255,255,0.05); padding:12px; border-radius:4px; font-size:11px; margin-bottom:20px; border-left:2px solid var(--cyan);">
            LAST_DNS_REQUEST: <span id="m-dns" style="color:#fff;"></span>
        </div>
        <div style="display:flex; gap:10px;">
            <button id="kill-btn" class="btn btn-red" onclick="toggleInternet()">ISOLATE NODE</button>
            <button class="btn" onclick="scanNode()">NMAP_SCAN</button>
            <button class="btn" style="border-color:#fff; color:#fff;" onclick="closeModal()">CLOSE</button>
        </div>
    </div>

    <div class="header">
        <div style="font-family:Rajdhani; font-size:26px; color:var(--green); letter-spacing:8px;">NERO <span style="color:white">COMMAND</span></div>
        <div style="text-align:right; font-size:10px; letter-spacing:1px;">
            <div style="color:var(--cyan); margin-bottom:2px;">NET_LOAD: {{ total_bw }} B/s</div>
            <div style="color:var(--green);">[ SYSTEM_LIVE | {{ devices|length }} NODES ]</div>
        </div>
    </div>

    <div class="grid">
        <div style="overflow-y:auto; padding-right:5px;">
            {% for ip, d in devices.items() %}
            <div class="card {{ 'jailed' if ip in blocked_devices }}" onclick="openModal('{{ ip }}', '{{ d.mac }}', '{{ d.os }}', '{{ dns_history.get(ip, 'Listening...') }}', {{ 'true' if ip in blocked_devices else 'false' }})">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span style="font-size:18px; letter-spacing:1px;">{{ ip }}</span>
                    <span style="font-size:9px; color:var(--cyan); border:1px solid var(--border); padding:2px 6px;">{{ d.os }}</span>
                </div>
                <div style="font-size:10px; color:var(--green); margin-top:10px; opacity:0.7;">
                    FLOW: {{ bandwidth_samples.get(ip, 0) }} B/s | PKTS_RECV: {{ d.get('packets', 0) }}
                </div>
            </div>
            {% endfor %}
        </div>
        <div class="log">
            <div style="color:var(--green); margin-bottom:12px; border-bottom:1px solid var(--border); padding-bottom:5px; font-family:Rajdhani;">SEC_EVENT_STREAM</div>
            {% for a in alerts %}
            <div style="margin-bottom:6px; line-height:1.4;">
                <span style="color:#444;">{{ a.time }}</span> <span style="color:var(--red);">[{{ a.type }}]</span> <span style="color:#eee;">{{ a.message }}</span>
            </div>
            {% endfor %}
        </div>
    </div>

    <script>
        let currentIp = "";
        function openModal(ip, mac, os, dns, isJailed) {
            currentIp = ip;
            document.getElementById('m-ip').innerText = "NODE: " + ip;
            document.getElementById('m-mac').innerText = mac;
            document.getElementById('m-os').innerText = os;
            document.getElementById('m-dns').innerText = dns;
            document.getElementById('m-status').innerText = isJailed ? "JAILED / OFFLINE" : "ACTIVE / ONLINE";
            document.getElementById('m-status').style.color = isJailed ? "var(--red)" : "var(--green)";
            document.getElementById('kill-btn').innerText = isJailed ? "RESTORE ACCESS" : "ISOLATE NODE";
            document.getElementById('modal').style.display = 'block';
            document.getElementById('overlay').style.display = 'block';
        }
        function closeModal() {
            document.getElementById('modal').style.display = 'none';
            document.getElementById('overlay').style.display = 'none';
        }
        function toggleInternet() {
            fetch('/api/toggle/' + currentIp, {method:'POST'}).then(() => location.reload());
        }
        function scanNode() {
            fetch('/api/scan/' + currentIp, {method:'POST'});
            alert("Nmap Stealth Scan Initiated for " + currentIp + ". Check terminal for progress.");
        }
        setInterval(() => { if(!document.hidden && document.getElementById('modal').style.display !== 'block') location.reload(); }, 3000);
    </script>
</body>
</html>"""

@app.route("/")
def index():
    total_bw = sum(bandwidth_samples.values())
    return render_template_string(HTML, devices=devices, dns_history=dns_history, alerts=list(reversed(alert_history))[:40], bandwidth_samples=bandwidth_samples, blocked_devices=blocked_devices, total_bw=total_bw)

@app.route("/api/toggle/<ip>", methods=["POST"])
def api_toggle(ip):
    if ip in blocked_devices: blocked_devices.remove(ip)
    else: blocked_devices.add(ip)
    return jsonify({"status":"ok"})

@app.route("/api/scan/<ip>", methods=["POST"])
def api_scan(ip):
    def run_scan(target):
        print(f"--- NMAP SCAN START: {target} ---")
        os.system(f"nmap -F {target}") 
        print(f"--- NMAP SCAN COMPLETE: {target} ---")
    threading.Thread(target=run_scan, args=(ip,)).start()
    return jsonify({"status":"ok"})

def start():
    app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False)
