"""
NERO Notifier — notifier.py
Serves a Flask app on port 80.
When a notification is sent to an IP, DNS queries from that device
are spoofed so their next website visit shows the NERO alert page.
"""
from __future__ import annotations

from flask import Flask, request, jsonify, render_template_string
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send, sniff
import threading, time, socket, os

notify_app = Flask(__name__)

INTERFACE  = "enp0s3"
ROUTER_IP  = "192.168.1.1"
ENABLE_DNS_SPOOF = False

# ip -> {title, message, expires}
active_notifications = {}
_lock = threading.Lock()

def get_nero_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.1.50"

NERO_IP = get_nero_ip()

# ─────────────────────────────────────────────────────────────────
# NOTIFICATION PAGE (served on port 80 to the hijacked device)
# ─────────────────────────────────────────────────────────────────
ALERT_PAGE = """<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Message</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{
  background:#050508;color:#fff;
  font-family:'Courier New',monospace;
  min-height:100vh;display:flex;
  align-items:center;justify-content:center;
}
.box{
  background:rgba(255,0,85,0.06);
  border:2px solid #ff0055;
  border-radius:14px;
  padding:44px 52px;
  max-width:480px;width:90%;
  text-align:center;
  animation:pulse 2s infinite;
}
@keyframes pulse{
  0%,100%{box-shadow:0 0 40px rgba(255,0,85,0.2);}
  50%{box-shadow:0 0 80px rgba(255,0,85,0.45);}
}
.icon{font-size:56px;margin-bottom:18px;}
.from{font-size:10px;letter-spacing:4px;color:#ff0055;margin-bottom:8px;}
.title{font-size:24px;font-weight:bold;color:#ff0055;
       margin-bottom:14px;letter-spacing:1px;}
.msg{font-size:15px;line-height:1.8;
     color:rgba(255,255,255,0.82);margin-bottom:28px;}
.btn{padding:12px 32px;border:1px solid #ff0055;background:none;
     color:#ff0055;font-family:inherit;font-size:12px;
     letter-spacing:2px;cursor:pointer;border-radius:4px;transition:.2s;}
.btn:hover{background:#ff0055;color:#fff;}
.note{font-size:9px;color:rgba(255,255,255,0.2);
      margin-top:12px;letter-spacing:1px;}
</style>
</head>
<body>
<div class="box">
  <div class="icon">📡</div>
  <div class="from">── NERO NETWORK ALERT ──</div>
  <div class="title">{{ title }}</div>
  <div class="msg">{{ message }}</div>
  <button class="btn" onclick="fetch('/nero-dismiss').then(()=>document.body.style.display='none')">
    OK, GOT IT
  </button>
  <div class="note">sent from network administrator</div>
</div>
</body>
</html>"""

@notify_app.route("/", defaults={"path": ""})
@notify_app.route("/<path:path>")
def catch_all(path):
    """Catch every HTTP request from a notified device and show the alert."""
    src_ip = request.remote_addr
    with _lock:
        notif = active_notifications.get(src_ip)
    if notif and time.time() < notif["expires"]:
        return render_template_string(ALERT_PAGE,
            title=notif["title"],
            message=notif["message"])
    # Not a notified device — just return empty
    return "", 204

@notify_app.route("/nero-dismiss", methods=["GET","POST"])
def dismiss():
    src_ip = request.remote_addr
    with _lock:
        active_notifications.pop(src_ip, None)
    return jsonify({"ok": True})

def start_http():
    # Port 80 requires admin/root. Allow override via env for easier dev.
    port = int(os.environ.get("NERO_HTTP_PORT", "80"))
    notify_app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)

# ─────────────────────────────────────────────────────────────────
# DNS SPOOFER — intercepts DNS from notified IPs only
# ─────────────────────────────────────────────────────────────────
def dns_spoof_callback(pkt):
    if not (pkt.haslayer(DNS) and pkt.haslayer(UDP) and pkt.haslayer(IP)):
        return
    if pkt[DNS].qr != 0:
        return
    src_ip = pkt[IP].src
    with _lock:
        notif = active_notifications.get(src_ip)
    if not notif:
        return
    if time.time() > notif["expires"]:
        with _lock:
            active_notifications.pop(src_ip, None)
        return
    try:
        qname = pkt[DNSQR].qname
        # Build spoofed reply pointing to NERO
        spoofed = (
            IP(dst=src_ip, src=pkt[IP].dst) /
            UDP(dport=pkt[UDP].sport, sport=53) /
            DNS(
                id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                an=DNSRR(rrname=qname, ttl=1, rdata=NERO_IP)
            )
        )
        send(spoofed, iface=INTERFACE, verbose=False)
    except Exception as e:
        print(f"[DNS SPOOF] {e}")

def start_dns_spoofer():
    sniff(iface=INTERFACE, filter="udp port 53",
          prn=dns_spoof_callback, store=0)

# ─────────────────────────────────────────────────────────────────
# PUBLIC API — called from dashboard
# ─────────────────────────────────────────────────────────────────
def send_notification(ip, title, message, duration=30):
    """
    Send a notification to a device by IP.
    duration = how many seconds to keep DNS hijack active.
    """
    with _lock:
        active_notifications[ip] = {
            "title":   title,
            "message": message,
            "expires": time.time() + duration,
        }
    print(f"[NOTIFY] Sent to {ip}: '{title}' — active for {duration}s")

def start():
    print(f"[NOTIFIER] NERO IP: {NERO_IP}")
    print(f"[NOTIFIER] HTTP alert server on port {os.environ.get('NERO_HTTP_PORT', '80')}")
    if ENABLE_DNS_SPOOF:
        print("[NOTIFIER] DNS spoofer active (opt-in)")
    else:
        print("[NOTIFIER] DNS spoofer disabled (default)")
    threading.Thread(target=start_http,       daemon=True).start()
    if ENABLE_DNS_SPOOF:
        threading.Thread(target=start_dns_spoofer,daemon=True).start()
