"""
NERO Notifier — notifier.py
DNS spoofing + HTTP alert server.
When send_notification(ip, ...) is called:
  - DNS queries from that IP are answered with NERO's IP
  - Their next HTTP request shows a full-screen alert page
  - After dismiss or timeout, DNS restores to normal
"""
from flask import Flask, request, render_template_string, jsonify
from scapy.all import sniff, IP, UDP, DNS, DNSQR, DNSRR
import threading, time
import actions

notify_app = Flask("notifier")

ALERT_HTML = """<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Message</title>
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
  padding:44px 52px;max-width:480px;
  width:90%;text-align:center;
}
.icon{font-size:52px;margin-bottom:16px;}
.from{font-size:10px;letter-spacing:4px;color:#ff0055;margin-bottom:8px;}
.title{font-size:22px;font-weight:bold;color:#ff0055;margin-bottom:14px;}
.msg{font-size:15px;line-height:1.8;color:rgba(255,255,255,0.82);margin-bottom:28px;}
.btn{padding:12px 32px;border:1px solid #ff0055;background:none;
     color:#ff0055;font-family:inherit;font-size:12px;letter-spacing:2px;
     cursor:pointer;border-radius:4px;transition:.2s;}
.btn:hover{background:#ff0055;color:#fff;}
.note{font-size:9px;color:rgba(255,255,255,0.2);margin-top:12px;letter-spacing:1px;}
</style>
</head>
<body>
<div class="box">
  <div class="icon">📡</div>
  <div class="from">── NETWORK MESSAGE ──</div>
  <div class="title">{{ title }}</div>
  <div class="msg">{{ message }}</div>
  <button class="btn" onclick="fetch('/nero-ack').then(()=>window.location='about:blank')">
    OK, GOT IT
  </button>
  <div class="note">from your network administrator</div>
</div>
</body>
</html>"""

@notify_app.route("/", defaults={"path": ""})
@notify_app.route("/<path:path>")
def catch_all(path):
    src = request.remote_addr
    notif = actions.active_notifications.get(src)
    if notif and time.time() < notif["expires"]:
        return render_template_string(ALERT_HTML,
                                      title=notif["title"],
                                      message=notif["message"])
    return "", 204

@notify_app.route("/nero-ack")
def ack():
    src = request.remote_addr
    actions.active_notifications.pop(src, None)
    return jsonify({"ok": True})

def _dns_spoof_loop():
    from scapy.all import send
    def _cb(pkt):
        if not (pkt.haslayer(DNS) and pkt.haslayer(UDP) and pkt.haslayer(IP)):
            return
        if pkt[DNS].qr != 0:
            return
        src = pkt[IP].src
        notif = actions.active_notifications.get(src)
        if not notif or time.time() > notif["expires"]:
            if src in actions.active_notifications:
                actions.active_notifications.pop(src, None)
            return
        try:
            qname = pkt[DNSQR].qname
            reply = (
                IP(dst=src, src=pkt[IP].dst) /
                UDP(dport=pkt[UDP].sport, sport=53) /
                DNS(
                    id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                    an=DNSRR(rrname=qname, ttl=1, rdata=actions.NERO_IP)
                )
            )
            send(reply, iface=actions.INTERFACE, verbose=False)
        except Exception as e:
            print(f"[NOTIFIER] DNS spoof error: {e}")

    sniff(iface=actions.INTERFACE, filter="udp port 53",
          prn=_cb, store=0)

def start():
    threading.Thread(target=_dns_spoof_loop, daemon=True).start()
    threading.Thread(
        target=lambda: notify_app.run(
            host="0.0.0.0", port=80, debug=False, use_reloader=False),
        daemon=True
    ).start()
    print("[NOTIFIER] DNS spoofer + HTTP alert server on port 80")
