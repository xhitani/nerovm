"""
NERO Actions — actions.py
Auto-block via ARP poison, restore, Telegram alerts,
rate limiter, and notification dispatch.
All config injected by main.py — works on any network.
"""
import time, threading, socket, os
from scapy.all import Ether, ARP, srp, sendp
import sensors, brain, memory

_lock        = threading.Lock()
blocked_ips  = set()
_mac_cache   = {}

INTERFACE        = os.environ.get("NERO_INTERFACE", "enp0s3")
ROUTER_IP        = os.environ.get("NERO_ROUTER_IP", "192.168.1.1")
TELEGRAM_TOKEN   = ""
TELEGRAM_CHAT_ID = ""
active_notifications = {}

def get_nero_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close()
        return ip
    except Exception:
        try:
            import netifaces
            addrs = netifaces.ifaddresses(INTERFACE)
            return addrs[netifaces.AF_INET][0]['addr']
        except Exception:
            return "127.0.0.1"

NERO_IP = get_nero_ip()

def _get_mac(ip):
    if ip in _mac_cache:
        return _mac_cache[ip]
    dev = sensors.devices.get(ip, {})
    mac = dev.get("mac", "")
    if mac and mac != "ff:ff:ff:ff:ff:ff":
        _mac_cache[ip] = mac
        return mac
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                     iface=INTERFACE, timeout=1, verbose=False)
        if ans:
            _mac_cache[ip] = ans[0][1].hwsrc
            return _mac_cache[ip]
    except Exception:
        pass
    return None

def _arp_poison_loop():
    while True:
        time.sleep(3)
        with _lock:
            targets = set(blocked_ips)
        if not targets:
            continue
        router_mac = _get_mac(ROUTER_IP)
        if not router_mac:
            continue
        for ip in targets:
            target_mac = _mac_cache.get(ip) or _get_mac(ip)
            if not target_mac:
                continue
            try:
                pkt = Ether(dst=target_mac) / ARP(
                    op=2, pdst=ip, hwdst=target_mac,
                    psrc=ROUTER_IP, hwsrc="00:00:00:00:00:00"
                )
                sendp(pkt, iface=INTERFACE, verbose=False)
            except Exception as e:
                print(f"[ACTIONS] Poison error {ip}: {e}")

def _restore_arp(ip):
    router_mac = _get_mac(ROUTER_IP)
    target_mac = _mac_cache.get(ip) or _get_mac(ip)
    if not router_mac or not target_mac:
        return
    try:
        pkt = Ether(dst=target_mac) / ARP(
            op=2, pdst=ip, hwdst=target_mac,
            psrc=ROUTER_IP, hwsrc=router_mac
        )
        sendp(pkt, iface=INTERFACE, verbose=False, count=5)
        print(f"[ACTIONS] ARP restored for {ip}")
    except Exception as e:
        print(f"[ACTIONS] Restore error {ip}: {e}")

def block(ip, reason="manual"):
    with _lock:
        blocked_ips.add(ip)
    if ip in sensors.devices:
        sensors.devices[ip]["blocked"] = True
    memory.upsert_device(ip, blocked=1)
    memory.save_alert(ip, "BLOCKED", "high", f"Blocked: {reason}")
    alert(ip, "BLOCKED", f"IP {ip} blocked\nReason: {reason}")
    print(f"[ACTIONS] Blocked {ip} — {reason}")

def unblock(ip):
    with _lock:
        blocked_ips.discard(ip)
    if ip in sensors.devices:
        sensors.devices[ip]["blocked"] = False
    memory.upsert_device(ip, blocked=0)
    _restore_arp(ip)
    memory.save_alert(ip, "UNBLOCKED", "info", f"Unblocked {ip}")
    print(f"[ACTIONS] Unblocked {ip}")

def _auto_block_loop():
    low_count = {}
    while True:
        time.sleep(10)
        for ip, score in list(brain.trust_scores.items()):
            if ip in blocked_ips:
                continue
            if score < 20:
                low_count[ip] = low_count.get(ip, 0) + 1
                if low_count[ip] >= 3:
                    block(ip, reason=f"auto-block: trust={score}/100")
                    low_count[ip] = 0
            else:
                low_count[ip] = 0

def alert(ip, title, message, severity="info"):
    memory.save_alert(ip, title, severity, message)
    _send_telegram(f"*{title}*\n{message}")

def _send_telegram(text):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print(f"[ALERT] {text[:120]}")
        return
    try:
        import requests
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            data={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "Markdown"},
            timeout=5
        )
    except Exception as e:
        print(f"[ALERT] Telegram failed: {e}")

def send_notification(ip, title, message, duration=60):
    with _lock:
        active_notifications[ip] = {
            "title":   title,
            "message": message,
            "expires": time.time() + duration,
        }
    memory.save_alert(ip, "NOTIFICATION", "info", f"{title}: {message}")
    print(f"[ACTIONS] Notification queued for {ip}: {title}")

def rate_limit(ip, kbps=512):
    import subprocess
    subprocess.run([
        "iptables", "-I", "FORWARD", "1", "-s", ip,
        "-m", "hashlimit",
        "--hashlimit-name", f"nero_{ip.replace('.','_')}",
        "--hashlimit-above", f"{kbps}kb/s",
        "--hashlimit-mode", "srcip", "-j", "DROP"
    ], stderr=subprocess.DEVNULL)
    memory.save_alert(ip, "RATE_LIMITED", "warning", f"Rate limited to {kbps}kb/s")

def remove_rate_limit(ip):
    import subprocess
    subprocess.run([
        "iptables", "-D", "FORWARD", "-s", ip,
        "-m", "hashlimit",
        "--hashlimit-name", f"nero_{ip.replace('.','_')}",
        "--hashlimit-above", "512kb/s",
        "--hashlimit-mode", "srcip", "-j", "DROP"
    ], stderr=subprocess.DEVNULL)

def start():
    global NERO_IP
    NERO_IP = get_nero_ip()
    threading.Thread(target=_arp_poison_loop, daemon=True).start()
    threading.Thread(target=_auto_block_loop, daemon=True).start()
    print(f"[ACTIONS] Engine active | Interface={INTERFACE} Router={ROUTER_IP} NERO={NERO_IP}")
