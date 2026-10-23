"""
NERO v5.0 — Self-Evolving Network Security AI
Works on ANY network: 192.168.1.x, 192.168.0.x, 10.0.0.x, 172.16.x.x
Auto-detects interface, router IP, and subnet.
"""
import os, sys, time, threading

def get_auto_config():
    # Method 1: netifaces
    try:
        import netifaces
        gws       = netifaces.gateways()
        default   = gws['default'][netifaces.AF_INET]
        router_ip = default[0]
        interface = default[1]
        if netifaces.AF_INET in netifaces.ifaddresses(interface):
            print(f"[AUTO-CONFIG] Interface={interface} Router={router_ip}")
            return interface, router_ip
    except Exception as e:
        print(f"[AUTO-CONFIG] netifaces: {e}")

    # Method 2: ip route
    try:
        import subprocess, re
        out   = subprocess.run(["ip","route","show","default"],
                               capture_output=True, text=True, timeout=5).stdout
        parts = out.strip().split()
        return parts[parts.index("dev")+1], parts[parts.index("via")+1]
    except Exception as e:
        print(f"[AUTO-CONFIG] ip route: {e}")

    # Method 3: socket
    try:
        import socket, subprocess, re
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        my_ip = s.getsockname()[0]; s.close()
        router = ".".join(my_ip.split(".")[:3]) + ".1"
        out    = subprocess.run(["ip","addr"], capture_output=True, text=True, timeout=3).stdout
        iface  = "eth0"
        lines  = out.splitlines()
        for i, line in enumerate(lines):
            if my_ip in line:
                for prev in reversed(lines[:i]):
                    m = re.match(r'\d+: (\S+?)[@:]', prev)
                    if m: iface = m.group(1); break
                break
        return iface, router
    except Exception as e:
        print(f"[AUTO-CONFIG] socket: {e}")

    print("[AUTO-CONFIG] All methods failed — using defaults")
    return "enp0s3", "192.168.1.1"

INTERFACE, ROUTER_IP = get_auto_config()
SUBNET = ".".join(ROUTER_IP.split(".")[:3]) + "."

# ── SETTINGS ──────────────────────────────────────────────────────
TELEGRAM_TOKEN    = ""
TELEGRAM_CHAT_ID  = ""
ENABLE_AUTOBLOCK  = True
ENABLE_EVOLUTION  = True
CODE_EVOLVER      = False
APPROVAL_REQUIRED = True
ENABLE_MASSCAN    = True
ENABLE_NIKTO      = False
ENABLE_PROXIMITY  = False
PROXIMITY_IFACE   = "wlan1"
# ──────────────────────────────────────────────────────────────────

if __name__ == "__main__" and os.getuid() != 0:
    print("[!] Run as root: sudo python3 main.py"); sys.exit(1)

os.environ["NERO_INTERFACE"] = INTERFACE
os.environ["NERO_ROUTER_IP"] = ROUTER_IP
os.environ["NERO_SUBNET"]    = SUBNET

import memory; memory.init()

import sensors
sensors.INTERFACE = INTERFACE
sensors.ROUTER_IP = ROUTER_IP
sensors.SUBNET    = SUBNET

import brain

import actions
actions.INTERFACE        = INTERFACE
actions.ROUTER_IP        = ROUTER_IP
actions.TELEGRAM_TOKEN   = TELEGRAM_TOKEN
actions.TELEGRAM_CHAT_ID = TELEGRAM_CHAT_ID
actions.NERO_IP          = actions.get_nero_ip()

import evolution
evolution.CODE_EVOLVER_ENABLED = CODE_EVOLVER
evolution.APPROVAL_REQUIRED    = APPROVAL_REQUIRED

import masscan_scan
masscan_scan.INTERFACE = INTERFACE
masscan_scan.ROUTER_IP = ROUTER_IP
masscan_scan.SUBNET    = SUBNET + "0/24"

import nikto_scan
import recon
recon.INTERFACE = INTERFACE
import notifier
import dashboard
import proximity
if ENABLE_PROXIMITY:
    proximity.MONITOR_INTERFACE = PROXIMITY_IFACE

def _restore_blocklist():
    blocked = [d for d in memory.get_all_devices() if d.get("blocked")]
    for dev in blocked:
        actions.blocked_ips.add(dev["ip"])
    if blocked:
        print(f"[MAIN] Restored {len(blocked)} blocked IPs")

def _arp_sweep():
    from scapy.all import Ether, ARP, srp
    print(f"[MAIN] ARP sweep {SUBNET}0/24 ...")
    for i in range(1, 255):
        ip = f"{SUBNET}{i}"
        if ip == ROUTER_IP: continue
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                         iface=INTERFACE, timeout=0.3, verbose=False)
            for _, r in ans:
                sensors._register_device(r.psrc, r.hwsrc, sensors._get_os(64), "PROBE")
            time.sleep(0.03)
        except Exception:
            pass
    print("[MAIN] ARP sweep done")

def main():
    print(f"""
╔══════════════════════════════════════════════════════════╗
║      NERO v5.0 — Self-Evolving Network Security AI       ║
╠══════════════════════════════════════════════════════════╣
║  Interface : {INTERFACE:<43}║
║  Router    : {ROUTER_IP:<43}║
║  Subnet    : {SUBNET+'0/24':<43}║
║  NERO IP   : {actions.NERO_IP:<43}║
║  Dashboard : http://{actions.NERO_IP}:8080{' '*(21-len(actions.NERO_IP))}║
╚══════════════════════════════════════════════════════════╝
""")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    os.system("sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null 2>&1")
    os.system("iptables -F")

    _restore_blocklist()
    sensors.start()
    brain.start()
    actions.start()
    if ENABLE_EVOLUTION: evolution.start()
    recon.start()
    threading.Thread(target=dashboard.start, daemon=True).start()
    notifier.start()
    if ENABLE_PROXIMITY: proximity.start()
    threading.Thread(target=_arp_sweep, daemon=True).start()

    actions.alert("SYSTEM", "NERO v5.0 Started",
                  f"Network: {SUBNET}0/24 | Interface: {INTERFACE}\n"
                  f"Dashboard: http://{actions.NERO_IP}:8080", severity="info")
    print(f"[MAIN] Running. Dashboard → http://{actions.NERO_IP}:8080\n")

    try:
        while True:
            time.sleep(60)
            print(f"[STATUS] {time.strftime('%H:%M:%S')} | "
                  f"{len(sensors.devices)} devices | "
                  f"{len(actions.blocked_ips)} blocked | "
                  f"{len(brain.anomaly_models)} models")
    except KeyboardInterrupt:
        print("\n[NERO] Shutting down.")
        if ENABLE_PROXIMITY: proximity.stop()

if __name__ == "__main__":
    main()
