from __future__ import annotations

import argparse
import logging
import os
import platform
import sys
import threading
import time
from typing import Any

from scapy.all import ARP, DNS, DHCP, Ether, IP, NoPayload, UDP, sendp, sniff, srp
from scapy.layers.dns import DNSQR

import dashboard as dashboard

# --- CONFIG ---
ROUTER_IP = "192.168.1.1"
INTERFACE = "enp0s3"
LAN_PREFIX = "192.168.1."

# --- SHARED MEMORY ---
devices           = {}
dns_history       = {}  # ip -> list of last 5 domains
alert_history     = []
bandwidth_samples = {}
blocked_devices   = set()
_mac_cache        = {}
state_lock        = threading.RLock()

log = logging.getLogger("nero")

def get_os(ttl: int) -> str:
    if ttl <= 64:  return "Linux/Android"
    if ttl <= 128: return "Windows"
    return "Network Node"

def get_mac(ip: str) -> str | None:
    with state_lock:
        cached = _mac_cache.get(ip)
    if cached:
        return cached
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                     iface=INTERFACE, timeout=1, verbose=False)
        if ans:
            mac = ans[0][1].hwsrc
            with state_lock:
                _mac_cache[ip] = mac
            return mac
    except Exception:
        pass
    return None

def set_device_name(ip: str, name: str | None) -> None:
    """Update device name only if we have something better than the IP."""
    if not name or name == ip:
        return
    name = name.strip().rstrip('.')
    if not name:
        return
    with state_lock:
        dev = devices.get(ip)
        if not dev:
            return
        current = dev.get("name", "")
        # Prefer mDNS/DHCP name over raw IP, don't overwrite a good name with a worse one
        if not current or current == ip:
            dev["name"] = name
            log.info("Name: %s -> %s", ip, name)

# ─────────────────────────────────────────────────────────────────
# PACKET CALLBACK — main sniffer (IP traffic + DNS queries)
# ─────────────────────────────────────────────────────────────────
def packet_callback(pkt):
    if not pkt.haslayer(IP):
        return
    src = pkt[IP].src

    with state_lock:
        if src in blocked_devices:
            return
    if not src.startswith(LAN_PREFIX) or src == ROUTER_IP:
        return

    src_mac = pkt.src
    if src_mac and src_mac != "ff:ff:ff:ff:ff:ff":
        with state_lock:
            _mac_cache[src] = src_mac

    is_new = False
    with state_lock:
        if src not in devices:
            is_new = True
            devices[src] = {
                "mac":     src_mac,
                "os":      get_os(pkt[IP].ttl),
                "packets": 0,
                "name":    "",
            }
            alert_history.append({
                "time":    time.strftime("%H:%M:%S"),
                "message": f"NEW DEVICE: {src} [{src_mac}] OS={get_os(pkt[IP].ttl)}"
            })

        devices[src]["packets"] += 1
        bandwidth_samples[src] = bandwidth_samples.get(src, 0) + len(pkt)

    # Outgoing DNS queries — keep last 8 unique domains per device
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
        try:
            qname = pkt[DNSQR].qname.decode().lower().rstrip('.')
            # Skip noise: local, arpa, and single-label names
            if '.' in qname and not qname.endswith('.local') and not qname.endswith('.arpa'):
                # Strip common subdomains to get root domain
                parts = qname.split('.')
                root = '.'.join(parts[-2:]) if len(parts) >= 2 else qname
                with state_lock:
                    history = dns_history.get(src, [])
                    if root not in history:
                        history = [root] + history  # newest first
                        dns_history[src] = history[:8]  # keep last 8 unique
        except Exception:
            pass

# ─────────────────────────────────────────────────────────────────
# mDNS LISTENER — UDP 5353, catches iPhone/Mac/Android .local names
# Apple devices announce themselves constantly via mDNS
# ─────────────────────────────────────────────────────────────────
def mdns_callback(pkt):
    try:
        if not pkt.haslayer(IP) or not pkt.haslayer(DNS):
            return
        src = pkt[IP].src
        if not src.startswith(LAN_PREFIX) or src == ROUTER_IP:
            return

        dns = pkt[DNS]

        # Check answers and additional records for PTR/A records with .local names
        for section in [dns.an, dns.ar, dns.ns]:
            rec = section
            while rec and rec != NoPayload():
                try:
                    name = ""
                    if hasattr(rec, 'rrname'):
                        name = rec.rrname.decode('utf-8', errors='ignore').rstrip('.')
                    elif hasattr(rec, 'qname'):
                        name = rec.qname.decode('utf-8', errors='ignore').rstrip('.')

                    if name and '.local' in name:
                        # Strip the .local suffix to get clean hostname
                        hostname = name.replace('.local', '').split('.')[0]
                        if hostname and len(hostname) > 1:
                            set_device_name(src, hostname)
                except Exception:
                    pass
                rec = rec.payload

        # Also check questions — devices query their own name
        if dns.qd:
            try:
                qname = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                if '.local' in qname:
                    hostname = qname.replace('.local', '').split('.')[0]
                    if hostname and len(hostname) > 1:
                        set_device_name(src, hostname)
            except Exception:
                pass

    except Exception as e:
        pass

def start_mdns_listener():
    sniff(iface=INTERFACE, filter="udp port 5353",
          prn=mdns_callback, store=0)

# ─────────────────────────────────────────────────────────────────
# DHCP LISTENER — UDP 67/68, catches hostname from DHCP requests
# Every device sends its name when requesting/renewing an IP
# ─────────────────────────────────────────────────────────────────
def dhcp_callback(pkt):
    try:
        if not pkt.haslayer(DHCP) or not pkt.haslayer(IP):
            return
        src = pkt[IP].src
        if src == "0.0.0.0":
            # DHCP discover — get IP from ARP cache or MAC
            if pkt.haslayer(Ether):
                mac = pkt[Ether].src
                # Find IP by MAC in devices
                with state_lock:
                    items = list(devices.items())
                for ip, dev in items:
                    if dev.get("mac") == mac:
                        src = ip
                        break
        if not src or src == "0.0.0.0":
            return

        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'hostname':
                hostname = opt[1]
                if isinstance(hostname, bytes):
                    hostname = hostname.decode('utf-8', errors='ignore')
                set_device_name(src, hostname)
                break
    except Exception:
        pass

def start_dhcp_listener():
    sniff(iface=INTERFACE, filter="udp port 67 or udp port 68",
          prn=dhcp_callback, store=0)

# ─────────────────────────────────────────────────────────────────
# NETBIOS LISTENER — UDP 137, catches Windows PC names instantly
# ─────────────────────────────────────────────────────────────────
def netbios_callback(pkt):
    try:
        if not pkt.haslayer(IP) or not pkt.haslayer(UDP):
            return
        src = pkt[IP].src
        if not src.startswith(LAN_PREFIX) or src == ROUTER_IP:
            return

        raw = bytes(pkt[UDP].payload)
        if len(raw) < 13:
            return

        # NetBIOS name query — name starts at byte 13, 32 bytes encoded
        # Each char is encoded as two bytes: (char + 0x41), so decode pairs
        encoded = raw[13:13+32]
        if len(encoded) < 32:
            return

        name = ""
        for i in range(0, 30, 2):
            c = ((encoded[i] - 0x41) << 4) | (encoded[i+1] - 0x41)
            if c == 0x20 or c == 0x00:
                break
            if 32 <= c <= 126:
                name += chr(c)

        if name and len(name) > 1:
            set_device_name(src, name)
    except Exception:
        pass

def start_netbios_listener():
    sniff(iface=INTERFACE, filter="udp port 137",
          prn=netbios_callback, store=0)

# ─────────────────────────────────────────────────────────────────
# ARP POISON / RESTORE
# ─────────────────────────────────────────────────────────────────
def arp_poison_blocked():
    while True:
        time.sleep(3)
        with state_lock:
            ips = list(blocked_devices)
            cache = dict(_mac_cache)
        for ip in ips:
            target_mac = cache.get(ip)
            if not target_mac:
                continue
            try:
                pkt = Ether(dst=target_mac) / ARP(
                    op=2, pdst=ip, hwdst=target_mac,
                    psrc=ROUTER_IP, hwsrc="00:00:00:00:00:00"
                )
                sendp(pkt, iface=INTERFACE, verbose=False)
            except Exception as e:
                log.warning("Poison failed %s: %s", ip, e)

def restore_device(ip: str) -> None:
    router_mac = get_mac(ROUTER_IP)
    target_mac = _mac_cache.get(ip) or get_mac(ip)
    if not router_mac or not target_mac:
        return
    try:
        pkt = Ether(dst=target_mac) / ARP(
            op=2, pdst=ip, hwdst=target_mac,
            psrc=ROUTER_IP, hwsrc=router_mac
        )
        sendp(pkt, iface=INTERFACE, verbose=False, count=5)
        print(f"[RESTORE] Correct ARP sent to {ip}")
    except Exception as e:
        print(f"[RESTORE] {ip}: {e}")

# ─────────────────────────────────────────────────────────────────
# BANDWIDTH RESET
# ─────────────────────────────────────────────────────────────────
def bw_reset():
    while True:
        time.sleep(1)
        with state_lock:
            for k in list(bandwidth_samples):
                bandwidth_samples[k] = 0

def _is_admin_or_root() -> bool:
    if os.name != "nt":
        # Linux/macOS: root is required for sniffing on most interfaces anyway.
        try:
            return os.geteuid() == 0  # type: ignore[attr-defined]
        except Exception:
            return False
    # Windows: admin required for packet capture drivers / raw sockets.
    try:
        import ctypes  # local import to avoid non-nt issues
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def _apply_linux_network_hardening() -> None:
    """Only run on Linux; ignore failures (containers/permissions)."""
    if platform.system().lower() != "linux":
        return
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    os.system("sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null 2>&1")
    os.system("iptables -F")

def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="NERO PLATINUM network monitor")
    p.add_argument("--interface", default=INTERFACE, help="Capture interface name")
    p.add_argument("--router-ip", default=ROUTER_IP, help="Router IP (default gateway)")
    p.add_argument("--lan-prefix", default=LAN_PREFIX, help="LAN prefix filter, e.g. 192.168.1.")
    p.add_argument("--log-level", default="INFO", help="DEBUG, INFO, WARNING, ERROR")
    p.add_argument(
        "--enable-active",
        action="store_true",
        help="Enable active interference features (opt-in). Requires NERO_ENABLE_ACTIVE=1.",
    )
    return p.parse_args(argv)

# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────
def main(argv: list[str]) -> int:
    global INTERFACE, ROUTER_IP, LAN_PREFIX

    args = _parse_args(argv)
    INTERFACE = args.interface
    ROUTER_IP = args.router_ip
    LAN_PREFIX = args.lan_prefix

    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if not _is_admin_or_root():
        log.error("Admin/root privileges are required for sniffing.")
        return 1

    dashboard.devices = devices
    dashboard.dns_history = dns_history
    dashboard.alert_history = alert_history
    dashboard.bandwidth_samples = bandwidth_samples
    dashboard.blocked_devices = blocked_devices
    dashboard.restore_device = restore_device
    dashboard.state_lock = state_lock

    _apply_linux_network_hardening()

    threading.Thread(target=dashboard.start, daemon=True).start()
    threading.Thread(target=bw_reset, daemon=True).start()
    threading.Thread(target=start_mdns_listener, daemon=True).start()
    threading.Thread(target=start_dhcp_listener, daemon=True).start()
    threading.Thread(target=start_netbios_listener, daemon=True).start()

    import notifier as notifier
    notifier.INTERFACE = INTERFACE
    notifier.ROUTER_IP = ROUTER_IP
    notifier.NERO_IP = notifier.get_nero_ip()

    enable_active = bool(args.enable_active) and (os.environ.get("NERO_ENABLE_ACTIVE") == "1")
    notifier.ENABLE_DNS_SPOOF = enable_active
    notifier.start()

    if enable_active:
        log.warning("Active interference enabled (opt-in).")
        threading.Thread(target=arp_poison_blocked, daemon=True).start()
    else:
        log.info("Active interference disabled (default).")

    log.info("NERO PLATINUM v4.5")
    log.info("Interface    : %s", INTERFACE)
    log.info("Monitoring   : %s0/24", LAN_PREFIX)
    log.info("Name sources : mDNS + DHCP + NetBIOS")

    sniff(iface=INTERFACE, prn=packet_callback, store=0)
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
