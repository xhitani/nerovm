"""
NERO Sensors — sensors.py
All packet sniffing: ARP, mDNS, DHCP, NetBIOS, DNS, bandwidth.
Writes into shared state dicts and memory.py.
"""
import time, threading
from collections import defaultdict
from scapy.all import sniff, ARP, IP, UDP, TCP, Ether, DNS, DNSQR, BOOTP, DHCP
import memory

# ── SHARED STATE (populated by this module, read by brain/dashboard) ──
devices           = {}   # ip -> {mac, name, os, packets, first_seen, last_seen, ...}
dns_history       = {}   # ip -> [domain, ...]  newest first
bandwidth_now     = {}   # ip -> bytes this second
_bandwidth_acc    = defaultdict(int)
arp_timestamps    = defaultdict(list)
mac_history       = defaultdict(set)
dhcp_fingerprints = {}
mdns_names        = {}
dhcp_names        = {}
ttl_obs           = defaultdict(list)

_lock = threading.Lock()

ROUTER_IP  = __import__("os").environ.get("NERO_ROUTER_IP", "192.168.1.1")
INTERFACE  = __import__("os").environ.get("NERO_INTERFACE", "enp0s3")
SUBNET     = __import__("os").environ.get("NERO_SUBNET",    "192.168.1.")

# ── HELPERS ──────────────────────────────────────────────────────
def _is_lan(ip):
    return ip.startswith(SUBNET) and ip != ROUTER_IP

def _get_os(ttl):
    if ttl <= 64:  return "Linux/Android"
    if ttl <= 128: return "Windows"
    return "Network Node"

def _set_name(ip, name):
    name = (name or "").strip().rstrip(".")
    if not name or name == ip:
        return
    with _lock:
        dev = devices.get(ip)
        if dev and (not dev.get("name") or dev["name"] == ip):
            dev["name"] = name
            memory.upsert_device(ip, name=name)

def _register_device(ip, mac, os_guess, source="ARP"):
    now = time.time()
    with _lock:
        if ip not in devices:
            devices[ip] = {
                "ip": ip, "mac": mac, "name": "",
                "os": os_guess, "packets": 0,
                "first_seen": now, "last_seen": now,
                "source": source, "vendor": _vendor(mac),
            }
            memory.upsert_device(ip, mac=mac, os=os_guess,
                                 first_seen=now, last_seen=now)
            return True   # new device
        else:
            devices[ip]["last_seen"]  = now
            devices[ip]["packets"]   += 1
            if mac and mac != "ff:ff:ff:ff:ff:ff":
                devices[ip]["mac"] = mac
            return False

# ── VENDOR LOOKUP ─────────────────────────────────────────────────
_SAMSUNG_OUIS = {
    "00:07:ab","00:12:47","00:15:99","00:16:32","10:30:47","2c:ae:2b",
    "34:23:87","38:aa:3c","50:01:bb","50:a4:c8","54:88:0e","5c:f6:dc",
    "60:a1:0a","70:f9:27","74:45:8a","78:1f:db","84:25:19","8c:71:f8",
    "90:18:7c","94:35:0a","a0:07:98","b4:07:f9","c0:bd:d1","d0:17:6a",
    "e0:99:71","e4:40:e2","f0:25:b7","f4:7b:5e",
}
_APPLE_OUIS = {
    "00:03:93","00:05:02","00:0a:27","00:0a:95","00:11:24","00:16:cb",
    "00:17:f2","00:1b:63","00:1c:b3","00:1d:4f","00:1e:52","00:1f:5b",
    "3c:07:54","40:30:04","a4:b1:97","a4:c3:61","a8:20:66","ac:1f:74",
    "ac:61:ea","b8:78:2e","d0:03:4b","d8:d1:cb","f0:18:98","f4:f1:5a",
}

def _vendor(mac):
    if not mac or len(mac) < 8:
        return "Unknown"
    oui = mac[:8].lower()
    if oui in _SAMSUNG_OUIS: return "Samsung"
    if oui in _APPLE_OUIS:   return "Apple"
    if mac.startswith("08:00:27"): return "VirtualBox"
    return "Unknown"

def _is_random_mac(mac):
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except Exception:
        return False

# ── ARP + IP HANDLER ─────────────────────────────────────────────
def _handle_arp(pkt):
    if not pkt.haslayer(ARP):
        return
    arp = pkt[ARP]
    ip  = arp.psrc
    mac = arp.hwsrc
    if ip == "0.0.0.0" or mac == "ff:ff:ff:ff:ff:ff":
        return
    if not _is_lan(ip):
        return
    if pkt.haslayer(IP):
        ttl = pkt[IP].ttl
        with _lock:
            ttl_obs[ip].append(ttl)
            if len(ttl_obs[ip]) > 50:
                ttl_obs[ip] = ttl_obs[ip][-50:]
    now = time.time()
    with _lock:
        arp_timestamps[ip].append(now)
        if len(arp_timestamps[ip]) > 1000:
            arp_timestamps[ip] = arp_timestamps[ip][-1000:]
        mac_history[ip].add(mac)
    os_guess = _get_os(pkt[IP].ttl) if pkt.haslayer(IP) else "Unknown"
    _register_device(ip, mac, os_guess, "ARP")

# ── IP/BANDWIDTH HANDLER ──────────────────────────────────────────
def _handle_ip(pkt):
    if not pkt.haslayer(IP):
        return
    src = pkt[IP].src
    dst = pkt[IP].dst
    sz  = len(pkt)
    for ip in (src, dst):
        if _is_lan(ip):
            with _lock:
                _bandwidth_acc[ip] += sz
            if ip in devices:
                _register_device(ip, devices[ip].get("mac",""), "", "IP")
    # DNS
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and _is_lan(src):
        try:
            qname = pkt[DNSQR].qname.decode().lower().rstrip(".")
            if "." in qname and not qname.endswith(".local") and not qname.endswith(".arpa"):
                parts = qname.split(".")
                root  = ".".join(parts[-2:])
                with _lock:
                    hist = dns_history.get(src, [])
                    if root not in hist:
                        dns_history[src] = ([root] + hist)[:10]
        except Exception:
            pass

# ── mDNS HANDLER ─────────────────────────────────────────────────
def _handle_mdns(pkt):
    try:
        if not pkt.haslayer(IP) or not pkt.haslayer(DNS):
            return
        src = pkt[IP].src
        if not _is_lan(src):
            return
        dns = pkt[DNS]
        for section in [dns.an, dns.ar]:
            rec = section
            while rec and rec.__class__.__name__ != "NoPayload":
                name = ""
                if hasattr(rec, "rrname"):
                    name = rec.rrname.decode("utf-8", errors="ignore").rstrip(".")
                if name and ".local" in name:
                    hostname = name.replace(".local", "").split(".")[0]
                    if len(hostname) > 1:
                        with _lock:
                            mdns_names[src] = hostname
                        _set_name(src, hostname)
                rec = rec.payload
        if dns.qd:
            try:
                qname = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                if ".local" in qname:
                    hostname = qname.replace(".local", "").split(".")[0]
                    if len(hostname) > 1:
                        with _lock:
                            mdns_names[src] = hostname
                        _set_name(src, hostname)
            except Exception:
                pass
    except Exception:
        pass

# ── DHCP HANDLER ─────────────────────────────────────────────────
def _handle_dhcp(pkt):
    try:
        if not pkt.haslayer(DHCP):
            return
        src = pkt[IP].src if pkt.haslayer(IP) else "0.0.0.0"
        if src == "0.0.0.0" and pkt.haslayer(Ether):
            mac = pkt[Ether].src
            for ip, dev in devices.items():
                if dev.get("mac") == mac:
                    src = ip
                    break
        if not src or src == "0.0.0.0":
            return
        opts = {o[0]: o[1] for o in pkt[DHCP].options if isinstance(o, tuple) and len(o) == 2}
        hostname = opts.get("hostname")
        if hostname:
            if isinstance(hostname, bytes):
                hostname = hostname.decode("utf-8", errors="ignore")
            with _lock:
                dhcp_names[src] = hostname
            _set_name(src, hostname)
        param_list = opts.get("param_req_list")
        if param_list:
            with _lock:
                dhcp_fingerprints[src] = list(param_list)
    except Exception:
        pass

# ── NETBIOS HANDLER ───────────────────────────────────────────────
def _handle_netbios(pkt):
    try:
        if not pkt.haslayer(IP) or not pkt.haslayer(UDP):
            return
        src = pkt[IP].src
        if not _is_lan(src):
            return
        raw = bytes(pkt[UDP].payload)
        if len(raw) < 45:
            return
        encoded = raw[13:13+32]
        if len(encoded) < 32:
            return
        name = ""
        for i in range(0, 30, 2):
            c = ((encoded[i] - 0x41) << 4) | (encoded[i+1] - 0x41)
            if c in (0x20, 0x00):
                break
            if 32 <= c <= 126:
                name += chr(c)
        if name and len(name) > 1:
            _set_name(src, name)
    except Exception:
        pass

# ── BANDWIDTH RESET THREAD ────────────────────────────────────────
def _bw_reset():
    while True:
        time.sleep(1)
        with _lock:
            for ip in list(_bandwidth_acc):
                bandwidth_now[ip] = _bandwidth_acc[ip]
                _bandwidth_acc[ip] = 0

# ── START ALL LISTENERS ───────────────────────────────────────────
def start():
    threading.Thread(target=_bw_reset, daemon=True).start()

    def _arp_listener():
        sniff(iface=INTERFACE, filter="arp", prn=_handle_arp, store=0)
    def _ip_listener():
        sniff(iface=INTERFACE, filter="ip", prn=_handle_ip, store=0)
    def _mdns_listener():
        sniff(iface=INTERFACE, filter="udp port 5353", prn=_handle_mdns, store=0)
    def _dhcp_listener():
        sniff(iface=INTERFACE, filter="udp port 67 or udp port 68", prn=_handle_dhcp, store=0)
    def _netbios_listener():
        sniff(iface=INTERFACE, filter="udp port 137", prn=_handle_netbios, store=0)

    for fn in [_arp_listener, _ip_listener, _mdns_listener,
               _dhcp_listener, _netbios_listener]:
        threading.Thread(target=fn, daemon=True).start()

    print(f"[SENSORS] All listeners active on {INTERFACE}")
