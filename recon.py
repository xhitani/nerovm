"""
NERO Recon — recon.py
Full device intelligence engine.
Enriches every device with model, owner hints, apps, and behavior profile.
"""
import socket, threading, time, re, json, struct
import urllib.request, urllib.error
from scapy.all import sniff, IP, UDP, TCP, DNS, DNSQR, Ether, sr1, ARP
import sensors, memory, os
INTERFACE = os.environ.get("NERO_INTERFACE", "enp0s3")

try:
    import masscan_scan
    _HAS_MASSCAN = True
except ImportError:
    _HAS_MASSCAN = False

try:
    import nikto_scan
    _HAS_NIKTO = True
except ImportError:
    _HAS_NIKTO = False

_lock       = threading.Lock()
_scan_done  = {}   # ip -> last scan timestamp
SCAN_COOLDOWN = 600
TIMEOUT       = 1.5

# ─────────────────────────────────────────────────────────────────
# APP FINGERPRINTS — identify installed apps from DNS queries
# ─────────────────────────────────────────────────────────────────
APP_SIGNATURES = {
    # Social
    "instagram":    ["instagram.com","cdninstagram.com","ig.me"],
    "tiktok":       ["tiktok.com","tiktokv.com","muscdn.com","byteoversea.com"],
    "snapchat":     ["snapchat.com","snap.com","sc-cdn.net"],
    "facebook":     ["facebook.com","fbcdn.net","fb.com","fbsbx.com"],
    "twitter/X":    ["twitter.com","t.co","twimg.com","x.com"],
    "whatsapp":     ["whatsapp.com","whatsapp.net"],
    "telegram":     ["telegram.org","t.me","tdesktop.com"],
    "discord":      ["discord.com","discordapp.com","discord.gg"],
    "linkedin":     ["linkedin.com","licdn.com"],
    "pinterest":    ["pinterest.com","pinimg.com"],
    "reddit":       ["reddit.com","redd.it","redditstatic.com"],
    "tumblr":       ["tumblr.com"],
    "bereal":       ["bereal.com","bere.al"],

    # Streaming
    "youtube":      ["youtube.com","googlevideo.com","youtu.be","ytimg.com"],
    "netflix":      ["netflix.com","nflxvideo.net","nflxso.net"],
    "spotify":      ["spotify.com","scdn.co","spotifycdn.com"],
    "twitch":       ["twitch.tv","twitchsvc.net","jtvnw.net"],
    "disney+":      ["disneyplus.com","disney-plus.net","bamgrid.com"],
    "prime video":  ["primevideo.com","amazon.com","aiv-cdn.net"],
    "anghami":      ["anghami.com"],
    "shahid":       ["shahid.net","mbc.net"],
    "osn+":         ["osn.com","osnplus.com"],

    # Gaming
    "fortnite":     ["epicgames.com","fortnite.com"],
    "pubg":         ["pubg.com","battlegrounds.com"],
    "roblox":       ["roblox.com","rbxcdn.com"],
    "minecraft":    ["minecraft.net","mojang.com"],
    "steam":        ["steampowered.com","steamcontent.com","steamgames.com"],
    "playstation":  ["playstation.com","psn.store","playstation.net"],
    "xbox":         ["xbox.com","xboxlive.com","microsoft.com"],
    "free fire":    ["garena.com","ff.garena.com"],

    # Comms / Productivity
    "zoom":         ["zoom.us","zoomgov.com"],
    "teams":        ["teams.microsoft.com","skype.com"],
    "gmail":        ["gmail.com","googlemail.com"],
    "outlook":      ["outlook.com","hotmail.com","live.com"],
    "apple mail":   ["icloud.com","me.com","mac.com"],
    "google drive": ["drive.google.com","docs.google.com"],
    "dropbox":      ["dropbox.com","dropboxstatic.com"],

    # Shopping
    "amazon":       ["amazon.com","amazon.fr","amazon.co.uk","amazonaws.com"],
    "ebay":         ["ebay.com","ebayimg.com"],
    "aliexpress":   ["aliexpress.com","alicdn.com"],
    "jumia":        ["jumia.com"],

    # Browsers / OS
    "chrome":       ["clients1.google.com","update.googleapis.com","safebrowsing.google.com"],
    "firefox":      ["mozilla.org","firefox.com","telemetry.mozilla.org"],
    "safari/icloud":["apple.com","icloud.com","mzstatic.com","itunes.apple.com"],

    # VPN (suspicious)
    "vpn detected": ["nordvpn.com","expressvpn.com","tunnelbear.com",
                     "protonvpn.com","surfshark.com","cyberghost.com",
                     "ipvanish.com","privateinternetaccess.com","windscribe.com"],

    # Crypto (very suspicious)
    "crypto":       ["binance.com","coinbase.com","kraken.com","blockchain.com",
                     "etherscan.io","bitcoin.org"],
}

# Build reverse lookup: domain -> app name
_DOMAIN_TO_APP = {}
for app, domains in APP_SIGNATURES.items():
    for d in domains:
        _DOMAIN_TO_APP[d] = app

# Per-device app tracking
detected_apps = {}   # ip -> set of app names

def _match_app(domain):
    """Match a DNS query domain to an app name."""
    parts = domain.strip(".").split(".")
    # Try exact match and 2-level suffix
    for i in range(len(parts)):
        candidate = ".".join(parts[i:])
        if candidate in _DOMAIN_TO_APP:
            return _DOMAIN_TO_APP[candidate]
    return None

def track_dns_for_apps(ip, domain):
    """Called by sensors when a DNS query is seen."""
    app = _match_app(domain)
    if app:
        with _lock:
            if ip not in detected_apps:
                detected_apps[ip] = set()
            detected_apps[ip].add(app)
            if ip in sensors.devices:
                sensors.devices[ip].setdefault("apps", set())
                sensors.devices[ip]["apps"].add(app)

# ─────────────────────────────────────────────────────────────────
# OUI LOOKUP — exact manufacturer from MAC
# ─────────────────────────────────────────────────────────────────
OUI_MAP = {
    "00:03:93":"Apple",    "00:05:02":"Apple",    "00:0a:27":"Apple",
    "00:0a:95":"Apple",    "00:11:24":"Apple",    "00:16:cb":"Apple",
    "00:17:f2":"Apple",    "00:1b:63":"Apple",    "00:1c:b3":"Apple",
    "3c:07:54":"Apple",    "40:30:04":"Apple",    "a4:b1:97":"Apple",
    "a4:c3:61":"Apple",    "a8:20:66":"Apple",    "f0:18:98":"Apple",
    "f4:f1:5a":"Apple",    "dc:2b:2a":"Apple",    "8c:85:90":"Apple",
    "b8:78:2e":"Apple",    "d0:03:4b":"Apple",    "00:cd:fe":"Apple",
    "00:07:ab":"Samsung",  "00:12:47":"Samsung",  "10:30:47":"Samsung",
    "2c:ae:2b":"Samsung",  "34:23:87":"Samsung",  "50:a4:c8":"Samsung",
    "54:88:0e":"Samsung",  "5c:f6:dc":"Samsung",  "70:f9:27":"Samsung",
    "78:1f:db":"Samsung",  "84:25:19":"Samsung",  "a0:07:98":"Samsung",
    "c0:bd:d1":"Samsung",  "e4:40:e2":"Samsung",  "38:aa:3c":"Samsung",
    "00:9e:c8":"Xiaomi",   "04:cf:8c":"Xiaomi",   "28:6c:07":"Xiaomi",
    "34:80:b3":"Xiaomi",   "50:64:2b":"Xiaomi",   "64:09:80":"Xiaomi",
    "74:51:ba":"Xiaomi",   "98:fa:e3":"Xiaomi",   "7c:1d:d9":"Xiaomi",
    "00:18:82":"Huawei",   "00:e0:fc":"Huawei",   "04:bd:70":"Huawei",
    "10:1b:54":"Huawei",   "24:09:95":"Huawei",   "34:6b:d3":"Huawei",
    "48:ad:08":"Huawei",   "70:72:3c":"Huawei",   "9c:b2:b2":"Huawei",
    "00:15:5d":"Microsoft","00:50:f2":"Microsoft", "28:18:78":"Microsoft",
    "48:50:73":"Microsoft","58:82:a8":"Microsoft", "7c:1e:52":"Microsoft",
    "00:0c:29":"VMware",   "00:50:56":"VMware",    "08:00:27":"VirtualBox",
    "00:1a:11":"Google",   "54:60:09":"Google",    "f4:f5:d8":"Google",
    "94:eb:2c":"Google",   "3c:5a:b4":"Google",
    "18:b4:30":"Nest",     "64:16:66":"Nest",
    "b8:27:eb":"Raspberry Pi", "dc:a6:32":"Raspberry Pi",
    "e4:5f:01":"Raspberry Pi",
    "00:17:88":"Philips Hue","ec:b5:fa":"Philips Hue",
    "14:91:82":"Amazon",   "44:65:0d":"Amazon",   "74:c2:46":"Amazon",
    "a0:02:dc":"Amazon",   "cc:f7:35":"Amazon",   "f0:27:2d":"Amazon",
    "68:54:fd":"Amazon Echo","00:fc:8b":"Amazon",
    "50:c7:bf":"TP-Link",  "14:cc:20":"TP-Link",  "c0:4a:00":"TP-Link",
    "e8:de:27":"TP-Link",  "f8:1a:67":"TP-Link",
    "00:1a:2b":"Cisco",    "00:1b:d4":"Cisco",    "00:1c:57":"Cisco",
    "18:33:9d":"Cisco",    "58:ac:78":"Cisco",
    "00:26:b9":"Dell",     "18:a9:9b":"Dell",     "b0:83:fe":"Dell",
    "b8:ca:3a":"Dell",     "f8:db:88":"Dell",
    "8c:16:45":"HP",       "00:0f:20":"HP",       "3c:d9:2b":"HP",
    "00:22:64":"HP",       "fc:15:b4":"HP",
    "00:1d:09":"Lenovo",   "00:23:ae":"Lenovo",   "28:d2:44":"Lenovo",
    "54:ee:75":"Lenovo",
    "00:26:c6":"Nintendo", "58:bd:a3":"Nintendo", "98:b6:e9":"Nintendo",
    "e0:0c:7f":"Nintendo",
    "00:d9:d1":"Sony",     "01:00:5e":"Sony",     "28:0d:fc":"Sony",
    "30:17:c8":"Sony",     "ac:9b:0a":"Sony",
    "00:e0:4c":"Realtek",  "00:50:b6":"Realtek",
}

def get_manufacturer(mac):
    if not mac or len(mac) < 8:
        return "Unknown"
    oui = mac[:8].lower()
    if oui in OUI_MAP:
        return OUI_MAP[oui]
    # Try online API if offline lookup fails
    try:
        url  = f"https://api.macvendors.com/{mac}"
        req  = urllib.request.Request(url, headers={"User-Agent":"NERO/5.0"})
        with urllib.request.urlopen(req, timeout=3) as r:
            vendor = r.read().decode().strip()
            if vendor and "errors" not in vendor.lower():
                return vendor
    except Exception:
        pass
    return "Unknown"

# ─────────────────────────────────────────────────────────────────
# UPnP / SSDP — gets exact device model and friendly name
# ─────────────────────────────────────────────────────────────────
SSDP_QUERY = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 1\r\n"
    "ST: ssdp:all\r\n\r\n"
).encode()

def _fetch_upnp_description(url):
    """Fetch UPnP XML description and extract device info."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NERO/5.0"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            xml = r.read().decode("utf-8", errors="ignore")
        info = {}
        for tag in ["friendlyName","manufacturer","modelName","modelNumber",
                    "modelDescription","serialNumber","deviceType","presentationURL"]:
            m = re.search(f"<{tag}>(.*?)</{tag}>", xml, re.IGNORECASE)
            if m:
                info[tag] = m.group(1).strip()
        return info
    except Exception:
        return {}

def scan_upnp(ip):
    """Send unicast M-SEARCH to a specific IP and fetch its description."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT)
        sock.sendto(SSDP_QUERY, (ip, 1900))
        resp, _ = sock.recvfrom(4096)
        sock.close()
        resp_str = resp.decode("utf-8", errors="ignore")
        # Extract LOCATION header
        loc = re.search(r"LOCATION:\s*(\S+)", resp_str, re.IGNORECASE)
        if loc:
            info = _fetch_upnp_description(loc.group(1))
            if info:
                return info
        # Even without XML, parse what we can from the SSDP response
        info = {}
        server = re.search(r"SERVER:\s*(.+)", resp_str, re.IGNORECASE)
        if server:
            info["server"] = server.group(1).strip()
        return info
    except Exception:
        return {}

# ─────────────────────────────────────────────────────────────────
# mDNS SERVICE DISCOVERY — what services does the device advertise
# ─────────────────────────────────────────────────────────────────
SERVICE_MEANINGS = {
    "_airplay":         "Apple AirPlay (iPhone/iPad/Mac)",
    "_raop":            "AirPlay Audio (Apple device)",
    "_apple-mobdev2":   "iPhone/iPad (connected to iTunes)",
    "_ipp":             "Printer (IPP)",
    "_printer":         "Printer",
    "_pdl-datastream":  "Printer (PCL/PS)",
    "_http":            "Web server",
    "_https":           "HTTPS web server",
    "_ssh":             "SSH server (Linux/Mac)",
    "_sftp-ssh":        "SFTP server",
    "_ftp":             "FTP server",
    "_smb":             "Windows file sharing (SMB)",
    "_afpovertcp":      "Mac file sharing (AFP)",
    "_spotify-connect": "Spotify running",
    "_googlecast":      "Google Chromecast / Google Home",
    "_nvstream":        "NVIDIA GameStream",
    "_xbox":            "Xbox console",
    "_sonos":           "Sonos speaker",
    "_daap":            "iTunes music sharing",
    "_presence":        "iMessage / FaceTime active",
    "_homekit":         "Apple HomeKit device",
    "_hap":             "HomeKit Accessory",
    "_smarttv":         "Smart TV",
    "_webdav":          "WebDAV server",
    "_rdp":             "Remote Desktop (Windows)",
    "_workstation":     "Linux workstation (Avahi)",
    "_companion-link":  "Apple Watch paired",
    "_sleep-proxy":     "Apple Sleep Proxy",
    "_device-info":     "Apple device info",
    "_nfs":             "NFS file server",
    "_mqtt":            "IoT MQTT broker",
    "_amzn-wplay":      "Amazon device (Echo/Fire)",
}

mdns_services = {}   # ip -> set of service strings

def _handle_mdns_services(pkt):
    """Parse mDNS packets for service type announcements."""
    try:
        if not pkt.haslayer(IP) or not pkt.haslayer(DNS):
            return
        src = pkt[IP].src
        if not src.startswith(sensors.SUBNET):
            return
        dns = pkt[DNS]
        for section in [dns.an, dns.ar, dns.ns]:
            rec = section
            while rec and rec.__class__.__name__ != "NoPayload":
                name = ""
                if hasattr(rec, "rrname"):
                    name = rec.rrname.decode("utf-8", errors="ignore")
                # Look for service type patterns like _airplay._tcp.local.
                for svc_key in SERVICE_MEANINGS:
                    if svc_key in name.lower():
                        with _lock:
                            mdns_services.setdefault(src, set())
                            mdns_services[src].add(svc_key)
                            if src in sensors.devices:
                                sensors.devices[src].setdefault("services", set())
                                sensors.devices[src]["services"].add(svc_key)
                rec = rec.payload
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────────
# HTTP BANNER GRAB — hits port 80/443/8080 for device web UI title
# ─────────────────────────────────────────────────────────────────
def grab_http_banner(ip):
    """Try common HTTP ports and grab server banner + page title."""
    result = {}
    for port in [80, 8080, 443, 8443, 8888]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT)
            if s.connect_ex((ip, port)) != 0:
                s.close()
                continue
            req = f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NERO/5.0\r\n\r\n"
            s.send(req.encode())
            raw = s.recv(4096).decode("utf-8", errors="ignore")
            s.close()
            server = re.search(r"Server:\s*(.+)", raw, re.IGNORECASE)
            title  = re.search(r"<title[^>]*>(.*?)</title>", raw, re.IGNORECASE | re.DOTALL)
            if server: result["http_server"] = server.group(1).strip()[:80]
            if title:  result["http_title"]  = re.sub(r'\s+',' ',title.group(1)).strip()[:80]
            if server or title:
                result["http_port"] = port
                break
        except Exception:
            pass
    return result

# ─────────────────────────────────────────────────────────────────
# TCP FINGERPRINTING — OS detection from SYN packet details
# ─────────────────────────────────────────────────────────────────
tcp_fingerprints = {}   # ip -> {os, ttl, window_size, ...}

def _handle_tcp_syn(pkt):
    """Passively fingerprint OS from TCP SYN packets."""
    try:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return
        if pkt[TCP].flags != 0x02:   # SYN only
            return
        src = pkt[IP].src
        if not src.startswith(sensors.SUBNET):
            return
        ttl  = pkt[IP].ttl
        win  = pkt[TCP].window
        opts = pkt[TCP].options

        # OS detection rules
        os_guess = "Unknown"
        if ttl <= 64:
            if win == 65535:        os_guess = "Linux (kernel ≥5.x)"
            elif win == 29200:      os_guess = "Linux (kernel 4.x)"
            elif win == 5840:       os_guess = "Linux (older)"
            elif win == 65535:      os_guess = "macOS / iOS"
            elif 60000 <= win:      os_guess = "macOS / iOS"
            else:                   os_guess = "Linux/Android"
        elif ttl <= 128:
            if win == 8192:         os_guess = "Windows (older)"
            elif win == 64240:      os_guess = "Windows 10/11"
            elif win == 65535:      os_guess = "Windows"
            else:                   os_guess = "Windows"
        elif ttl <= 255:
            os_guess = "Cisco / Network Device"

        fp = {"os": os_guess, "ttl": ttl, "window": win}
        with _lock:
            tcp_fingerprints[src] = fp
            if src in sensors.devices:
                if not sensors.devices[src].get("os") or sensors.devices[src]["os"] == "Unknown":
                    sensors.devices[src]["os"] = os_guess
                sensors.devices[src]["tcp_fp"] = fp
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────────
# PORT BANNER GRAB — SSH version, FTP banner, Telnet banner
# ─────────────────────────────────────────────────────────────────
BANNER_PORTS = {
    22:   "SSH",
    21:   "FTP",
    23:   "Telnet",
    25:   "SMTP",
    110:  "POP3",
    143:  "IMAP",
    3306: "MySQL",
    5900: "VNC",
}

def grab_port_banners(ip):
    """Grab text banners from common service ports."""
    result = {}
    for port, name in BANNER_PORTS.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT)
            if s.connect_ex((ip, port)) != 0:
                s.close()
                continue
            banner = s.recv(256).decode("utf-8", errors="ignore").strip()
            s.close()
            if banner:
                result[name] = banner[:100]
        except Exception:
            pass
    return result

# ─────────────────────────────────────────────────────────────────
# FULL SCAN — runs everything for one IP
# ─────────────────────────────────────────────────────────────────
def full_scan(ip):
    """Run all recon methods for a device. Called in background thread."""
    now = time.time()
    if now - _scan_done.get(ip, 0) < SCAN_COOLDOWN:
        return
    _scan_done[ip] = now

    print(f"[RECON] Scanning {ip}...")
    profile = {}

    # 1. Manufacturer from MAC
    mac = sensors.devices.get(ip, {}).get("mac", "")
    if mac:
        vendor = get_manufacturer(mac)
        profile["vendor"] = vendor
        sensors.devices[ip]["vendor"] = vendor

    # 2. UPnP
    upnp = scan_upnp(ip)
    if upnp:
        profile["upnp"] = upnp
        # Friendly name is the best "device name" source
        if "friendlyName" in upnp and upnp["friendlyName"]:
            name = upnp["friendlyName"]
            sensors._set_name(ip, name)
            profile["device_name"] = name
        if "modelName" in upnp:
            profile["model"] = upnp["modelName"]
        if "manufacturer" in upnp:
            profile["manufacturer"] = upnp["manufacturer"]

    # 3. HTTP banner
    http = grab_http_banner(ip)
    if http:
        profile.update(http)
        if "http_title" in http and http["http_title"]:
            sensors.devices[ip]["http_title"] = http["http_title"]

    # 4. Port banners
    banners = grab_port_banners(ip)
    if banners:
        profile["banners"] = banners
        if "SSH" in banners:
            sensors.devices[ip]["ssh_banner"] = banners["SSH"]
            # SSH banner often reveals OS: "SSH-2.0-OpenSSH_8.9p1 Ubuntu"
            if "Ubuntu" in banners["SSH"]:   sensors.devices[ip]["os"] = "Ubuntu Linux"
            elif "Debian" in banners["SSH"]: sensors.devices[ip]["os"] = "Debian Linux"
            elif "raspberrypi" in banners["SSH"].lower(): sensors.devices[ip]["os"] = "Raspberry Pi OS"

    # 5. Masscan open ports (already scanned in background)
    if _HAS_MASSCAN:
        open_ports = masscan_scan.get_open_ports(ip)
        if open_ports:
            profile["open_ports"]      = open_ports
            profile["security_issues"] = masscan_scan.get_security_issues(ip)
            sensors.devices[ip]["open_ports"] = open_ports

    # 6. Store full profile
    with _lock:
        if ip in sensors.devices:
            sensors.devices[ip]["recon"] = profile

    memory.upsert_device(ip,
        vendor=profile.get("vendor",""),
        notes=json.dumps(profile))

    # Build summary for print
    parts = []
    if profile.get("device_name"): parts.append(f"name={profile['device_name']}")
    if profile.get("model"):       parts.append(f"model={profile['model']}")
    if profile.get("vendor"):      parts.append(f"vendor={profile['vendor']}")
    if profile.get("http_title"):  parts.append(f"title={profile['http_title']}")
    print(f"[RECON] {ip}: {' | '.join(parts) or 'no extra info found'}")

# ─────────────────────────────────────────────────────────────────
# SCAN QUEUE WORKER
# ─────────────────────────────────────────────────────────────────
_queue = []

def queue_scan(ip):
    with _lock:
        if ip not in _queue:
            _queue.append(ip)

def _queue_worker():
    while True:
        time.sleep(2)
        with _lock:
            ip = _queue.pop(0) if _queue else None
        if ip:
            threading.Thread(target=full_scan, args=(ip,), daemon=True).start()

# ─────────────────────────────────────────────────────────────────
# ENHANCED DNS PACKET HANDLER
# Hooks into the sniff pipeline to track apps in real time
# ─────────────────────────────────────────────────────────────────
def _handle_dns_apps(pkt):
    try:
        if not pkt.haslayer(IP) or not pkt.haslayer(DNS):
            return
        if pkt[DNS].qr != 0:
            return
        src = pkt[IP].src
        if not src.startswith(sensors.SUBNET):
            return
        qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").lower().rstrip(".")
        track_dns_for_apps(src, qname)
        # Also enrich sensor DNS history
        if "." in qname and not qname.endswith(".local") and not qname.endswith(".arpa"):
            parts = qname.split(".")
            root  = ".".join(parts[-2:])
            with _lock:
                hist = sensors.dns_history.get(src, [])
                if root not in hist:
                    sensors.dns_history[src] = ([root] + hist)[:15]
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────────
# AUTO-SCAN NEW DEVICES
# ─────────────────────────────────────────────────────────────────
def _watch_new_devices():
    """Queue a recon scan whenever a new device appears."""
    known = set()
    while True:
        time.sleep(5)
        current = set(sensors.devices.keys())
        new     = current - known
        for ip in new:
            queue_scan(ip)
        known = current

# ─────────────────────────────────────────────────────────────────
# START
# ─────────────────────────────────────────────────────────────────
def start():
    # Passive listeners
    def _mdns_svc():
        sniff(iface=sensors.INTERFACE, filter="udp port 5353",
              prn=_handle_mdns_services, store=0)
    def _tcp_fp():
        sniff(iface=sensors.INTERFACE, filter="tcp",
              prn=_handle_tcp_syn, store=0)
    def _dns_apps():
        sniff(iface=sensors.INTERFACE, filter="udp port 53",
              prn=_handle_dns_apps, store=0)

    threading.Thread(target=_mdns_svc,        daemon=True).start()
    threading.Thread(target=_tcp_fp,           daemon=True).start()
    threading.Thread(target=_dns_apps,         daemon=True).start()
    threading.Thread(target=_queue_worker,     daemon=True).start()
    threading.Thread(target=_watch_new_devices,daemon=True).start()
    if _HAS_MASSCAN:
        masscan_scan.INTERFACE = sensors.INTERFACE
        masscan_scan.ROUTER_IP = sensors.ROUTER_IP
        masscan_scan.SUBNET    = sensors.SUBNET + "0/24"
        masscan_scan.start()
    if _HAS_NIKTO:
        nikto_scan.start()
    print("[RECON] Device intelligence engine active")
    print("[RECON] Tracking: apps, UPnP, HTTP banners, TCP fingerprint, mDNS services")
