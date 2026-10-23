"""
NERO Masscan — masscan_scan.py
Scans the entire subnet in ~2 seconds using masscan.
Auto-updates device profiles with open ports, device types, security flags.
Requires: sudo apt install masscan
"""
import subprocess, json, time, threading, re
import sensors, memory

INTERFACE    = __import__("os").environ.get("NERO_INTERFACE", "enp0s3")
ROUTER_IP    = __import__("os").environ.get("NERO_ROUTER_IP", "192.168.1.1")
_s           = __import__("os").environ.get("NERO_SUBNET", "192.168.1.")
SUBNET       = _s + "0/24" if not _s.endswith("/24") else _s
SCAN_RATE    = 5000
RESCAN_EVERY = 300   # full rescan every 5 min

PORTS = ",".join(map(str, [
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445,
    554, 1883, 3389, 4443, 5000, 5357, 5900,
    7547, 8080, 8443, 8888, 9100, 49152,
]))

PORT_INFO = {
    21:    ("FTP",      "⚠️ FTP open — unencrypted"),
    22:    ("SSH",      "🔐 SSH server"),
    23:    ("Telnet",   "🚨 Telnet open — critical risk"),
    25:    ("SMTP",     "📧 Mail server"),
    53:    ("DNS",      "🌐 DNS server"),
    80:    ("HTTP",     "🌍 Web interface"),
    139:   ("NetBIOS",  "🪟 Windows NetBIOS"),
    443:   ("HTTPS",    "🔒 Secure web interface"),
    445:   ("SMB",      "🪟 Windows file sharing"),
    554:   ("RTSP",     "📷 IP Camera"),
    1883:  ("MQTT",     "🔌 IoT MQTT broker"),
    3389:  ("RDP",      "🖥 Windows Remote Desktop"),
    5900:  ("VNC",      "🖥 VNC remote desktop"),
    7547:  ("TR-069",   "⚠️ Router remote management"),
    8080:  ("HTTP-ALT", "🌍 Alt web interface"),
    9100:  ("Printer",  "🖨 Network printer"),
    49152: ("UPnP",     "📡 UPnP service"),
}

PORT_DEVICE_TYPE = {
    554: "IP Camera", 1883: "IoT Device", 9100: "Printer",
    3389: "Windows PC", 7547: "Router/Modem", 23: "Old/IoT Device",
}

scan_results = {}   # ip -> set of open ports
_lock        = threading.Lock()

def _check_masscan():
    try:
        subprocess.run(["masscan", "--version"], capture_output=True, timeout=3)
        return True
    except FileNotFoundError:
        return False

def _run_masscan(target):
    cmd = [
        "masscan", target,
        "-p", PORTS,
        "--rate", str(SCAN_RATE),
        "-e", INTERFACE,
        "--output-format", "json",
        "--output-filename", "-",
        "--wait", "1",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = result.stdout.strip()
        if not output or output == "[]":
            return []
        output = re.sub(r',\s*\]', ']', output)
        if not output.startswith('['):
            output = '[' + output + ']'
        return json.loads(output)
    except Exception as e:
        print(f"[MASSCAN] Error: {e}")
        return []

def _process(raw):
    found = {}
    for entry in raw:
        ip    = entry.get("ip", "")
        ports = entry.get("ports", [])
        if not ip or ip == ROUTER_IP:
            continue
        for p in ports:
            if p.get("proto") != "tcp":
                continue
            found.setdefault(ip, set()).add(p["port"])

    with _lock:
        for ip, ports in found.items():
            scan_results[ip] = ports
            if ip not in sensors.devices:
                continue
            sensors.devices[ip]["open_ports"] = sorted(ports)
            for port, dtype in PORT_DEVICE_TYPE.items():
                if port in ports and not sensors.devices[ip].get("device_type"):
                    sensors.devices[ip]["device_type"] = dtype
            if 3389 in ports:
                sensors.devices[ip]["os"] = "Windows"
            flags = []
            if 23 in ports:   flags.append("TELNET_OPEN")
            if 21 in ports:   flags.append("FTP_OPEN")
            if 7547 in ports: flags.append("TR069_EXPOSED")
            if flags:
                sensors.devices[ip]["security_flags"] = flags
    return found

def scan_subnet():
    print(f"[MASSCAN] Scanning {SUBNET}...")
    t0  = time.time()
    raw = _run_masscan(SUBNET)
    found = _process(raw)
    dt = time.time() - t0
    total = sum(len(p) for p in found.values())
    print(f"[MASSCAN] Done in {dt:.1f}s — {len(found)} devices, {total} open ports")

def scan_ip(ip):
    raw   = _run_masscan(ip)
    found = _process(raw)
    ports = found.get(ip, set())
    print(f"[MASSCAN] {ip}: {sorted(ports) or 'no open ports'}")
    return ports

def get_open_ports(ip):
    with _lock:
        return sorted(scan_results.get(ip, set()))

def get_port_info(port):
    return PORT_INFO.get(port, (str(port), f"Port {port}"))

def get_security_issues(ip):
    return [
        f"{PORT_INFO[p][0]}: {PORT_INFO[p][1]}"
        for p in get_open_ports(ip)
        if p in PORT_INFO and ("⚠️" in PORT_INFO[p][1] or "🚨" in PORT_INFO[p][1])
    ]

def _continuous_scan():
    time.sleep(20)   # let sensors warm up first
    while True:
        try:
            scan_subnet()
        except Exception as e:
            print(f"[MASSCAN] Scan error: {e}")
        time.sleep(RESCAN_EVERY)

def _new_device_watcher():
    known = set()
    time.sleep(15)
    while True:
        time.sleep(5)
        current = set(sensors.devices.keys())
        for ip in current - known:
            if ip != ROUTER_IP:
                threading.Thread(target=scan_ip, args=(ip,), daemon=True).start()
        known = current

def start():
    if not _check_masscan():
        print("[MASSCAN] Not found — install: sudo apt install masscan")
        return False
    threading.Thread(target=_continuous_scan,   daemon=True).start()
    threading.Thread(target=_new_device_watcher,daemon=True).start()
    print(f"[MASSCAN] Active — scanning {SUBNET} every {RESCAN_EVERY}s at {SCAN_RATE} pkt/s")
    return True
