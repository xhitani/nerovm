"""
NERO Nikto — nikto_scan.py
Web vulnerability scanner. Runs Nikto against devices with HTTP ports open.
Finds: default passwords, outdated firmware, CVEs, exposed admin panels.
Requires: sudo apt install nikto
"""
import subprocess, threading, time, re, json
import sensors, memory

_lock         = threading.Lock()
_scan_done    = {}
SCAN_COOLDOWN = 1800   # 30 min between rescans
HTTP_PORTS    = {80, 443, 8080, 8443, 8888}

nikto_results = {}   # ip -> list of findings

SEVERITY_PATTERNS = {
    "critical": ["default password","admin:admin","credentials","backdoor","shell","exec("],
    "high":     ["outdated","vulnerable","CVE-","OSVDB-","XSS","SQL injection","disclosure"],
    "medium":   ["debug","test","backup","config","phpinfo","server-status",".git"],
    "info":     ["cookie","header","allow","options"],
}

def _check_nikto():
    try:
        subprocess.run(["nikto", "-Version"], capture_output=True, timeout=5)
        return True
    except FileNotFoundError:
        return False

def _severity(text):
    tl = text.lower()
    for sev, patterns in SEVERITY_PATTERNS.items():
        if any(p in tl for p in patterns):
            return sev
    return "info"

def _run_nikto(ip, port=80, ssl=False):
    cmd = [
        "nikto", "-host", ip, "-port", str(port),
        "-output", "-", "-Format", "txt",
        "-Tuning", "1234578",
        "-timeout", "5", "-maxtime", "120s",
        "-nointeractive", "-ask", "no",
    ]
    if ssl:
        cmd.append("-ssl")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=150)
        return r.stdout
    except subprocess.TimeoutExpired:
        print(f"[NIKTO] Timeout {ip}:{port}")
        return ""
    except Exception as e:
        print(f"[NIKTO] Error {ip}:{port}: {e}")
        return ""

def _parse(raw, port):
    findings = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("+"):
            continue
        if any(skip in line for skip in ["Target IP:","Target Port:","Start Time:","End Time:","Nikto","host(s)"]):
            continue
        text = line.lstrip("+ ").strip()
        if not text or len(text) < 10:
            continue
        refs = re.findall(r'(?:OSVDB|CVE)[-:]\S+', text)
        findings.append({"port": port, "finding": text[:300], "severity": _severity(text), "refs": refs})
    return findings

def scan_device(ip, open_ports=None):
    now = time.time()
    if now - _scan_done.get(ip, 0) < SCAN_COOLDOWN:
        return

    if open_ports is None:
        try:
            import masscan_scan
            open_ports = masscan_scan.get_open_ports(ip)
        except ImportError:
            open_ports = [80]

    http_ports = [p for p in open_ports if p in HTTP_PORTS]
    if not http_ports:
        return

    _scan_done[ip] = now
    all_findings = []

    for port in http_ports:
        ssl = port in {443, 8443}
        print(f"[NIKTO] Scanning {ip}:{port}{'(SSL)' if ssl else ''}...")
        raw      = _run_nikto(ip, port, ssl)
        findings = _parse(raw, port)
        all_findings.extend(findings)
        for f in findings:
            if f["severity"] in ("critical", "high"):
                memory.save_alert(ip, "VULN_" + f["severity"].upper(), f["severity"],
                                  f"Nikto [{ip}:{port}]: {f['finding'][:150]}")
                print(f"[NIKTO] {f['severity'].upper()}: {f['finding'][:80]}")

    with _lock:
        nikto_results[ip] = all_findings
        if ip in sensors.devices:
            sensors.devices[ip]["nikto"] = all_findings
            worst = "none"
            for f in all_findings:
                if f["severity"] == "critical":                        worst = "critical"; break
                elif f["severity"] == "high" and worst != "critical":  worst = "high"
                elif f["severity"] == "medium" and worst not in ("critical","high"): worst = "medium"
            sensors.devices[ip]["vuln_level"] = worst

    n_crit = sum(1 for f in all_findings if f["severity"] == "critical")
    n_high = sum(1 for f in all_findings if f["severity"] == "high")
    print(f"[NIKTO] {ip}: {len(all_findings)} findings ({n_crit} critical, {n_high} high)")

def get_findings(ip):
    with _lock:
        return list(nikto_results.get(ip, []))

def get_worst_severity(ip):
    findings = get_findings(ip)
    if any(f["severity"] == "critical" for f in findings): return "critical"
    if any(f["severity"] == "high"     for f in findings): return "high"
    if any(f["severity"] == "medium"   for f in findings): return "medium"
    if findings:                                            return "info"
    return "none"

def _scanner_worker():
    time.sleep(45)   # wait for masscan to finish first
    while True:
        try:
            import masscan_scan
            for ip in list(sensors.devices.keys()):
                if ip == sensors.ROUTER_IP:
                    continue
                ports = masscan_scan.get_open_ports(ip)
                if any(p in HTTP_PORTS for p in ports):
                    threading.Thread(target=scan_device, args=(ip, ports), daemon=True).start()
                    time.sleep(10)
        except ImportError:
            for ip in list(sensors.devices.keys()):
                threading.Thread(target=scan_device, args=(ip, [80]), daemon=True).start()
                time.sleep(15)
        time.sleep(SCAN_COOLDOWN)

def start():
    if not _check_nikto():
        print("[NIKTO] Not found — install: sudo apt install nikto")
        return False
    threading.Thread(target=_scanner_worker, daemon=True).start()
    print("[NIKTO] Web vulnerability scanner active")
    return True
