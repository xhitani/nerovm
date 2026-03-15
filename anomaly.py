def detect_spoofing(log):
    ip_to_mac = {}
    alerts = []
    for entry in log:
        ip = entry["ip"]
        mac = entry["mac"]
        if ip in ip_to_mac:
            if ip_to_mac[ip] != mac:
                alerts.append({
                    "ip": ip,
                    "original_mac": ip_to_mac[ip],
                    "spoofed_mac": mac
                })
        else:
            ip_to_mac[ip] = mac
    return alerts
