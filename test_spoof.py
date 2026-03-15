# test_spoof.py
from anomaly import detect_spoofing

# Simulate: same IP, two different MACs = spoofing attack
fake_log = [
    {"ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:ff"},
    {"ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:ff"},  # same, ok
    {"ip": "192.168.1.5", "mac": "11:22:33:44:55:66"},  # different MAC = ALERT
]

alerts = detect_spoofing(fake_log)
for a in alerts:
    print(f"[ALERT] Spoofing detected on {a['ip']}")
    print(f"  Original MAC: {a['original_mac']}")
    print(f"  Spoofed  MAC: {a['spoofed_mac']}")
