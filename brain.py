"""
NERO Brain — brain.py
DNA fingerprinting, trust scoring, anomaly detection (Isolation Forest).
Retrains models continuously. Feeds results to evolution.py.
"""
import time, threading, numpy as np
from collections import defaultdict
from sklearn.ensemble import IsolationForest
import sensors, memory

_lock         = threading.Lock()
trust_scores  = {}       # ip -> int 0-100
anomaly_models= {}       # ip -> IsolationForest
dna_cache     = defaultdict(list)  # ip -> [vector, ...]

ALERT_THRESHOLD  = 40
RETRAIN_INTERVAL = 60
COOLDOWN         = 120
_cooldowns       = {}

SAMSUNG_DHCP = [
    [1,3,6,15,26,28,51,58,59,43],
    [1,3,6,15,26,28,51,58,59],
    [1,121,3,6,15,119,252,95,44,46],
]

# ── DNA VECTOR ────────────────────────────────────────────────────
def _extract_vector(ip):
    timestamps = list(sensors.arp_timestamps.get(ip, []))
    dev        = sensors.devices.get(ip, {})
    if len(timestamps) < 2:
        return None
    now    = time.time()
    recent = [t for t in timestamps[-100:] if now - t < 3600]
    if len(recent) > 1:
        dur     = max(recent) - min(recent)
        arp_rate= len(recent) / max(dur / 60, 1)
    else:
        arp_rate = 0
    hour          = time.localtime().tm_hour
    active_min    = (max(timestamps) - min(timestamps)) / 60
    unique_hours  = len(set(time.localtime(t).tm_hour for t in timestamps[-100:]))
    visits        = dev.get("packets", 1)
    fp            = sensors.dhcp_fingerprints.get(ip, [])
    is_samsung    = 1 if fp in SAMSUNG_DHCP else 0
    bw            = sensors.bandwidth_now.get(ip, 0)
    return [
        min(arp_rate, 100),
        hour,
        min(active_min, 1440),
        unique_hours,
        min(visits, 200),
        is_samsung,
        min(bw / 1000, 1000),  # KB/s capped
    ]

def update_dna(ip):
    v = _extract_vector(ip)
    if v:
        with _lock:
            dna_cache[ip].append(v)
            if len(dna_cache[ip]) > 500:
                dna_cache[ip] = dna_cache[ip][-500:]
        memory.save_dna(ip, v)

# ── TRUST SCORE ───────────────────────────────────────────────────
def calculate_trust(ip):
    score = 50
    dev   = sensors.devices.get(ip, {})
    macs  = sensors.mac_history.get(ip, set())
    ts    = list(sensors.arp_timestamps.get(ip, []))
    fp    = sensors.dhcp_fingerprints.get(ip, [])

    pkts = dev.get("packets", 0)
    if pkts >= 200: score += 25
    elif pkts >= 50: score += 15
    elif pkts < 5:   score -= 15

    real_macs = [m for m in macs if not sensors._is_random_mac(m) and m != "unknown"]
    rand_macs = [m for m in macs if sensors._is_random_mac(m)]
    if len(real_macs) == 1 and not rand_macs: score += 20
    elif rand_macs and not real_macs:          score += 5
    elif len(real_macs) > 1:                  score -= 50  # MAC changed = spoof

    if fp:                  score += 10
    if fp in SAMSUNG_DHCP:  score += 5
    if sensors.dhcp_names.get(ip) or sensors.mdns_names.get(ip): score += 10

    now    = time.time()
    recent = [t for t in ts if now - t < 60]
    rate   = len(recent)
    if rate > 50:    score -= 30  # ARP flood
    elif rate > 20:  score -= 10
    elif rate < 5:   score += 5

    if 2 <= time.localtime().tm_hour <= 5: score -= 10

    # Isolation Forest signal
    v = _extract_vector(ip)
    if v:
        with _lock:
            model = anomaly_models.get(ip)
        if model:
            try:
                if model.predict([v])[0] == -1:
                    score -= 25
            except Exception:
                pass

    # Blocked = 0
    if ip in sensors.devices and sensors.devices[ip].get("blocked"):
        score = 0

    score = max(0, min(100, score))
    with _lock:
        trust_scores[ip] = score
    memory.upsert_device(ip, trust_score=score)
    return score

def trust_label(score):
    if score >= 80: return "TRUSTED"
    if score >= 60: return "NORMAL"
    if score >= 40: return "SUSPICIOUS"
    if score >= 20: return "DANGEROUS"
    return "BLOCKED"

def trust_color(score):
    if score >= 80: return "#00ff88"
    if score >= 60: return "#00d4ff"
    if score >= 40: return "#ffaa00"
    return "#ff3366"

# ── SPOOF DETECTION ───────────────────────────────────────────────
def check_spoof(ip, new_mac):
    dev = sensors.devices.get(ip, {})
    old_mac = dev.get("mac", "")
    if not old_mac or sensors._is_random_mac(old_mac) or sensors._is_random_mac(new_mac):
        return False
    return old_mac != new_mac

# ── RETRAIN LOOP ──────────────────────────────────────────────────
def _retrain_loop():
    while True:
        time.sleep(RETRAIN_INTERVAL)
        with _lock:
            ips = list(dna_cache.keys())
        for ip in ips:
            with _lock:
                vectors = list(dna_cache.get(ip, []))
            if len(vectors) < 15:
                continue
            try:
                model = IsolationForest(
                    contamination=0.08,
                    n_estimators=100,
                    random_state=42
                )
                model.fit(np.array(vectors))
                with _lock:
                    anomaly_models[ip] = model
            except Exception as e:
                print(f"[BRAIN] Retrain failed {ip}: {e}")

# ── DNA UPDATE LOOP ───────────────────────────────────────────────
def _dna_loop():
    while True:
        time.sleep(10)
        for ip in list(sensors.devices.keys()):
            update_dna(ip)
            calculate_trust(ip)

# ── ALERT COOLDOWN ────────────────────────────────────────────────
def can_alert(ip, key=""):
    k   = f"{ip}:{key}"
    now = time.time()
    if now - _cooldowns.get(k, 0) > COOLDOWN:
        _cooldowns[k] = now
        return True
    return False

def start():
    threading.Thread(target=_retrain_loop, daemon=True).start()
    threading.Thread(target=_dna_loop,     daemon=True).start()
    print("[BRAIN] DNA + trust + anomaly engine active")
