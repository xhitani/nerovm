#!/usr/bin/env python3
"""
NERO - Network Evolution & Response Operator
Full Security Engine v1.0
"""

import time
import threading
import subprocess
import json
import os
import requests
from collections import defaultdict
from scapy.all import sniff, ARP
from sklearn.ensemble import IsolationForest
import numpy as np

# ─────────────────────────────────────────────────────────────────
# CONFIGURATION — edit these
# ─────────────────────────────────────────────────────────────────
TELEGRAM_TOKEN   = ""
TELEGRAM_CHAT_ID = ""
NETWORK_INTERFACE = "enp0s3"        # change to your interface name
ALERT_TRUST_THRESHOLD = 40
RETRAIN_INTERVAL = 60
# ─────────────────────────────────────────────────────────────────

lock = threading.Lock()
dna_store      = defaultdict(list)
devices        = {}
trust_scores   = {}
mac_history    = defaultdict(set)
arp_timestamps = defaultdict(list)
anomaly_models = {}
alert_cooldown = {}
online         = []
COOLDOWN_SECONDS = 120

# ─────────────────────────────────────────────────────────────────
# TELEGRAM
# ─────────────────────────────────────────────────────────────────
def send_telegram(message):
    if TELEGRAM_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print(f"[TELEGRAM] {message}")
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        requests.post(url, data={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "Markdown"
        }, timeout=5)
    except Exception as e:
        print(f"[TELEGRAM] Failed: {e}")

def maybe_alert(ip, message, force=False):
    now = time.time()
    last = alert_cooldown.get(ip, 0)
    if force or (now - last) > COOLDOWN_SECONDS:
        alert_cooldown[ip] = now
        send_telegram(message)

# ─────────────────────────────────────────────────────────────────
# DNA FINGERPRINTING
# ─────────────────────────────────────────────────────────────────
def extract_dna_vector(ip):
    with lock:
        timestamps = arp_timestamps.get(ip, [])
        dev = devices.get(ip, {})

    if len(timestamps) < 2:
        return None

    now = time.time()
    recent = [t for t in timestamps if now - t < 3600]

    if len(recent) > 1:
        duration = max(recent) - min(recent)
        arp_rate = len(recent) / max(duration / 60, 1)
    else:
        arp_rate = 0

    hour = time.localtime().tm_hour

    if timestamps:
        active_minutes = (max(timestamps) - min(timestamps)) / 60
    else:
        active_minutes = 0

    unique_hours = len(set(
        time.localtime(t).tm_hour for t in timestamps[-100:]
    ))

    visits = dev.get("visits", 1)

    return [
        min(arp_rate, 100),
        hour,
        min(active_minutes, 1440),
        min(arp_rate, 100) / 10,
        unique_hours,
        min(visits, 50)
    ]

def update_dna(ip):
    vector = extract_dna_vector(ip)
    if vector:
        with lock:
            dna_store[ip].append(vector)
            if len(dna_store[ip]) > 500:
                dna_store[ip] = dna_store[ip][-500:]

def get_dna_summary(ip):
    with lock:
        vectors = dna_store.get(ip, [])

    if not vectors:
        return "No DNA data yet"

    arr = np.array(vectors)
    avg_rate  = np.mean(arr[:, 0])
    peak_hour = int(np.mean(arr[:, 1]))
    avg_active = np.mean(arr[:, 2])

    return (
        f"ARP rate: {avg_rate:.1f} pkt/min | "
        f"Peak hour: {peak_hour:02d}:00 | "
        f"Avg active: {avg_active:.0f} min"
    )

# ─────────────────────────────────────────────────────────────────
# TRUST SCORING
# ─────────────────────────────────────────────────────────────────
def calculate_trust(ip):
    score = 50

    with lock:
        dev  = devices.get(ip, {})
        macs = mac_history.get(ip, set())
        timestamps = arp_timestamps.get(ip, [])

    visits = dev.get("visits", 1)
    if visits >= 5:
        score += 30
    elif visits >= 2:
        score += 15
    else:
        score -= 20

    if len(macs) == 1:
        score += 20
    elif len(macs) == 2:
        score -= 20
    elif len(macs) >= 3:
        score -= 50

    now = time.time()
    recent = [t for t in timestamps if now - t < 60]
    arp_rate = len(recent)

    if arp_rate > 50:
        score -= 30
    elif arp_rate > 20:
        score -= 10
    elif arp_rate < 10:
        score += 10

    hour = time.localtime().tm_hour
    if 2 <= hour <= 4:
        score -= 10

    vector = extract_dna_vector(ip)
    if vector and ip in anomaly_models:
        try:
            pred = anomaly_models[ip].predict([vector])[0]
            if pred == -1:
                score -= 25
                print(f"[DNA] {ip} anomaly detected")
        except:
            pass

    score = max(0, min(100, score))

    with lock:
        trust_scores[ip] = score

    return score

def trust_label(score):
    if score >= 80: return "TRUSTED"
    if score >= 60: return "NORMAL"
    if score >= 40: return "SUSPICIOUS"
    if score >= 20: return "DANGEROUS"
    return "BLOCKED"

def trust_emoji(score):
    if score >= 80: return "🟢"
    if score >= 60: return "🟡"
    if score >= 40: return "🟠"
    return "🔴"

# ─────────────────────────────────────────────────────────────────
# ARP SPOOFING DETECTION
# ─────────────────────────────────────────────────────────────────
def check_spoofing(ip, mac):
    with lock:
        known_macs = mac_history.get(ip, set())
        dev = devices.get(ip, {})

    if not known_macs:
        return False, None

    original_mac = dev.get("mac")

    if original_mac and mac != original_mac and len(known_macs) >= 1:
        return True, original_mac

    return False, None

# ─────────────────────────────────────────────────────────────────
# PACKET HANDLER
# ─────────────────────────────────────────────────────────────────
def handle_packet(packet):
    if not packet.haslayer(ARP):
        return

    arp = packet[ARP]
    ip  = arp.psrc
    mac = arp.hwsrc

    if ip == "0.0.0.0" or mac == "ff:ff:ff:ff:ff:ff":
        return

    now = time.time()

    with lock:
        arp_timestamps[ip].append(now)
        if len(arp_timestamps[ip]) > 1000:
            arp_timestamps[ip] = arp_timestamps[ip][-1000:]

        mac_history[ip].add(mac)

        if ip not in devices:
            devices[ip] = {
                "ip":         ip,
                "mac":        mac,
                "name":       ip,
                "first_seen": now,
                "last_seen":  now,
                "visits":     1,
            }
            is_new = True
            if ip not in online:
                online.append(ip)
        else:
            devices[ip]["last_seen"] = now
            devices[ip]["visits"]   += 1
            is_new = False

    is_spoofing, original_mac = check_spoofing(ip, mac)
    if is_spoofing:
        msg = (
            f"🚨 *ARP SPOOFING DETECTED*\n"
            f"IP: `{ip}`\n"
            f"Original MAC: `{original_mac}`\n"
            f"Spoofed MAC: `{mac}`"
        )
        print(f"\n{'='*50}")
        print(f"[SPOOF] {ip} MAC changed {original_mac} → {mac}")
        print(f"{'='*50}\n")
        maybe_alert(ip + "_spoof", msg, force=True)

    if is_new:
        score = calculate_trust(ip)
        emoji = trust_emoji(score)
        print(f"[NEW] {emoji} {ip} [{mac}] Trust: {score}/100 ({trust_label(score)})")
        maybe_alert(ip, (
            f"📡 *New Device*\n"
            f"IP: `{ip}`\n"
            f"MAC: `{mac}`\n"
            f"Trust: {score}/100 — {trust_label(score)} {emoji}"
        ))
    else:
        with lock:
            visits = devices[ip]["visits"]
        if visits % 20 == 0:
            score = calculate_trust(ip)
            if score < ALERT_TRUST_THRESHOLD:
                maybe_alert(ip, (
                    f"⚠️ *Low Trust*\n"
                    f"IP: `{ip}`\n"
                    f"Trust: {score}/100 — {trust_label(score)}\n"
                    f"DNA: {get_dna_summary(ip)}"
                ))

    update_dna(ip)

# ─────────────────────────────────────────────────────────────────
# AI MODEL TRAINER
# ─────────────────────────────────────────────────────────────────
def train_anomaly_models():
    while True:
        time.sleep(RETRAIN_INTERVAL)
        with lock:
            ips = list(dna_store.keys())

        for ip in ips:
            with lock:
                vectors = dna_store.get(ip, [])

            if len(vectors) < 10:
                continue

            try:
                X = np.array(vectors)
                model = IsolationForest(
                    contamination=0.1,
                    random_state=42,
                    n_estimators=50
                )
                model.fit(X)
                anomaly_models[ip] = model
                print(f"[AI] Model trained for {ip} — {len(vectors)} samples")
            except Exception as e:
                print(f"[AI] Training failed for {ip}: {e}")

# ─────────────────────────────────────────────────────────────────
# STATUS PRINTER
# ─────────────────────────────────────────────────────────────────
def print_status():
    while True:
        time.sleep(30)
        with lock:
            devs   = dict(devices)
            scores = dict(trust_scores)

        if not devs:
            print("\n[STATUS] No devices seen yet...")
            continue

        print("\n" + "="*65)
        print(f"  NERO STATUS — {time.strftime('%H:%M:%S')} — {len(devs)} devices")
        print("="*65)
        print(f"  {'IP':<18} {'MAC':<20} {'TRUST':<8} {'STATUS'}")
        print("-"*65)

        for ip, dev in sorted(devs.items()):
            score = scores.get(ip, 50)
            emoji = trust_emoji(score)
            label = trust_label(score)
            mac   = dev.get("mac", "unknown")
            print(f"  {ip:<18} {mac:<20} {emoji}{score:<7} {label}")

        print("="*65 + "\n")

# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────
def main():
    print("""
╔══════════════════════════════════════════════════════╗
║         NERO — Security Engine v1.0                  ║
╠══════════════════════════════════════════════════════╣
║  DNA Fingerprinting  ✓                               ║
║  Trust Scoring       ✓                               ║
║  Spoof Detection     ✓                               ║
║  Telegram Alerts     ✓                               ║
║  AI Anomaly Model    ✓                               ║
╚══════════════════════════════════════════════════════╝
""")
    print(f"[NERO] Interface: {NETWORK_INTERFACE}")
    print(f"[NERO] Alert threshold: trust < {ALERT_TRUST_THRESHOLD}")
    print("[NERO] Listening for ARP packets...\n")

    threading.Thread(target=train_anomaly_models, daemon=True).start()
    threading.Thread(target=print_status,         daemon=True).start()

    send_telegram(
        f"🧠 *NERO Started*\n"
        f"Interface: `{NETWORK_INTERFACE}`\n"
        f"Time: {time.strftime('%H:%M:%S')}"
    )

    try:
        sniff(
            iface=NETWORK_INTERFACE,
            filter="arp",
            prn=handle_packet,
            store=False
        )
    except KeyboardInterrupt:
        print("\n[NERO] Stopped.")
    except Exception as e:
        print(f"\n[NERO] Error: {e}")
        print("[NERO] Try: sudo python3 nero.py")
        print("[NERO] Check interface with: ip link show")

if __name__ == "__main__":
    main()
