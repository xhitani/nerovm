"""
NERO Proximity — proximity.py
Captures WiFi probe requests from nearby devices using monitor mode.
Detects phones/laptops that are near you but NOT on your network.

How it works:
  - Puts a second interface into monitor mode via airmon-ng
  - Sniffs 802.11 probe request frames (type=0, subtype=4)
  - Every device with WiFi ON sends these every few seconds
  - Extracts MAC, signal strength (RSSI), and probed SSIDs
  - Identifies manufacturer from MAC OUI
  - Tracks first/last seen, signal history, probed networks

Requirements:
  sudo apt install aircrack-ng
  A WiFi adapter that supports monitor mode (NOT your main adapter)
  Set MONITOR_INTERFACE below to your second adapter (e.g. wlan1)
"""
import threading, time, json, subprocess, re, os
from collections import defaultdict
from scapy.all import sniff, Dot11, Dot11ProbeReq, Dot11Elt, RadioTap

# ── CONFIG ────────────────────────────────────────────────────────
MONITOR_INTERFACE = "wlan1"   # Change to your monitor-mode adapter
CHANNEL_HOP       = True      # Hop channels to catch more devices
HOP_INTERVAL      = 0.5       # Seconds per channel
CHANNELS          = [1,2,3,4,5,6,7,8,9,10,11,12,13,36,40,44,48]
DEVICE_TIMEOUT    = 300       # Remove device after 5 min of silence
MON_INTERFACE     = ""        # Set by start() after airmon-ng runs

_lock   = threading.Lock()

# ── PROXIMITY STORE ───────────────────────────────────────────────
# mac -> {
#   mac, vendor, first_seen, last_seen,
#   rssi_history: [int], probed_ssids: set,
#   probe_count: int, on_network: bool
# }
nearby_devices = {}

# ── OUI LOOKUP (same as recon.py) ────────────────────────────────
OUI_MAP = {
    "00:03:93":"Apple",    "00:05:02":"Apple",    "00:0a:27":"Apple",
    "00:0a:95":"Apple",    "00:11:24":"Apple",    "00:16:cb":"Apple",
    "00:17:f2":"Apple",    "00:1b:63":"Apple",    "00:1c:b3":"Apple",
    "3c:07:54":"Apple",    "40:30:04":"Apple",    "a4:b1:97":"Apple",
    "a4:c3:61":"Apple",    "a8:20:66":"Apple",    "f0:18:98":"Apple",
    "f4:f1:5a":"Apple",    "dc:2b:2a":"Apple",    "8c:85:90":"Apple",
    "b8:78:2e":"Apple",    "d0:03:4b":"Apple",    "00:cd:fe":"Apple",
    "b8:8d:12":"Apple",    "f8:4d:89":"Apple",    "28:f0:76":"Apple",
    "00:07:ab":"Samsung",  "00:12:47":"Samsung",  "10:30:47":"Samsung",
    "2c:ae:2b":"Samsung",  "34:23:87":"Samsung",  "50:a4:c8":"Samsung",
    "54:88:0e":"Samsung",  "5c:f6:dc":"Samsung",  "70:f9:27":"Samsung",
    "78:1f:db":"Samsung",  "84:25:19":"Samsung",  "a0:07:98":"Samsung",
    "c0:bd:d1":"Samsung",  "e4:40:e2":"Samsung",  "38:aa:3c":"Samsung",
    "00:9e:c8":"Xiaomi",   "04:cf:8c":"Xiaomi",   "28:6c:07":"Xiaomi",
    "34:80:b3":"Xiaomi",   "50:64:2b":"Xiaomi",   "64:09:80":"Xiaomi",
    "74:51:ba":"Xiaomi",   "98:fa:e3":"Xiaomi",   "7c:1d:d9":"Xiaomi",
    "00:18:82":"Huawei",   "00:e0:fc":"Huawei",   "10:1b:54":"Huawei",
    "34:6b:d3":"Huawei",   "70:72:3c":"Huawei",   "9c:b2:b2":"Huawei",
    "14:91:82":"Amazon",   "44:65:0d":"Amazon",   "74:c2:46":"Amazon",
    "b8:27:eb":"Raspberry Pi","dc:a6:32":"Raspberry Pi",
    "00:15:5d":"Microsoft","48:50:73":"Microsoft",
    "00:0c:29":"VMware",   "08:00:27":"VirtualBox",
    "50:c7:bf":"TP-Link",  "14:cc:20":"TP-Link",  "c0:4a:00":"TP-Link",
    "00:1a:2b":"Cisco",    "18:33:9d":"Cisco",
    "00:26:b9":"Dell",     "b8:ca:3a":"Dell",
    "8c:16:45":"HP",       "fc:15:b4":"HP",
    "00:1d:09":"Lenovo",   "54:ee:75":"Lenovo",
    "00:26:c6":"Nintendo", "98:b6:e9":"Nintendo",
    "18:b4:30":"Nest",     "64:16:66":"Nest",
    "00:17:88":"Philips Hue",
}

def _get_vendor(mac):
    if not mac or len(mac) < 8:
        return "Unknown"
    oui = mac[:8].lower()
    return OUI_MAP.get(oui, "Unknown")

def _is_random_mac(mac):
    """Randomized MACs have locally administered bit set."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except Exception:
        return False

def _signal_quality(rssi):
    """Convert RSSI to human-readable signal strength."""
    if rssi >= -50:  return "🟢 Excellent (very close)"
    if rssi >= -65:  return "🟡 Good (same room)"
    if rssi >= -75:  return "🟠 Fair (nearby)"
    if rssi >= -85:  return "🔴 Weak (further away)"
    return "⚫ Very weak (far)"

def _estimate_distance(rssi):
    """Rough distance estimate from RSSI (assumes ~0dBi antenna)."""
    if rssi >= -50:  return "< 2m"
    if rssi >= -60:  return "2–5m"
    if rssi >= -70:  return "5–15m"
    if rssi >= -80:  return "15–30m"
    return "> 30m"

# ── PROBE REQUEST HANDLER ─────────────────────────────────────────
def _handle_probe(pkt):
    """Process a captured 802.11 probe request frame."""
    try:
        # Must be a probe request (type=0 management, subtype=4)
        if not pkt.haslayer(Dot11):
            return
        if pkt[Dot11].type != 0 or pkt[Dot11].subtype != 4:
            return

        mac = pkt[Dot11].addr2
        if not mac or mac == "ff:ff:ff:ff:ff:ff":
            return
        mac = mac.lower()

        # Extract RSSI from RadioTap header
        rssi = -100
        if pkt.haslayer(RadioTap):
            try:
                rssi = -(256 - pkt[RadioTap].dBm_AntSignal) if pkt[RadioTap].dBm_AntSignal > 0 else pkt[RadioTap].dBm_AntSignal
            except Exception:
                pass

        # Extract probed SSID
        ssid = ""
        if pkt.haslayer(Dot11Elt):
            try:
                ssid_raw = pkt[Dot11Elt].info
                if ssid_raw:
                    ssid = ssid_raw.decode("utf-8", errors="ignore").strip()
            except Exception:
                pass

        now = time.time()

        with _lock:
            if mac not in nearby_devices:
                vendor = _get_vendor(mac)
                nearby_devices[mac] = {
                    "mac":          mac,
                    "vendor":       vendor,
                    "randomized":   _is_random_mac(mac),
                    "first_seen":   now,
                    "last_seen":    now,
                    "rssi_history": [],
                    "rssi":         rssi,
                    "probed_ssids": set(),
                    "probe_count":  0,
                    "on_network":   False,
                }
                print(f"[PROXIMITY] New nearby device: {mac} ({vendor}) RSSI={rssi}dBm")
            else:
                nearby_devices[mac]["last_seen"] = now
                nearby_devices[mac]["rssi"]       = rssi

            dev = nearby_devices[mac]
            dev["probe_count"] += 1
            dev["rssi_history"].append(rssi)
            if len(dev["rssi_history"]) > 50:
                dev["rssi_history"] = dev["rssi_history"][-50:]
            if ssid and len(ssid) > 0 and ssid != "\x00":
                dev["probed_ssids"].add(ssid)

    except Exception as e:
        pass

# ── CHANNEL HOPPER ────────────────────────────────────────────────
def _channel_hopper():
    """Hop through WiFi channels to catch probes on all frequencies."""
    iface = MON_INTERFACE or MONITOR_INTERFACE
    idx   = 0
    while True:
        ch = CHANNELS[idx % len(CHANNELS)]
        try:
            subprocess.run(
                ["iwconfig", iface, "channel", str(ch)],
                capture_output=True, timeout=1
            )
        except Exception:
            pass
        idx += 1
        time.sleep(HOP_INTERVAL)

# ── DEVICE CLEANUP ────────────────────────────────────────────────
def _cleanup_loop():
    """Remove devices not seen recently."""
    while True:
        time.sleep(30)
        now = time.time()
        with _lock:
            stale = [
                mac for mac, dev in nearby_devices.items()
                if now - dev["last_seen"] > DEVICE_TIMEOUT
            ]
            for mac in stale:
                del nearby_devices[mac]
                print(f"[PROXIMITY] {mac} left proximity")

# ── MONITOR MODE SETUP ────────────────────────────────────────────
def _start_monitor_mode(iface):
    """Put interface into monitor mode using airmon-ng."""
    print(f"[PROXIMITY] Starting monitor mode on {iface}...")

    # Kill interfering processes
    try:
        subprocess.run(["airmon-ng", "check", "kill"],
                       capture_output=True, timeout=10)
        print("[PROXIMITY] Killed interfering processes")
    except Exception as e:
        print(f"[PROXIMITY] airmon-ng check kill: {e}")

    # Start monitor mode
    try:
        result = subprocess.run(
            ["airmon-ng", "start", iface],
            capture_output=True, text=True, timeout=15
        )
        output = result.stdout + result.stderr

        # airmon-ng renames interface: wlan1 -> wlan1mon
        mon_name = iface + "mon"
        match = re.search(r'monitor mode (?:vif )?enabled (?:for|on) \[?(\w+)\]?', output)
        if match:
            mon_name = match.group(1)

        # Verify the monitor interface exists
        check = subprocess.run(["iwconfig", mon_name],
                               capture_output=True, text=True, timeout=5)
        if "Monitor" in check.stdout:
            print(f"[PROXIMITY] Monitor mode active: {mon_name}")
            return mon_name
        else:
            # Try the original name (some drivers don't rename)
            check2 = subprocess.run(["iwconfig", iface],
                                    capture_output=True, text=True, timeout=5)
            if "Monitor" in check2.stdout:
                print(f"[PROXIMITY] Monitor mode active: {iface}")
                return iface

        print(f"[PROXIMITY] Monitor mode may be active — using {mon_name}")
        return mon_name

    except Exception as e:
        print(f"[PROXIMITY] Failed to start monitor mode: {e}")
        return None

def _stop_monitor_mode(mon_iface):
    """Restore interface to managed mode."""
    try:
        subprocess.run(["airmon-ng", "stop", mon_iface],
                       capture_output=True, timeout=10)
        # Restart network manager
        subprocess.run(["systemctl", "restart", "NetworkManager"],
                       capture_output=True, timeout=10)
        print(f"[PROXIMITY] Monitor mode stopped on {mon_iface}")
    except Exception as e:
        print(f"[PROXIMITY] Stop monitor error: {e}")

# ── PUBLIC API ────────────────────────────────────────────────────
def get_nearby_devices():
    """Return list of nearby devices sorted by signal strength."""
    with _lock:
        devs = []
        for mac, dev in nearby_devices.items():
            avg_rssi = int(sum(dev["rssi_history"]) / max(len(dev["rssi_history"]), 1))
            devs.append({
                "mac":          mac,
                "vendor":       dev["vendor"],
                "randomized":   dev["randomized"],
                "rssi":         avg_rssi,
                "signal":       _signal_quality(avg_rssi),
                "distance":     _estimate_distance(avg_rssi),
                "first_seen":   time.strftime("%H:%M:%S", time.localtime(dev["first_seen"])),
                "last_seen":    time.strftime("%H:%M:%S", time.localtime(dev["last_seen"])),
                "probe_count":  dev["probe_count"],
                "probed_ssids": sorted(dev["probed_ssids"]),
                "on_network":   dev["on_network"],
                "age_sec":      int(time.time() - dev["first_seen"]),
            })
        return sorted(devs, key=lambda x: x["rssi"], reverse=True)

def mark_on_network(mac):
    """Called by sensors when a device joins the LAN."""
    mac = mac.lower()
    with _lock:
        if mac in nearby_devices:
            nearby_devices[mac]["on_network"] = True

def get_count():
    with _lock:
        return len(nearby_devices)

# ── START ─────────────────────────────────────────────────────────
_mon_iface = None

def start():
    global MON_INTERFACE, _mon_iface

    # Check airmon-ng is installed
    try:
        subprocess.run(["airmon-ng", "--help"],
                       capture_output=True, timeout=3)
    except FileNotFoundError:
        print("[PROXIMITY] airmon-ng not found — install: sudo apt install aircrack-ng")
        print("[PROXIMITY] Proximity tracking disabled")
        return False

    # Check adapter exists
    try:
        result = subprocess.run(["iwconfig", MONITOR_INTERFACE],
                                capture_output=True, text=True, timeout=3)
        if "No such device" in result.stderr or MONITOR_INTERFACE not in result.stdout:
            print(f"[PROXIMITY] Interface {MONITOR_INTERFACE} not found")
            print(f"[PROXIMITY] Available interfaces:")
            os.system("iwconfig 2>/dev/null | grep -E '^[a-z]'")
            print(f"[PROXIMITY] Set MONITOR_INTERFACE in proximity.py to your WiFi adapter")
            return False
    except Exception as e:
        print(f"[PROXIMITY] Interface check failed: {e}")
        return False

    # Start monitor mode
    mon = _start_monitor_mode(MONITOR_INTERFACE)
    if not mon:
        print("[PROXIMITY] Could not start monitor mode — is your adapter supported?")
        return False

    _mon_iface = mon
    MON_INTERFACE = mon

    # Start threads
    if CHANNEL_HOP:
        threading.Thread(target=_channel_hopper, daemon=True).start()
    threading.Thread(target=_cleanup_loop, daemon=True).start()

    # Start probe sniffer
    def _sniffer():
        sniff(
            iface=mon,
            prn=_handle_probe,
            store=0,
            filter="type mgt subtype probe-req"
        )
    threading.Thread(target=_sniffer, daemon=True).start()

    print(f"[PROXIMITY] Probe capture active on {mon}")
    print(f"[PROXIMITY] Channel hopping: {'ON' if CHANNEL_HOP else 'OFF'}")
    print(f"[PROXIMITY] Capturing probe requests from nearby devices...")
    return True

def stop():
    if _mon_iface:
        _stop_monitor_mode(_mon_iface)
