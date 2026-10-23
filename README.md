# NERO v5.0 — Self-Evolving Network Security AI

A self-hosted network monitor for your own LAN. Discovers devices via ARP/mDNS/DHCP/DNS,
builds a behavioral fingerprint per device, scores trust with an Isolation Forest anomaly
model, and can auto-block suspicious devices (ARP-based), rate-limit them, scan them
(masscan/nikto), and alert you via Telegram — all from a live web dashboard.

**Run this only on a network you own or are authorized to administer.** Port scanning,
vulnerability scanning, and ARP-based blocking performed against devices you do not control
is illegal in most jurisdictions.

## Requirements

- Linux, Python 3.9+, root privileges (raw packet sniffing)
- `masscan` and `nikto` installed on the system for those scan features (optional — the app
  detects their absence and disables those features gracefully)

## Install

```bash
sudo apt update
sudo apt install -y python3 python3-pip masscan nikto
pip3 install -r requirements.txt
```

## Run

```bash
sudo python3 main.py
```

Interface, router IP, and subnet are auto-detected. Dashboard: `http://<this-machine-ip>:8080`

## Configuration

Edit the settings block at the top of `main.py`:

- `TELEGRAM_TOKEN` / `TELEGRAM_CHAT_ID` — enable Telegram alerts
- `ENABLE_AUTOBLOCK` — auto-block devices with low trust scores
- `ENABLE_MASSCAN` / `ENABLE_NIKTO` — enable port/vuln scanning of LAN devices
- `ENABLE_PROXIMITY` — enable the optional WiFi/BT proximity module
- `CODE_EVOLVER` / `APPROVAL_REQUIRED` — the self-patching module that proposes code changes
  via the Claude API; patches require human approval by default

## Project layout

| File | Role |
|---|---|
| `main.py` | Entry point, auto-config, wires everything together |
| `sensors.py` | Packet sniffing / device discovery |
| `brain.py` | Trust scoring + anomaly detection |
| `actions.py` | Blocking, rate limiting, Telegram alerts |
| `recon.py` | Device enrichment (apps, services, fingerprints) |
| `masscan_scan.py` / `nikto_scan.py` | Port and web vuln scanning |
| `evolution.py` | Self-tuning trust weights + optional code-patching |
| `proximity.py` | Optional WiFi/Bluetooth proximity monitor |
| `memory.py` | SQLite persistence (`nero.db`, created at runtime, not committed) |
| `dashboard.py` | Web dashboard (Flask) |
| `notifier.py` | Notification dispatch |
