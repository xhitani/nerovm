# NERO v5.0 — Network Security Monitoring & Response

NERO is a self-hosted network security monitoring project designed to discover devices on a local network, analyze behavioral patterns, assess device trust, and support security response actions through a live web dashboard.

> **Important:** NERO must run on a suitable Linux host with access to the network it monitors. Hosting the dashboard on AWS EC2 does not automatically provide visibility into devices on your home Wi-Fi.

## Features

- **Device discovery:** Uses network protocols such as ARP, mDNS, DHCP, and DNS to discover devices where the host has sufficient network visibility.
- **Behavioral analysis:** Builds device profiles and uses an Isolation Forest model to identify potentially unusual behavior.
- **Trust scoring:** Evaluates device behavior to help identify suspicious activity.
- **Security response:** Includes configurable device-blocking and rate-limiting functionality.
- **Network reconnaissance:** Optional Masscan and Nikto integrations.
- **Notifications:** Supports Telegram alerts when configured.
- **Web dashboard:** Flask-based dashboard for viewing monitoring information.
- **Persistent storage:** SQLite-based local data storage.
- **Optional proximity monitoring:** Wi-Fi and Bluetooth proximity functionality.
- **Experimental adaptation:** Includes a module for adjusting trust weights and optionally proposing code changes.

## Architecture

NERO has two distinct deployment responsibilities:

1. **Monitoring and enforcement:** Runs on a Linux host with appropriate access to the target LAN or gateway.
2. **Dashboard and management:** Provides the web interface. It can be hosted locally or remotely, provided the deployment is secured and the necessary data connectivity is configured.

For monitoring and blocking devices across a home network, traffic must be visible to NERO, and blocking actions must be enforced by a device that can control that traffic. A typical solution is a Linux gateway or a compatible router integration.

## Requirements

- Linux
- Python 3.9 or later, subject to dependency compatibility
- Root privileges or the specific capabilities required for packet capture and network enforcement
- Dependencies listed in `requirements.txt`
- Optional: Masscan and Nikto for supported scanning features
- Optional: Telegram bot credentials for notifications

## Installation

Clone the repository:

```bash
git clone https://github.com/xhitani/nerovm.git
cd nerovm
```

Install system packages:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip build-essential
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install Python dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Install optional scanning tools if you intend to use those features:

```bash
sudo apt install -y masscan nikto
```

## Running NERO

Start the application with the privileges required by your deployment:

```bash
sudo .venv/bin/python main.py
```

The dashboard is configured to use port `8080` in the documented setup:

```text
http://<host-ip>:8080
```

Use the actual IP address of the machine running NERO. Ensure firewall rules permit access only from trusted clients.

## Configuration

Review the configuration settings near the beginning of `main.py`. Available options include:

| Setting | Purpose |
|---|---|
| `TELEGRAM_TOKEN` | Telegram bot token for alerts |
| `TELEGRAM_CHAT_ID` | Destination for Telegram notifications |
| `ENABLE_AUTOBLOCK` | Controls automatic blocking behavior |
| `ENABLE_MASSCAN` | Enables the Masscan integration |
| `ENABLE_NIKTO` | Enables the Nikto integration |
| `ENABLE_PROXIMITY` | Enables optional proximity monitoring |
| `CODE_EVOLVER` | Controls experimental code-evolution functionality |
| `APPROVAL_REQUIRED` | Controls approval requirements for proposed code changes |

Verify the actual behavior and defaults in the current source code before enabling security response features.

## Project Structure

| File | Responsibility |
|---|---|
| `main.py` | Application entry point and configuration |
| `sensors.py` | Packet monitoring and device discovery |
| `brain.py` | Trust scoring and anomaly detection |
| `actions.py` | Blocking, rate limiting, and response actions |
| `recon.py` | Device enrichment and service information |
| `masscan_scan.py` | Masscan integration |
| `nikto_scan.py` | Nikto integration |
| `evolution.py` | Trust-weight adaptation and experimental code changes |
| `proximity.py` | Optional Wi-Fi/Bluetooth proximity monitoring |
| `memory.py` | SQLite persistence |
| `dashboard.py` | Flask dashboard |
| `notifier.py` | Notification handling |

## Deployment on AWS EC2

NERO can run on an Ubuntu EC2 instance for remote dashboard hosting and other supported tasks. However, an ordinary EC2 instance is not automatically part of your home LAN.

To monitor and block devices on a home network, use one of the following approaches:

- Deploy NERO on a Linux gateway through which the relevant device traffic passes.
- Integrate with a router that supports the required device-management and firewall controls.
- Use a secure communication channel between a local monitoring agent and a remotely hosted dashboard, if supported by the implementation.

Do not assume that enabling a bridge on the EC2 instance will connect it to your home Wi-Fi.

## Security Considerations

- Use NERO only on networks you own or are authorized to administer.
- Do not expose the dashboard publicly without suitable authentication and access controls.
- Restrict inbound firewall and cloud security-group rules to trusted sources.
- Store credentials and API tokens outside version control.
- Review blocking rules before enabling automatic enforcement.
- Test in an isolated environment before applying changes to a live network.
- Treat vulnerability scanning and experimental code modification as potentially disruptive operations.

## Limitations
