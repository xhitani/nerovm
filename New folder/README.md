# NERO PLATINUM (Ubuntu Server)

Run the dashboard + passive network monitor on your own LAN.

## Install

```bash
sudo apt update
sudo apt install -y python3 python3-pip
pip3 install -r requirements.txt
```

## Run

Packet sniffing typically requires root:

```bash
sudo python3 main111.py --interface eth0 --router-ip 192.168.1.1 --lan-prefix 192.168.1.
```

Dashboard: `http://<server-ip>:8080`

## Run with systemd (systemctl start nero)

Suggested layout:

```bash
sudo mkdir -p /opt/nero /etc/nero
sudo cp -r ./* /opt/nero/
sudo cp nero.service /etc/systemd/system/nero.service
sudo cp nero.env.example /etc/nero/nero.env
sudo nano /etc/nero/nero.env
sudo systemctl daemon-reload
sudo systemctl enable --now nero
```

Logs:

```bash
sudo journalctl -u nero -f
```

## Safer defaults (recommended)

By default, **active interference** features are disabled.

## Opt-in: active interference (authorized testing only)

If you explicitly want to enable the active features, you must set an env var and a flag:

```bash
export NERO_ENABLE_ACTIVE=1
sudo -E python3 main111.py --enable-active --interface eth0 --router-ip 192.168.1.1 --lan-prefix 192.168.1.
```

## Notifier HTTP port

The notifier serves HTTP on port 80 by default. Override with:

```bash
export NERO_HTTP_PORT=8081
sudo -E python3 main111.py --interface eth0
```

