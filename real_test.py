from scapy.all import sniff, ARP
from anomaly import detect_spoofing

log = []

def handle(pkt):
    if pkt.haslayer(ARP):
        entry = {"ip": pkt[ARP].psrc, "mac": pkt[ARP].hwsrc}
        log.append(entry)
        print(f"Captured: {entry['ip']} -> {entry['mac']}")
        
        alerts = detect_spoofing(log)
        for a in alerts:
            print(f"\n[DANGER] REAL ATTACK on {a['ip']}!")
            print(f"  Known MAC:  {a['original_mac']}")
            print(f"  Attack MAC: {a['spoofed_mac']}\n")

print("Monitoring your network... (Ctrl+C to stop)")
sniff(filter="arp", prn=handle, store=False)
