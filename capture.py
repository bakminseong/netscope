from scapy.all import sniff, ARP, IP, TCP, UDP, DNS, DNSQR
import threading

packet_queue = []
lock = threading.Lock()

def process_packet(pkt):
    data = {"type": "OTHER", "src": "", "dst": "", "detail": ""}

    if pkt.haslayer(ARP):
        data["type"] = "ARP"
        data["src"] = pkt[ARP].psrc
        data["dst"] = pkt[ARP].pdst
        data["detail"] = f"op={pkt[ARP].op} hwsrc={pkt[ARP].hwsrc}"

    elif pkt.haslayer(IP):
        data["src"] = pkt[IP].src
        data["dst"] = pkt[IP].dst

        if pkt.haslayer(TCP):
            data["type"] = "TCP"
            data["detail"] = f"sport={pkt[TCP].sport} dport={pkt[TCP].dport} flags={pkt[TCP].flags}"

        elif pkt.haslayer(UDP):
            data["type"] = "UDP"
            data["detail"] = f"sport={pkt[UDP].sport} dport={pkt[UDP].dport}"

            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                data["type"] = "DNS"
                data["detail"] = f"query={pkt[DNSQR].qname.decode()}"

    with lock:
        packet_queue.append(data)
        if len(packet_queue) > 500:
            packet_queue.pop(0)

def start_capture(interface="ens33"):
    sniff(iface=interface, prn=process_packet, store=False)
