from collections import defaultdict
import time

arp_table = {}
port_scan_log = defaultdict(list)
alerts = []

SUSPICIOUS_DOMAINS = ["malware", "phishing", "evil", "botnet"]

def check_arp_spoof(src_ip, src_mac):
    if src_ip in arp_table:
        if arp_table[src_ip] != src_mac:
            alert = {
                "time": time.strftime("%H:%M:%S"),
                "type": "ARP Spoofing Detected",
                "detail": f"{src_ip} MAC changed: {arp_table[src_ip]} -> {src_mac}",
                "level": "HIGH"
            }
            alerts.append(alert)
            return alert
    arp_table[src_ip] = src_mac
    return None

def check_port_scan(src_ip, dst_port):
    now = time.time()
    port_scan_log[src_ip] = [
        (t, p) for t, p in port_scan_log[src_ip] if now - t < 5
    ]
    port_scan_log[src_ip].append((now, dst_port))
    unique_ports = set(p for _, p in port_scan_log[src_ip])
    if len(unique_ports) >= 10:
        alert = {
            "time": time.strftime("%H:%M:%S"),
            "type": "Port Scan Detected",
            "detail": f"{src_ip} accessed {len(unique_ports)} ports within 5 seconds",
            "level": "MEDIUM"
        }
        alerts.append(alert)
        port_scan_log[src_ip] = []
        return alert
    return None

def check_suspicious_dns(query):
    for keyword in SUSPICIOUS_DOMAINS:
        if keyword in query.lower():
            alert = {
                "time": time.strftime("%H:%M:%S"),
                "type": "Suspicious DNS Query",
                "detail": f"Suspicious domain access attempt: {query}",
                "level": "MEDIUM"
            }
            alerts.append(alert)
            return alert
    return None

def analyze(packet):
    alert = None
    if packet["type"] == "ARP":
        parts = packet["detail"].split()
        hwsrc = parts[1].split("=")[1] if len(parts) > 1 else ""
        alert = check_arp_spoof(packet["src"], hwsrc)
    elif packet["type"] == "TCP":
        try:
            dport = int(packet["detail"].split()[1].split("=")[1])
            alert = check_port_scan(packet["src"], dport)
        except Exception:
            pass
    elif packet["type"] == "DNS":
        try:
            query = packet["detail"].split("=")[1]
            alert = check_suspicious_dns(query)
        except Exception:
            pass
    return alert
