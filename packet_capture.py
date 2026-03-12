from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time
import threading
import csv
from datetime import datetime

# -----------------------------
# Global Stats (imported from app.py in main)
# -----------------------------
# In app.py you will do: from packet_capture import start_sniffing

# Default dictionaries to track stats
scan_tracker = defaultdict(list)   # IP -> list of (port, timestamp)
ip_counter = defaultdict(int)      # IP -> attack count

PORT_SCAN_THRESHOLD = 10
TIME_WINDOW = 5  # seconds

# Thread-safe lock for shared resources
lock = threading.Lock()

# Attack logging function
def log_attack(ip):
    with open("logs/attack_log.csv", "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([datetime.now(), ip, "Suspicious Packet"])

# -----------------------------
# Feature Extraction
# -----------------------------
def extract_features(packet):
    length = len(packet)
    protocol = 0
    flags = 0
    src_ip = "0.0.0.0"

    if IP in packet:
        src_ip = packet[IP].src
        protocol = packet[IP].proto

    if TCP in packet:
        flags = int(packet[TCP].flags)

    return [length, protocol, flags], src_ip

# -----------------------------
# Packet Processing
# -----------------------------
def process_packet(packet, model, stats):
    """
    Process each packet: ML detection, port scan detection, and stats update.
    """
    global scan_tracker, ip_counter

    features, src_ip = extract_features(packet)

    try:
        # Predict attack using ML model
        prediction = model.predict([features])[0]

        with lock:
            stats["total"] += 1

            if prediction == "Attack":
                stats["attacks"] += 1
                ip_counter[src_ip] += 1
                log_attack(src_ip)
            else:
                stats["normal"] += 1

            # ----------------- Port Scan Detection -----------------
            if TCP in packet and packet[TCP].flags == 2:  # SYN
                current_time = time.time()
                scan_tracker[src_ip].append((packet[TCP].dport, current_time))
                # Keep only recent ports within TIME_WINDOW
                scan_tracker[src_ip] = [(p, t) for p, t in scan_tracker[src_ip] if current_time - t <= TIME_WINDOW]
                unique_ports = set(p for p, t in scan_tracker[src_ip])
                if len(unique_ports) >= PORT_SCAN_THRESHOLD:
                    print(f"⚠ ALERT! Port scan detected from {src_ip}")
                    stats["attacks"] += 1
                    ip_counter[src_ip] += 1
                    log_attack(src_ip)
                    # Reset to avoid multiple alerts
                    scan_tracker[src_ip] = []

    except Exception as e:
        print("Packet processing error:", e)

# -----------------------------
# Start Sniffing Thread
# -----------------------------
def start_sniffing(model, stats, iface=None):
    """
    Start sniffing packets on given interface (default all interfaces).
    Pass in ML model and stats dictionary from main app.py
    """
    print("🚀 Packet capture started...")

    sniff(
        iface=iface,
        filter="ip",
        prn=lambda pkt: process_packet(pkt, model, stats),
        store=False
    )