from flask import Flask, render_template, jsonify
from scapy.all import sniff, IP, TCP
import joblib
import threading
from collections import defaultdict
import csv
from datetime import datetime
import time

app = Flask(__name__)

# -----------------------------
# Load ML Model
# -----------------------------
model = joblib.load("models/trained_model.pkl")

# -----------------------------
# Dashboard Statistics
# -----------------------------
stats = {"total": 0, "attacks": 0, "normal": 0}
ip_counter = defaultdict(int)
lock = threading.Lock()

# -----------------------------
# Packets per second
# -----------------------------
pps_stats = []
pps_counter = 0

# -----------------------------
# Port Scan Detection
# -----------------------------
scan_tracker = defaultdict(list)  # ip -> list of (dest_port, timestamp)
PORT_SCAN_THRESHOLD = 10
TIME_WINDOW = 5  # seconds

# -----------------------------
# Attack Logging
# -----------------------------
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
# ML Prediction
# -----------------------------
def predict_attack(features):
    try:
        prediction = model.predict([features])[0]
        return prediction
    except Exception:
        return "Normal"

# -----------------------------
# Packet Processing
# -----------------------------
def packet_callback(packet):
    global stats, pps_counter

    try:
        features, src_ip = extract_features(packet)
        result = predict_attack(features)

        with lock:
            stats["total"] += 1
            pps_counter += 1

            if result == "Attack":
                stats["attacks"] += 1
                ip_counter[src_ip] += 1
                log_attack(src_ip)
            else:
                stats["normal"] += 1

            # ----- Port Scan Detection -----
            if TCP in packet and packet[TCP].flags == 2:  # SYN flag
                current_time = time.time()
                scan_tracker[src_ip].append((packet[TCP].dport, current_time))
                # Keep only recent ports in TIME_WINDOW
                scan_tracker[src_ip] = [(port, t) for port, t in scan_tracker[src_ip] if current_time - t <= TIME_WINDOW]
                unique_ports = set(port for port, t in scan_tracker[src_ip])
                if len(unique_ports) >= PORT_SCAN_THRESHOLD:
                    print(f"⚠ ALERT! Port scan detected from {src_ip}")
                    stats["attacks"] += 1
                    ip_counter[src_ip] += 1
                    log_attack(src_ip)
                    scan_tracker[src_ip] = []

    except Exception as e:
        print("Packet processing error:", e)

# -----------------------------
# Packet Sniffing Thread
# -----------------------------
def start_sniffing():
    print("🚀 AI IDS started capturing packets...")
    sniff(filter="ip", prn=packet_callback, store=False)

# -----------------------------
# Update PPS every second
# -----------------------------
def update_pps():
    global pps_stats, pps_counter
    while True:
        time.sleep(1)
        with lock:
            pps_stats.append(pps_counter)
            if len(pps_stats) > 30:
                pps_stats.pop(0)
            pps_counter = 0

# -----------------------------
# Get Top Attackers
# -----------------------------
def get_top_attackers():
    sorted_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)
    return sorted_ips[:5]

# -----------------------------
# Flask Routes
# -----------------------------
@app.route("/")
def dashboard():
    return render_template(
        "dashboard.html",
        total=stats["total"],
        attacks=stats["attacks"],
        normal=stats["normal"],
        attackers=get_top_attackers()
    )

@app.route("/pps_data")
def pps_data():
    with lock:
        return jsonify(pps_stats)

@app.route("/stats_data")
def stats_data():
    with lock:
        port_scan_count = sum(1 for ports in scan_tracker.values() if len(ports) >= PORT_SCAN_THRESHOLD)
        return jsonify({
            "total": stats["total"],
            "attacks": stats["attacks"],
            "normal": stats["normal"],
            "port_scans": port_scan_count,
            "attackers": get_top_attackers()
        })

# -----------------------------
# Start Application
# -----------------------------
if __name__ == "__main__":
    threading.Thread(target=update_pps, daemon=True).start()
    threading.Thread(target=start_sniffing, daemon=True).start()
    app.run(debug=True)