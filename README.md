# 🛡 AI Intrusion Detection System (AI IDS)

**Author:** Jyothi Samberpu  
**GitHub:** [jyothi-samberpu](https://github.com/jyothi-samberpu/AI_IDS_Project)

## Overview

This project is an **AI-powered Network Intrusion Detection System (IDS)** that monitors network traffic in real-time and detects suspicious activity. It uses **machine learning** to identify attacks and includes features like **port scan detection**, **live dashboard**, and **top attacker tracking**.

This system is ideal for demonstrating **cybersecurity monitoring** and **SOC-style dashboards**.

## Features

- **ML-based attack detection** (predicts if a packet is malicious or normal)
- **Port scan detection** (detects SYN scans over multiple ports)
- **Live dashboard** with statistics:
  - Total packets
  - Attacks
  - Normal packets
  - Port scans
  - Top attacker IPs
- \*\*Live charts:
  - Pie chart for Attack vs Normal packets
  - Packets per second line chart
- **Logging**: All suspicious packets are logged to `logs/attack_log.csv`
- Modular and thread-safe design

## Requirements

- Python 3.10+
- Libraries:

  ```bash
  pip install flask scapy joblib chart.js


  Installation

    1.Clone the repository:
            git clone https://github.com/jyothi-samberpu/AI_IDS_Project.git
            cd AI_IDS_Project
  ```

(Optional) Create a virtual environment:

python -m venv .venv
.venv\Scripts\activate # Windows
source .venv/bin/activate # Linux/Mac

Install dependencies:

pip install -r requirements.txt

Run the application:

python app.py

Open your browser and go to:

http://127.0.0.1:5000
Project Structure
AI_IDS_Project/
├─ app.py # Main Flask app and dashboard
├─ dashboard.html # HTML template for live dashboard
├─ packet_capture.py # Packet sniffing and attack processing
├─ models/
│ └─ trained_model.pkl # Pre-trained ML model
├─ logs/ # Attack logs (CSV files)
├─ dataset/ # Sample dataset
├─ .venv/ # Python virtual environment
├─ utils/ # Utility scripts
└─ README.md
How It Works

The system captures live IP packets using Scapy.

Each packet is processed in real-time:

Features like packet length, protocol, and TCP flags are extracted.

ML model predicts if it’s Normal or Attack.

Suspicious activity is logged.

Port scan detection monitors SYN packets to multiple ports and raises alerts.

The dashboard updates live, showing:
Packet counts
Top attackers
Port scans
Traffic graphs

Future Enhancements
Add detection for UDP and ICMP attacks.
Include alert notifications on the dashboard.
Integrate with real SOC logging systems.
Train the ML model with more diverse attack datasets.

License

This project is open-source and available under the MIT License.

Author
Jyothi Samberpu
GitHub
https://github.com/jyothi-samberpu/AI_IDS_Project
L
