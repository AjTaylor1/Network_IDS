# Network Intrusion Detection System
# Custom Network Traffic IDS

A simple Intrusion Detection System (IDS) prototype to monitor network traffic, detect anomalous patterns, and alert the user in real-time.

## Features

- Packet capture and analysis using Scapy
- Basic anomaly detection (e.g., high packet rates from single IPs)
- Logging of detected anomalies
- Real-time alerts via email and Slack
- Simple web UI to view alerts and stats

## Requirements

- Python 3.7+
- `scapy`
- `flask`
- `requests`
- `schedule`
- Email account for SMTP (e.g., Gmail)
- Slack webhook URL for notifications

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/AjTaylor1/Network_IDS.git
   cd Network_IDS
