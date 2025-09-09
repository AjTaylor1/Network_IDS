import time
import logging
import smtplib
import requests
from collections import defaultdict
from email.mime.text import MIMEText
from scapy.all import sniff, IP
from flask import Flask, render_template, jsonify
from threading import Lock

# Configuration
THRESHOLD = 100  # packets
TIME_WINDOW = 60  # seconds
EMAIL_SETTINGS = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 465,
    'username': 'your-email@gmail.com',
    'password': 'your-email-app-password',
    'from_addr': 'your-email@gmail.com',
    'to_addr': 'recipient-email@example.com'
}
SLACK_WEBHOOK_URL = 'https://hooks.slack.com/services/XXXXXXXXX/XXXXXXXXX/XXXXXXXXXXXXXXXXXXXX'

# Logging setup
logging.basicConfig(filename='alerts.log', level=logging.INFO, format='%(asctime)s %(message)s')
alerts = []
alerts_lock = Lock()

# Packet monitoring
packet_counts = defaultdict(int)
start_time = time.time()

# Email alert function
def send_email_alert(message):
    try:
        msg = MIMEText(message)
        msg['Subject'] = 'Network IDS Alert'
        msg['From'] = EMAIL_SETTINGS['from_addr']
        msg['To'] = EMAIL_SETTINGS['to_addr']

        with smtplib.SMTP_SSL(EMAIL_SETTINGS['smtp_server'], EMAIL_SETTINGS['smtp_port']) as server:
            server.login(EMAIL_SETTINGS['username'], EMAIL_SETTINGS['password'])
            server.send_message(msg)
        logging.info("Email alert sent.")
    except Exception as e:
        logging.error(f"Failed to send email alert: {e}")

# Slack alert function
def send_slack_alert(message):
    try:
        payload = {'text': message}
        response = requests.post(SLACK_WEBHOOK_URL, json=payload)
        if response.status_code != 200:
            logging.error(f"Slack alert failed: {response.status_code} {response.text}")
        else:
            logging.info("Slack alert sent.")
    except Exception as e:
        logging.error(f"Failed to send Slack alert: {e}")

# Log alert function
def log_alert(message):
    logging.info(message)
    with alerts_lock:
        alerts.append({'time': time.strftime('%Y-%m-%d %H:%M:%S'), 'message': message})

# Anomaly detection function
def detect_anomalies(pkt):
    global start_time

    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        packet_counts[src_ip] += 1

    current_time = time.time()
    if current_time - start_time > TIME_WINDOW:
        for ip, count in packet_counts.items():
            if count > THRESHOLD:
                alert_msg = f\"High traffic from {ip}: {count} packets in last {TIME_WINDOW} seconds\"
                print(f\"ALERT: {alert_msg}\")
                log_alert(alert_msg)
                send_email_alert(alert_msg)
                send_slack_alert(alert_msg)
        packet_counts.clear()
        start_time = current_time

# Flask web UI
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/alerts')
def get_alerts():
    with alerts_lock:
        return jsonify(alerts[-20:])  # return last 20 alerts

if __name__ == '__main__':
    # Start packet capture in a separate thread
    from threading import Thread
    def start_sniffing():
        sniff(prn=detect_anomalies, store=False)
    Thread(target=start_sniffing, daemon=True).start()

    # Start Flask web UI
    app.run(debug=True, use_reloader=False)
