# Intrusion Detection System (IDS)

A modular, Python-based IDS designed for real-world use. It supports signature-based detection, IP reputation checks, and ML-based log analysis.

---

## Who Is This For?

- Security researchers  
- SOC analysts  
- Students learning threat detection  
- DevOps teams needing lightweight IDS


- Security researchers  
- SOC analysts  
- Students learning threat detection  
- DevOps teams needing lightweight IDS

---

## Features

- Real-time log and network monitoring  
- Signature-based threat detection  
- IP reputation checks (AbuseIPDB, VirusTotal)  
- ML-based log classification using scikit-learn  
- Telegram/console alerting with HTML formatting  
- SQLite-based alert storage  
- Modular architecture for easy extension

---

## Installation

```
git clone https://github.com/Agz4roth/Intrusion-Detection-System.git
cd Intrusion-Detection-System
pip install -r requirements.txt
```

---

Usage

`
python src/ids.py
`

Log files are monitored in real-time. Alerts are dispatched based on severity and classification. Configuration is managed via config/signature_rules.json.

---

Extending

- Add ML-based anomaly detection modules  
- Integrate IP reputation APIs (AbuseIPDB, VirusTotal)  
- Expose REST API for querying stored threats  
- Add Prometheus metrics and Grafana dashboards

---

Security Notes

- Avoid running as root unless necessary  
- Review and sanitize alert content before deployment  
- Keep signature rules under version control

---

License

Released under the MIT License.

---

Project Status

Version: v0.1.0  
Status: Under active development  
Roadmap: REST API, Docker image, ML-based anomaly detection

---

Folder Structure

```
├── src/                  # Core IDS logic
├── models/               # ML models (e.g., log_model.pkl)
├── logs/                 # Input log files
├── config/               # Signature rules
├── data/                 # SQLite DB and network_events.log
├── requirements.txt      # Dependencies
├── README.md             # Project overview
```
---
