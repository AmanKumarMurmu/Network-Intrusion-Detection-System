# 🛡️ Sentinel AI

### AI-Powered Network Intrusion Detection & Security Monitoring System

**Sentinel AI** is a cybersecurity-focused Network Intrusion Detection System (NIDS) designed to analyze network traffic, identify suspicious activities, classify potential attacks, and provide security insights through an interactive monitoring dashboard.

The system combines **network traffic analysis, machine learning, security alerting, and visualization** to provide a simplified SOC-style security monitoring experience.

---

## 🚀 Key Features

* 🔍 **Network Traffic Analysis** — Capture and analyze network traffic and connection patterns.
* 🧩 **Feature Extraction** — Extract relevant features from network packets for security analysis.
* 🤖 **ML-Based Detection** — Classify network activity as normal or potentially malicious.
* 🚨 **Threat Detection** — Identify suspicious activities such as:

  * Port Scanning
  * DoS/DDoS Patterns
  * Brute-Force Attempts
  * Suspicious Network Connections
* 📊 **Security Dashboard** — Visualize network activity and detected threats.
* 🌐 **IP & Connection Visibility** — Display source IP, destination IP, protocol, and related traffic information.
* ⚠️ **Risk Classification** — Categorize detected events based on their potential severity.
* 🔔 **Security Alerts** — Generate alerts when suspicious activity is detected.
* 🗄️ **Event Storage** — Store security events for analysis and monitoring.
* 📈 **Threat Analytics** — Visualize attack frequency and security trends over time.

---

## 🧠 How It Works

```text
                Network Traffic
                       │
                       ▼
              Traffic Capture
                       │
                       ▼
              Feature Extraction
                       │
                       ▼
             Machine Learning Model
                       │
                       ▼
             ┌─────────┴─────────┐
             │                   │
          Normal              Suspicious
             │                   │
             ▼                   ▼
       Normal Event        Threat Detection
                                 │
                                 ▼
                         Risk Classification
                                 │
                                 ▼
                         Security Alert
                                 │
                                 ▼
                         Monitoring Dashboard
```

---

## 🛠️ Technology Stack

| Technology            | Purpose                                      |
| --------------------- | -------------------------------------------- |
| **Python**            | Core security and data-processing logic      |
| **Scikit-learn**      | Machine learning and traffic classification  |
| **Pandas**            | Dataset processing and analysis              |
| **NumPy**             | Numerical and feature processing             |
| **Scapy**             | Network packet capture and analysis          |
| **Flask / Streamlit** | Web-based monitoring interface               |
| **SQLite**            | Security event storage                       |
| **Linux**             | Security testing and development environment |
| **Wireshark**         | Network traffic inspection and analysis      |

---

## 🔐 Detected Threat Categories

### Port Scanning

Identifies patterns where a source attempts to probe multiple ports or services on a host.

### DoS/DDoS Patterns

Detects abnormal traffic patterns that may indicate attempts to overwhelm a network service.

### Brute-Force Attempts

Identifies repeated connection or authentication attempts that may indicate credential-based attacks.

### Suspicious Connections

Highlights unusual network communication based on traffic characteristics and detection rules.

---

## 📊 Security Dashboard

The dashboard provides visibility into detected network activity, including:

* Source IP Address
* Destination IP Address
* Network Protocol
* Attack/Threat Type
* Risk Level
* Timestamp
* Security Event History
* Attack Trends
* Alert Statistics

This provides a simplified **SOC-style monitoring interface** for analyzing security events.

---

## 🤖 Machine Learning Pipeline

Sentinel AI follows a basic machine-learning security pipeline:

```text
Raw Network Data
       ↓
Data Cleaning
       ↓
Feature Extraction
       ↓
Feature Processing
       ↓
Model Training
       ↓
Traffic Classification
       ↓
Threat Detection
       ↓
Security Alert
```

The ML component can be trained using labeled network-security datasets and used to classify previously unseen traffic based on learned patterns.

---

## 📁 Suggested Project Structure

```text
sentinel-ai/
│
├── data/
│   └── datasets/
│
├── models/
│   └── intrusion_model.pkl
│
├── src/
│   ├── packet_capture.py
│   ├── feature_extraction.py
│   ├── detection.py
│   └── alerts.py
│
├── dashboard/
│   └── app.py
│
├── database/
│   └── security_events.db
│
├── requirements.txt
├── README.md
└── .gitignore
```

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone <your-repository-url>
cd sentinel-ai
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

On Linux:

```bash
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Start the application

For a Streamlit application:

```bash
streamlit run app.py
```

For a Flask application:

```bash
python app.py
```

---

## 🧪 Security Testing

The system can be evaluated using:

* Public intrusion-detection datasets
* Controlled network traffic
* Simulated scanning activity
* Benign and suspicious traffic samples
* Packet captures analyzed with Wireshark

> **Note:** Security testing should only be performed on systems and networks where you have explicit authorization.

---

## 📈 Future Improvements

Planned improvements include:

* [ ] Real-time packet monitoring
* [ ] Advanced anomaly detection
* [ ] Multiple ML models for comparison
* [ ] IP reputation integration
* [ ] Email/Telegram security notifications
* [ ] Role-based authentication
* [ ] Detailed incident investigation
* [ ] Automated security reports
* [ ] MITRE ATT&CK technique mapping
* [ ] Integration with SIEM platforms
* [ ] Docker-based deployment

---

## 🎯 Project Objectives

The main objectives of Sentinel AI are to:

1. Detect suspicious network behavior.
2. Apply machine learning to network-security analysis.
3. Provide centralized visibility into security events.
4. Generate actionable security alerts.
5. Demonstrate practical concepts used in **IDS, SOC monitoring, network security, and threat detection**.

---

## 🌐 Live Demo

**Sentinel AI:** `https://threat-sniffer-ai.lovable.app`

---

## 👨‍💻 Project Highlights

Sentinel AI demonstrates practical knowledge of:

**Cybersecurity • Network Security • Intrusion Detection • Machine Learning • Packet Analysis • Threat Detection • Security Monitoring • Python • Linux • Database Management**

---

## ⚠️ Disclaimer

Sentinel AI is an educational cybersecurity project intended for authorized security testing, research, and learning purposes.

Do not use the project to monitor, scan, or analyze networks without proper authorization.

---


