# Sentinel NIDS — Python capture agent

Linux sensor that captures traffic, extracts flow features, classifies them with
scikit-learn, stores events in SQLite and streams detections to the web dashboard.

## Stack

Python · Scapy (capture) · Pandas/NumPy (features) · scikit-learn (RandomForest
Normal/Attack classifier) · SQLite (local event store) · Streamlit (optional
local dashboard) · Wireshark/tcpdump (pcap replay).

## Install

```bash
cd agent
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## 1. Train the model

```bash
python train_model.py     # writes model.joblib + prints precision/recall
```

Replace `build_dataset()` in `train_model.py` with a labelled export
(CIC-IDS2017, NSL-KDD, or your own captures) mapped onto `FEATURE_NAMES` for
production accuracy.

## 2. Run the sensor

```bash
export NIDS_INGEST_URL="https://<your-app>/api/public/ingest"
export NIDS_INGEST_TOKEN="<the NIDS_INGEST_TOKEN secret from the app>"
sudo -E python nids_agent.py -i eth0
```

Offline analysis of a Wireshark capture:

```bash
python nids_agent.py --pcap capture.pcap
```

Useful env vars: `NIDS_SENSOR_NAME`, `NIDS_MODEL_PATH`, `NIDS_DB_PATH`.

## Detection coverage

| Signal | Detected as |
| --- | --- |
| Many distinct destination ports, high SYN ratio | Port Scan |
| Very high packets/sec, tiny packets, single target | DoS / DDoS |
| Repeated bursts to 22/21/3389/3306/... | Brute Force |
| High RST ratio or auth-port probing | Suspicious Connection |
| Model flags attack without a matching rule | Anomalous Traffic |

Risk level combines the attack class, model confidence and packet rate:
`low → medium → high → critical`.

## Local Streamlit view (optional)

```bash
streamlit run streamlit_app.py
```

Reads the same `nids_events.db` written by the agent — handy when the host has
no internet access to reach the hosted dashboard.
