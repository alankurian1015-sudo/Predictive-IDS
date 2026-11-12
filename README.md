# Predictive Intrusion Detection System (PIDS): Monitoring Dashboard

A browser dashboard that scores network flows with a trained classifier (and an optional autoencoder),
flags each flow as Genuine, Suspicious or Malicious, groups alerts into incidents, forecasts the
attack share for the next minute, and lets an analyst triage alerts.

> Replay of labelled CIC-IDS2017 flows by default. The class mix in the replay file is a demo
> sample (attacks over-represented), not real-world traffic proportions.

## Features

- Live feed with a verdict per flow, KPIs, traffic and attack-type charts, top source IPs, targeted ports,
  score histogram
- Alert queue ordered by severity, with Acknowledge / False positive / Escalate and an investigate drawer
- Incidents & Predictive Kill-Chain: alerts from the same source and attack family within 60 s are merged; adversary progression across MITRE ATT&CK stages is modeled to forecast the next likely attack vector, probability, time window, and proactive countermeasure
- Predictive outlook: Holt exponential smoothing on the attack share, risk level, early-warning banner
- Model health against ground truth (precision/recall, confusion matrix, calibration)
- Feature importance: built-in importances and SHAP (Kernel SHAP by default, Tree SHAP as a fast cross-check),
  computed on attack flows only against a benign background, with a time limit and a Stop button
- Feeds: replay stream, watched CSV file (`live/`), uploaded CSV flows, or raw PCAP/PCAPNG network packet captures (automatic 5-tuple flow aggregation and CICFlowMeter metric extraction); alert export to CSV

## Architecture

```
replay / watched CSV ──────┐
                           ├─► backend/detector.py ──► alert buffer ──► FastAPI (server.py) ──► HTML/JS Dashboard
uploaded CSV (validated) ──┤   (Random Forest /                         extras.py (incidents,
                           │    XGBoost + AE)                           SHAP explanations)
uploaded .pcap / .pcapng ──┘
         │
         ▼
backend/pcap.py (native packet dissector, 5-tuple flow aggregation, 80+ CICFlowMeter metrics)
```

## Project Structure

```
Predictive-IDS/
├── README.md
├── requirements.txt
├── .gitignore
│
├── backend/                     # All Python backend code
│   ├── __init__.py
│   ├── server.py                # FastAPI app (main entry point)
│   ├── common.py                # Shared labels, severity rules
│   ├── detector.py              # ML model loading & prediction pipeline
│   ├── feed.py                  # CSV parsing, validation & feature alignment
│   ├── pcap.py                  # PCAP/PCAPNG dissector & CICFlowMeter flow engine
│   ├── forecast.py              # Holt smoothing & risk levels
│   ├── stream.py                # Parquet replay stream
│   └── extras.py                # Incidents & SHAP router
│
├── frontend/                    # Static web assets
│   ├── index.html
│   ├── style.css
│   ├── app.js
│   └── extras.js
│
├── scripts/                     # Batch files & utility scripts
│   ├── setup.bat
│   ├── run.bat
│   ├── check.bat
│   ├── simulate_feed.py
│   ├── check_setup.py
│   └── diagnose_xgb.py
│
├── tests/                       # Comprehensive test suites
│   ├── __init__.py
│   ├── test_csv_processing.py           # Unit tests for CSV validation & alignment
│   ├── test_pcap_processing.py          # Unit tests for PCAP/PCAPNG flow extraction
│   ├── test_upload_workflows_full.py    # Integration tests & edge cases (negative testing)
│   ├── testapp.py
│   ├── test_watch.py
│   └── time_check.py
│
├── models/                      # (gitignored) ML model artifacts
├── data/                        # (gitignored) Stream data
└── live/                        # (gitignored) Watched CSV feed & test captures
```

## Quick start (Windows)

1. Install Python 3.10 to 3.12.
2. Double-click `scripts/setup.bat` (first time only).
3. Put your files in place (see below), then double-click `scripts/check.bat`.
4. Double-click `scripts/run.bat`. Open http://localhost:8765 if it does not open by itself.

Manual start: activate `.venv`, then `uvicorn backend.server:app --port 8765`.

## Files you must provide

```
models/  feature_cols.joblib, label_encoder.joblib, a classifier (rf.joblib or xgb.json),
         optional: preprocessor.joblib, autoencoder.keras, ae_threshold.joblib,
                   ae_feature_cols.joblib, ae_preprocessor.joblib
data/    test_stream.parquet (flows with IPs, ports, Timestamp, Label and the feature columns),
         stream_meta.json ({"held_out": true|false})
live/    flows.csv (optional, for the watched-file feed)
```

They are exported from the training notebook. Install the same scikit-learn version that saved them.

## Using it

- **Replay**: pick a day (2017-07-04 to 07 have attacks) and use *Fast-forward 2 min* to fill the forecast history.
- **Watch flows file**: point it at a CSV inside `live/` that another program keeps appending to.
- **Upload flows CSV or PCAP/PCAPNG captures**:
  - **CSV Uploads**: up to 150 MB and 200,000 rows. Columns are matched to the model's 65 features by name, supporting abbreviations/aliases (`Tot Fwd Pkts` $\rightarrow$ `Total Fwd Packets`). Invalid values, NaNs, and infinities are safely cleaned; missing required features are clearly reported.
  - **PCAP / PCAPNG Uploads**: Raw packet captures (`.pcap` or `.pcapng` saved directly from Wireshark or `tcpdump`). The built-in engine automatically reconstructs bidirectional 5-tuple conversations and calculates all 65 flow statistics required by the models.
- **Incidents** merge alerts per (source IP, family). Feeds without IP addresses show "unknown" as the source.
- **Feature importance**: built-in importances are instant; SHAP runs in the background on attack flows only.

## PCAP & CSV Processing Engine

The application includes native file-processing pipelines decoupled for both the Random Forest and Autoencoder models:

1. **PCAP & PCAPNG Dissector (`backend/pcap.py`)**:
   - Supports Big-Endian and Little-Endian standard PCAPs as well as modern PCAPNG format (SHB, IDB, EPB).
   - Reconstructs bidirectional flows by `(Source IP, Destination IP, Source Port, Destination Port, Protocol)` with standard 120-second inactivity timeouts.
   - Computes 80+ network flow features matching the official CICFlowMeter specification (durations, forward/backward packet counts and byte sizes, inter-arrival times, TCP flags, active/idle periods).
   - Validates captures against zero-flow packets (e.g. non-transport ARP or ICMP-only captures).
2. **CSV Validation Pipeline (`backend/feed.py`)**:
   - Validates CSV structure, ensures non-empty data rows, and cleans numeric infinities.
   - Maps feature column aliases and imputes missing display metadata (`Source IP`, `Timestamp`, etc.).
3. **Independent Dual-Model Pipeline (`backend/detector.py`)**:
   - **Random Forest**: Exact 65 features in their original training order, evaluated without scaling.
   - **Autoencoder**: Exact 65 features scaled via `ae_preprocessor.joblib` (`StandardScaler`), evaluated against the calibrated reconstruction MSE threshold $2.106967 \times 10^{13}$.

## Authentication & Default Accounts

The dashboard is secured with role-based access control (RBAC). Seed default accounts using `python scripts/seed_users.py`.

| Account | Username | Default Password | Role | Permissions |
| :--- | :--- | :--- | :--- | :--- |
| **Admin** | `admin` | `admin123` | `admin` | Full control: Ingestion feeds, PCAP uploads, simulation rates, user management, and triage. |
| **Analyst** | `analyst` | `analyst123` | `analyst` | Threat investigation: Live Situation Room, Incident Triage, SHAP calculations, and CSV export. |
| **Auditor** | `viewer` | `viewer123` | `viewer` | Read-only access: Situation Room metrics, attack forecasts, and model health. (Triage actions disabled). |

## Multi-Page SOC Portal Structure

The dashboard features tabbed view routing with uninterrupted background WebSocket streaming:
1. **📊 Live Situation Room (`#/live`)**: Real-time traffic KPIs, latest flows table, traffic & port charts, and 60-second Holt forecast.
2. **🚨 Incidents & Alert Triage (`#/incidents`)**: MITRE ATT&CK predictive kill-chain matrix, grouped incidents, and actionable alert queue with investigation drawer.
3. **🧠 Model Health & XAI (`#/models`)**: Precision/recall breakdown, confusion matrix, calibration curve, and interactive SHAP explainability.
4. **⚙️ Ingestion & Replay (`#/ingestion`)** *(Admin only)*: Traffic source selection, replay jump, simulation speed, and PCAP/CSV upload.
5. **👥 User Management (`#/users`)** *(Admin only)*: Create and manage SOC accounts and assign roles.

## API

| Endpoint | Method | Role Required | Purpose |
|---|---|---|---|
| `/api/auth/login` | POST | Public | Authenticates credentials and issues HttpOnly JWT cookie |
| `/api/auth/logout` | POST | Public | Clears session cookie |
| `/api/auth/me` | GET | Any Authenticated | Retrieves current user session profile |
| `/api/auth/users` | GET / POST | `admin` | List or register SOC user accounts |
| `/api/auth/users/{id}` | DELETE | `admin` | Deactivates a user account |
| `/api/state` | GET | Any Authenticated | Everything the page renders |
| `/api/incidents` | GET | Any Authenticated | Grouped incidents and MITRE kill-chain data |
| `/api/incident/status` | POST | `admin`, `analyst` | Triage whole incident |
| `/api/status` | POST | `admin`, `analyst` | Triage alert (Acknowledge, Escalate, False positive) |
| `/api/explain` | GET | Any Authenticated | Feature importance and SHAP status |
| `/api/explain/run` | POST | `admin`, `analyst` | Launch SHAP background calculation |
| `/api/health` | GET | Any Authenticated | Precision/recall, confusion matrix, calibration |
| `/api/alert/{id}` | GET | Any Authenticated | Alert investigation details |
| `/api/control`, `/api/jump`, `/api/clear`, `/api/fastforward` | POST | `admin` | Ingestion and playback controls |
| `/api/upload` | POST | `admin` | Upload CSV or raw PCAP/PCAPNG capture |
| `/ws` | WebSocket | Any Authenticated | Real-time live feed push stream (authenticated on handshake) |
| GET /api/pcap/info | CICFlowMeter environment and CLI compatibility status |
| GET /api/export | Alerts as CSV |

## Testing

Run the full automated test suite (34 unit and integration tests):
```powershell
$env:PYTHONPATH="."
.\.venv\Scripts\pytest.exe tests/ -v
```
- `tests/test_csv_processing.py`: CSV validation, feature alignment, alias resolution, and NaN cleaning.
- `tests/test_pcap_processing.py`: PCAP and PCAPNG parsing, flow extraction, and CICFlowMeter metrics.
- `tests/test_upload_workflows_full.py`: End-to-end upload workflows and negative edge cases (empty files, truncated PCAPs, corrupted magic bytes, non-transport packets).

## Limitations (please read)

- Model-health numbers are optimistic when replay rows may have been seen in training (the page says so).
- The forecast follows the replay's own trajectory; it shows the mechanism, not proven predictive power.
- The autoencoder was a weak anomaly detector on this data (AUC about 0.6).
- SHAP importance is global, from attack flows only, class-balanced. It shows magnitude, not direction.
  Per-alert explanations are not implemented.
- No login: run on localhost only. Do not expose the port to a network.

## Troubleshooting

| Problem | Fix |
|---|---|
| `[WinError 10013]` on start | Change `PORT` in `scripts/run.bat` |
| Blank page, red console errors | Press Ctrl+F5; check `frontend/` has index.html, style.css, app.js, extras.js |
| "Model features missing" | The uploaded CSV columns differ from the model's 65 training features |
| "No valid IPv4 TCP/UDP packets found" | The uploaded PCAP contains only non-transport traffic (e.g. ARP or ICMP) |
| SHAP panel says not installed | `pip install shap` |

## Data and citation

CIC-IDS2017: Sharafaldin, Lashkari, Ghorbani, "Toward Generating a New Intrusion Detection Dataset and
Intrusion Traffic Characterization", ICISSP 2018. Dataset by the Canadian Institute for Cybersecurity, UNB.
