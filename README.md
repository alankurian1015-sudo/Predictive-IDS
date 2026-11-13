# Predictive Intrusion Detection System (PIDS)
### Enterprise Network Telemetry, Anomaly Scoring & Threat Correlation Platform

A high-performance Security Operations Center (SOC) dashboard that evaluates network flows in real time using a multi-class Random Forest classifier and an optional Autoencoder anomaly detector. The platform classifies flows into fine-grained attack signatures, correlates alerts into multi-stage security incidents, maps adversary progression against the MITRE ATT&CK framework, forecasts short-horizon attack trends, and enforces Role-Based Access Control (RBAC).

---

## Key Capabilities

- **Real-Time Telemetry & Scoring**: Evaluates live streaming flows against 65 network features; outputs classification verdicts, confidence intervals, anomaly reconstruction scores, and Shannon uncertainty estimates.
- **Role-Based Access Control (RBAC)**: Secure multi-user SQLite identity store with `bcrypt` salt hashing, JWT session cookies (`HttpOnly`, `SameSite=Lax`), and WebSocket upgrade authentication.
- **Multi-View Operations Console**:
  - **Live Threat Feed (`#/live`)**: Real-time KPI metrics, streaming flow telemetry table, hostile IP ranking, targeted ports distribution, score histogram, and 60-second Holt linear exponential forecast.
  - **Incidents & Triage (`#/incidents`)**: MITRE ATT&CK 5-stage progression pipeline, multi-flow correlation clusters, and alert triage queue with slide-out deep inspection drawer.
  - **Model Health & XAI (`#/models`)**: Precision, recall, and support matrices; confusion matrix heatmap; calibration curves; and on-demand Kernel/Tree SHAP explainability.
  - **Data Ingestion (`#/ingestion`)** *(Admin only)*: Switch between CIC-IDS2017 replay scenarios, live directory watchers, and ad-hoc PCAP/PCAPNG/CSV packet uploads.
  - **Access Control (`#/users`)** *(Admin only)*: Provision operator accounts, manage role permissions, inspect last active timestamps, and deactivate users.
- **Adversary Progression Forecasting**: Correlates alerts across 5 kill-chain stages (Reconnaissance, Credential Access, Web Exploitation, Lateral Movement/C2, Exfiltration/Impact) to project the adversary's next target vector and proactive countermeasure.
- **Dual-Model Scoring Architecture**: Decoupled evaluation pipelines for supervised multi-class classification and unsupervised autoencoder reconstruction error.
- **High-Throughput Packet Dissector**: Native PCAP and PCAPNG parser that reconstructs bidirectional 5-tuple conversations and computes 80+ CICFlowMeter network flow metrics.

---

## System Architecture

```
+─────────────────────────────────────────────────────────────────────────────+
|                             INGESTION SOURCES                               |
|  Replay Engine (Parquet) │ Live File Watcher │ PCAP / PCAPNG / CSV Uploads  |
+─────────────────────────────────────────────────────────────────────────────+
                                      │
                                      ▼
+─────────────────────────────────────────────────────────────────────────────+
|                         FEATURE PROCESSING PIPELINE                         |
|  - pcap.py: 5-tuple conversation tracking & 80+ CICFlowMeter metrics        |
|  - feed.py: 65-feature alignment, column aliasing & numerical sanitization  |
+─────────────────────────────────────────────────────────────────────────────+
                                      │
                                      ▼
+─────────────────────────────────────────────────────────────────────────────+
|                            DETECTION ENGINE (ML)                            |
|  - detector.py: Random Forest Classifier (65 features, unscaled)            |
|  - Autoencoder Anomaly Detector (StandardScaler, reconstruction threshold)   |
|  - forecast.py: Holt linear exponential smoothing (60s risk projection)     |
+─────────────────────────────────────────────────────────────────────────────+
                                      │
                                      ▼
+─────────────────────────────────────────────────────────────────────────────+
|                     APPLICATION & PERSISTENCE LAYER                         |
|  - FastAPI (backend/server.py): REST endpoints & WebSockets (/ws)           |
|  - RBAC & Sessions (backend/auth.py, db.py): SQLite, bcrypt, JWT cookies    |
|  - Incidents & XAI (backend/extras.py): Kill-chain correlation & SHAP       |
+─────────────────────────────────────────────────────────────────────────────+
                                      │
                                      ▼
+─────────────────────────────────────────────────────────────────────────────+
|                          SOC OPERATIONS FRONTEND                            |
|  - Fixed Navigation Rail (Detection, Intelligence, Administration)          |
|  - Real-Time Context HUD: Live scoring switch, min-conf slider, filters     |
|  - High-density data grids, Chart.js visualizations, slide-out drawer       |
|  - Zero-Trust Gateway (frontend/login.html): Operator credential management |
+─────────────────────────────────────────────────────────────────────────────+
```

---

## Directory Structure

```
Predictive-IDS/
├── README.md
├── requirements.txt
├── .gitignore
│
├── backend/                     # Python backend service
│   ├── __init__.py
│   ├── server.py                # FastAPI application entry point
│   ├── auth.py                  # JWT authentication, password hashing & RBAC
│   ├── db.py                    # SQLite persistence layer for user accounts
│   ├── detector.py              # Dual-model ML inference pipeline
│   ├── common.py                # Threat taxonomy, label mapping & severity rules
│   ├── feed.py                  # CSV parsing, feature validation & alignment
│   ├── pcap.py                  # PCAP/PCAPNG packet dissector & flow engine
│   ├── forecast.py              # Holt exponential smoothing & risk evaluation
│   ├── stream.py                # Replay stream state & ring buffer
│   └── extras.py                # Incidents, MITRE ATT&CK correlation & SHAP router
│
├── frontend/                    # Single-Page SOC application assets
│   ├── index.html               # Main application shell & navigation
│   ├── login.html               # Zero-trust operator authentication portal
│   ├── style.css                # Enterprise design system (dark/light themes)
│   ├── app.js                   # Application state, chart controls & UI routing
│   ├── extras.js                # Kill-chain visualizer, incident queue & XAI
│   └── chart.umd.min.js         # Local Chart.js fallback
│
├── scripts/                     # Operational utilities & automation
│   ├── setup.bat                # Environment bootstrap script
│   ├── run.bat                  # Service launcher
│   ├── check.bat                # Environment diagnostic script
│   ├── seed_users.py            # Pre-seeds default SOC operator accounts
│   ├── simulate_feed.py         # Mock telemetry generator for testing
│   ├── check_setup.py           # Dependency verification script
│   └── diagnose_xgb.py          # Model sanity checker
│
├── tests/                       # Comprehensive test suites (54 passing tests)
│   ├── __init__.py
│   ├── test_auth.py             # Authentication, RBAC, session & user lifecycle
│   ├── testapp.py               # Core API endpoints, state & control flows
│   ├── test_csv_processing.py   # CSV parsing, feature alignment & alias resolution
│   ├── test_pcap_processing.py  # PCAP/PCAPNG parsing & CICFlowMeter flow extraction
│   ├── test_upload_workflows_full.py # Negative testing & upload edge cases
│   └── test_watch.py            # Directory watcher verification
│
├── models/                      # ML model artifacts (gitignored)
├── data/                        # Replay datasets & SQLite auth DB (gitignored)
└── live/                        # Monitored directory for live packet feeds (gitignored)
```

---

## Authentication & Default Operator Accounts

The system implements Role-Based Access Control (RBAC). Seed default credentials using:
```bash
python scripts/seed_users.py
```

| Role | Username | Default Password | Access Permissions |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin` | `admin123` | Full control: File uploads, packet ingestion, replay speed, user provisioning, and alert triage. |
| **SOC Analyst** | `analyst` | `analyst123` | Threat analysis: Live Feed, Incident Triage, alert triage (Ack/FP/Escalate), SHAP compute, and CSV export. |
| **Auditor / Viewer**| `viewer` | `viewer123` | Read-only observation: Situation Room metrics, flow logs, model health, and calibration. Triage actions restricted. |

---

## Getting Started

### Prerequisites
- Python 3.10 to 3.12 (64-bit)
- Windows, Linux, or macOS

### 1. Installation
Clone the repository and install dependencies:
```bash
git clone https://github.com/alankurian1015-sudo/Predictive-IDS.git
cd Predictive-IDS

python -m venv .venv
# Windows:
.\.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

### 2. Required Model & Data Files
Ensure the following artifacts are placed in the respective folders:
```
models/
  ├── feature_cols.joblib        # Ordered feature names for inference
  ├── label_encoder.joblib       # Attack class encoder
  ├── rf.joblib                  # Trained Random Forest classifier
  ├── preprocessor.joblib        # (Optional) Feature scaler
  ├── autoencoder.keras          # (Optional) Trained Autoencoder model
  ├── ae_threshold.joblib        # (Optional) Anomaly reconstruction threshold
  ├── ae_feature_cols.joblib     # (Optional) Autoencoder feature list
  └── ae_preprocessor.joblib     # (Optional) Autoencoder StandardScaler

data/
  ├── test_stream.parquet        # Labelled evaluation flow dataset
  └── stream_meta.json           # Metadata config ({"held_out": true|false})
```

### 3. Initialize Operator Accounts
```bash
python scripts/seed_users.py
```

### 4. Run the Service
```bash
uvicorn backend.server:app --port 8765 --reload
```
Navigate to `http://localhost:8765` in your browser. You will be directed to the authentication portal (`login.html`).

---

## Multi-Page Console Views

Tabbed client-side routing preserves active background WebSocket telemetry across view switches:

1. **Live Threat Feed (`#/live`)**
   - High-density KPI summary: Overall Attack Rate, Open Critical Alarms, Escalated Incidents, Average Confidence, and Anomalies.
   - Streaming flows table with live verdict indicators (`Attack` / `Benign`), millisecond timestamps, confidence values, and 5-tuple routing.
   - Dynamic charts: Traffic by threat family area chart, attack class doughnut, top hostile source IPs, targeted destination ports, and score distribution histogram.
   - Predictive 60s outlook: Real-time Holt linear exponential smoothing against observed attack proportions with risk-level alerting.

2. **Incidents & Triage (`#/incidents`)**
   - **MITRE ATT&CK Pipeline**: 5 stages visualized horizontally with active threat flow counts and hazard indicators.
   - **Correlated Incidents**: Merges alerts originating from the same source IP and attack family within 60-second sliding windows. Displays target footprint, duration, and projected next vector.
   - **Alert Queue**: Prioritized alarm feed with action triggers (`Ack`, `FP`, `Escalate`) and investigation drawer integration.

3. **Model Health & XAI (`#/models`)**
   - **Global Feature Importance**: Top contributing features rendered via calibrated horizontal distribution bars.
   - **Interactive SHAP Explainer**: Kernel SHAP and Tree SHAP execution engine with sample size budget, time limit guardrails, class selector, and cancellation controls.
   - **Validation Metrics**: Precision, recall, and support per attack class against ground truth.
   - **Confusion Matrix & Calibration**: Intensity-shaded confusion matrix and bin-accuracy calibration chart.

4. **Data Ingestion (`#/ingestion`)** *(Admin only)*
   - Telemetry source selector: Historical Replay, Live Directory Watcher (`live/flows.csv`), or Packet Capture Ingestion.
   - Packet capture upload dropzone supporting `.pcap`, `.pcapng`, and `.csv` files up to 150 MB.
   - Scoring rate slider (1 to 500 events per 2-second tick) and scenario day jump controls.

5. **Access Control (`#/users`)** *(Admin only)*
   - Operator account directory with user IDs, roles, last login timestamps, and account deactivation actions.
   - User provisioning form with credential validation and role tier assignment.

---

## API Reference

### Authentication & IAM
| Method | Endpoint | Access Level | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/login` | Public | Validates credentials; sets `HttpOnly` JWT session cookie. |
| `POST` | `/api/auth/logout` | Authenticated | Invalidates session and clears cookie. |
| `GET` | `/api/auth/me` | Authenticated | Returns authenticated user profile and assigned role. |
| `GET` | `/api/auth/users` | Admin | Lists all provisioned operator accounts. |
| `POST` | `/api/auth/users` | Admin | Provisions a new user account with role. |
| `DELETE` | `/api/auth/users/{id}` | Admin | Deactivates an operator account. |

### Telemetry & Operations
| Method | Endpoint | Access Level | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/state` | Authenticated | Returns current telemetry snapshot, KPIs, feed, and charts. |
| `GET` | `/api/incidents` | Authenticated | Returns correlated incident clusters and MITRE ATT&CK summary. |
| `POST` | `/api/incident/status` | Analyst, Admin | Updates status for an entire incident cluster. |
| `POST` | `/api/status` | Analyst, Admin | Triages an individual alert (`Acknowledged`, `False positive`, `Escalated`). |
| `GET` | `/api/alert/{id}` | Authenticated | Fetches detailed flow parameters and top-3 class attributions. |
| `GET` | `/api/explain` | Authenticated | Retrieves global feature importances and active SHAP state. |
| `POST` | `/api/explain/run` | Analyst, Admin | Dispatches background SHAP attribution calculation. |
| `POST` | `/api/explain/cancel` | Analyst, Admin | Cancels active SHAP computation. |
| `GET` | `/api/health` | Authenticated | Retrieves precision/recall, confusion matrix, and calibration curve. |
| `GET` | `/api/export` | Authenticated | Exports filtered alert telemetry as CSV. |
| `WS` | `/ws` | Authenticated | Real-time push stream (validated via session cookie during handshake). |

### Ingestion Controls (Admin)
| Method | Endpoint | Access Level | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/control` | Admin | Configures live scoring state, scoring rate, and feed source. |
| `POST` | `/api/jump` | Admin | Jumps stream replay to a specific scenario day. |
| `POST` | `/api/fastforward` | Admin | Fast-forwards the replay buffer by 60 ticks (2 minutes). |
| `POST` | `/api/clear` | Admin | Flushes the active in-memory flow ring buffer. |
| `POST` | `/api/upload` | Admin | Ingests CSV flows or raw PCAP/PCAPNG network captures. |

---

## Verification & Testing

The project includes an automated test suite covering unit validation, packet extraction, integration workflows, negative test cases, and authentication lifecycle:

```powershell
.\.venv\Scripts\pytest -v
```

### Test Coverage Highlights (54 Passed)
- `tests/test_auth.py`: Login validation, password verification, 401 rejections, RBAC role-level restrictions, user creation and deactivation lifecycles, and logout flow.
- `tests/testapp.py`: Authenticated API fixtures, scoring pipeline, filter controls, alert triage status updates, fast-forwarding, and buffer clearance.
- `tests/test_csv_processing.py`: Header parsing, feature mapping, alias resolution (`Tot Fwd Pkts` $\rightarrow$ `Total Fwd Packets`), and NaN/infinite value sanitization.
- `tests/test_pcap_processing.py`: Big-endian and little-endian PCAP parsing, PCAPNG block dissection, 5-tuple conversation grouping, and 80+ CICFlowMeter feature calculations.
- `tests/test_upload_workflows_full.py`: Upload boundary testing (oversized payloads, corrupted packet headers, empty captures, truncated files, and non-transport packet handling).
- `tests/test_watch.py`: Live file watcher polling and change detection.

---

## Operational Considerations

1. **Replay vs. Production Traffic**: The included replay dataset over-represents attack traffic relative to standard production baselines to demonstrate triage and correlation mechanisms.
2. **Model Health Metrics**: Ground-truth validation metrics reflect replay evaluation data. When evaluating unlabelled live packet captures, validation metrics are marked unavailable.
3. **SHAP Execution Budget**: Kernel SHAP evaluates features against a background benign sample. For low-latency environments, use Tree SHAP or lower evaluation flow limits ($n=20$).
4. **Network Exposure**: Ensure production deployments place the FastAPI service behind a TLS reverse proxy (e.g., Nginx, Caddy, or Cloudflare Tunnel) with secure cookie flags enabled.

---

## Dataset Citation

The demonstration replay stream is derived from the **CIC-IDS2017** benchmark:
> Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*. Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP). Canadian Institute for Cybersecurity (CIC), University of New Brunswick.
