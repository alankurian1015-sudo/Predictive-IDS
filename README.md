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
- Incidents: alerts from the same source and attack family within 60 s are merged into one row
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

## API

| Endpoint | Purpose |
|---|---|
| GET /api/state | Everything the page renders |
| GET /api/incidents, POST /api/incident/status | Incident list and triage |
| GET /api/explain, POST /api/explain/run | Feature importance, SHAP job |
| GET /api/health | Precision/recall, confusion matrix, calibration |
| GET /api/alert/{id}, POST /api/status | One alert, alert triage |
| POST /api/control, /api/jump, /api/clear, /api/fastforward | Playback and state controls |
| POST /api/upload | Upload CSV or raw PCAP/PCAPNG capture (auto-detected) |
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
