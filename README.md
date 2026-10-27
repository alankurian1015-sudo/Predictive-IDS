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
-- Feature importance: built-in importances and SHAP (Kernel SHAP by default, Tree SHAP as a fast cross-check),
  computed on attack flows only against a benign background, with a time limit and a Stop button
- Feeds: replay, watched CSV file (`live/`), uploaded CSV; alert export to CSV

## Architecture

```
replay / watched CSV / upload  ->  backend/detector.py  ->  alert buffer  ->  FastAPI (backend/server.py)  ->  HTML/JS page
                                   (classifier +                               backend/extras.py
                                    autoencoder)                               (incidents, SHAP)
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
│   ├── detector.py              # ML model loading & prediction
│   ├── feed.py                  # CSV parsing & alignment
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
├── tests/                       # All test files
│   ├── __init__.py
│   ├── testapp.py
│   ├── test_watch.py
│   └── time_check.py
│
├── models/                      # (gitignored) ML model artifacts
├── data/                        # (gitignored) Stream data
└── live/                        # (gitignored) Watched CSV feed
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
- **Upload flows CSV**: up to 150 MB and 200,000 rows. Columns are matched to the model's features by
  name; missing features stop the feed and are listed on screen.
- **Incidents** merge alerts per (source IP, family). Feeds without IP addresses show "unknown" as the source.
- **Feature importance**: built-in importances are instant; SHAP runs in the background on attack flows only.

## API

| Endpoint | Purpose |
|---|---|
| GET /api/state | Everything the page renders |
| GET /api/incidents, POST /api/incident/status | Incident list and triage |
| GET /api/explain, POST /api/explain/run | Feature importance, SHAP job |
| GET /api/health | Precision/recall, confusion matrix, calibration |
| GET /api/alert/{id}, POST /api/status | One alert, alert triage |
| POST /api/control, /api/jump, /api/clear, /api/fastforward, /api/upload | Controls |
| GET /api/export | Alerts as CSV |

## Limitations (please read)

- Replay and uploaded data are recorded flows. Real packet capture needs a flow extractor whose features
  match the training data; this has not been validated.
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
| "Model features missing" | The file's columns differ from the model's training features |
| SHAP panel says not installed | `pip install shap` |

## Data and citation

CIC-IDS2017: Sharafaldin, Lashkari, Ghorbani, "Toward Generating a New Intrusion Detection Dataset and
Intrusion Traffic Characterization", ICISSP 2018. Dataset by the Canadian Institute for Cybersecurity, UNB.