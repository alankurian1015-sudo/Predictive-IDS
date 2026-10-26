"""common.py: shared labels, families and severity rules.
Tolerant of older and newer callers, so file versions can't clash."""
import math
import re
from functools import lru_cache

import numpy as np

# Columns that identify a flow. Shown in the dashboard; the model's input columns
# come from models/feature_cols.joblib, not from this list.
ID_COLS = ["Flow ID", "Source IP", "Source Port", "Destination IP",
           "Destination Port", "Protocol", "Timestamp", "Label"]

SEV_ORDER = ["Critical", "High", "Medium", "Info"]
STATUSES = ("New", "Acknowledged", "False positive", "Escalated")   # one list for every endpoint

# Triage thresholds (uncalibrated starting points: tune them on labelled replay data)
BENIGN_SUSPECT_ATTACK = 0.3     # classifier says benign but P(attack) is above this -> Medium
ANOMALY_HIGH = 1.5              # autoencoder error / threshold above this counts as "high"
CRITICAL_MIN_CONF = 0.5
HIGH_MIN_CONF = 0.4

FAMILIES = ["Benign", "DoS/DDoS", "Recon", "Brute force", "Web attack",
            "Botnet", "Infiltration", "Exploit", "Other"]


def clip10(X):
    """Kept only so joblib can unpickle preprocessors that used it. Harmless if unused."""
    return np.clip(X, -10, 10)


@lru_cache(maxsize=4096)        # labels come from a tiny set, so this removes the regex from the hot path
def norm_label(s):
    """'Web Attack � Brute Force' and 'Web Attack - Brute Force' -> 'web attack brute force'."""
    return re.sub(r"[^a-z0-9]+", " ", str(s).lower()).strip()


@lru_cache(maxsize=4096)
def family_of(label):
    """Group the 15 CIC-IDS2017 labels into families (keyword-based, encoding-proof)."""
    l = norm_label(label)
    if l == "benign":
        return "Benign"
    if "web attack" in l:
        return "Web attack"
    if "ddos" in l or l.startswith("dos"):
        return "DoS/DDoS"
    if "portscan" in l or "port scan" in l:
        return "Recon"
    if "patator" in l:
        return "Brute force"
    if l == "bot":
        return "Botnet"
    if "infiltration" in l:
        return "Infiltration"
    if "heartbleed" in l:
        return "Exploit"
    return "Other"


# ---- legacy names, so older copies of other files that import them still work ----
_LABELS = ["BENIGN", "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest",
           "DoS slowloris", "FTP-Patator", "Heartbleed", "Infiltration", "PortScan",
           "SSH-Patator", "Web Attack - Brute Force", "Web Attack - Sql Injection",
           "Web Attack - XSS"]
FAMILY = {l: family_of(l) for l in _LABELS}
CRITICAL = {l for l in _LABELS
            if family_of(l) in ("Infiltration", "Exploit", "Botnet") or "sql" in norm_label(l)}
HIGH = {l for l in _LABELS if family_of(l) in ("DoS/DDoS", "Brute force", "Web attack")} - CRITICAL


def _num(x, default=None):
    """Float, or `default` when x is None / NaN / not a number."""
    try:
        x = float(x)
    except (TypeError, ValueError):
        return default
    return default if math.isnan(x) else x


def severity(predicted, confidence=1.0, attack_score=0.0, anomaly=None, *_extra, **_extra_kw):
    """Triage level for one alert.

    attack_score = 1 - P(BENIGN)                         (from XGBoost)
    anomaly      = autoencoder error / threshold, or None/NaN when there is no autoencoder
    Works with 2, 3 or 4 positional arguments; extra arguments are ignored.
    """
    fam = family_of(predicted)
    conf = _num(confidence, 0.0)
    atk = _num(attack_score, 0.0)
    anom = _num(anomaly)
    anom_high = anom is not None and anom > ANOMALY_HIGH

    if fam == "Benign":
        # classifier says benign, but another signal disagrees -> worth a look
        return "Medium" if (atk > BENIGN_SUSPECT_ATTACK or anom_high) else "Info"
    if fam in ("Infiltration", "Exploit", "Botnet") or "sql" in norm_label(predicted):
        return "Critical" if conf > CRITICAL_MIN_CONF else "High"
    if fam in ("DoS/DDoS", "Brute force", "Web attack") and conf >= HIGH_MIN_CONF:
        return "High"
    return "High" if anom_high else "Medium"


if __name__ == "__main__":
    # Self-test: run  `python common.py`  to confirm every call style works.
    print(severity("DDoS", 0.99))                           # 2 args
    print(severity("DDoS", 0.99, 0.99))                     # 3 args
    print(severity("DDoS", 0.99, 0.99, float("nan")))       # 4 args, NaN anomaly (no autoencoder)
    print(severity("Heartbleed", 0.9, 0.9, 2.0, "extra"))   # extra args are ignored
    print(severity("BENIGN", 0.8, 0.1, None))
    print(family_of("Web Attack � XSS"), "|", family_of("DoS Hulk"), "|", family_of("PortScan"))
    print("common.py OK")