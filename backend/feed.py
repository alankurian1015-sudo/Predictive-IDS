"""feed.py: turns incoming flow records (CSV rows) into rows the detector can score."""
import re
from io import StringIO
from pathlib import Path

import numpy as np
import pandas as pd

DISPLAY = ["Timestamp", "Source IP", "Destination IP", "Destination Port", "Label"]
EXTRA = ["Flow ID", "Source Port", "Protocol"]

# Abbreviated extractor names -> the names used in the CIC-IDS2017 CSVs
_ABBR = {
    "Src IP": "Source IP", "Dst IP": "Destination IP",
    "Src Port": "Source Port", "Dst Port": "Destination Port",
    "Tot Fwd Pkts": "Total Fwd Packets", "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Total Length of Fwd Packets", "TotLen Bwd Pkts": "Total Length of Bwd Packets",
    "Fwd Pkt Len Max": "Fwd Packet Length Max", "Fwd Pkt Len Min": "Fwd Packet Length Min",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean", "Fwd Pkt Len Std": "Fwd Packet Length Std",
    "Bwd Pkt Len Max": "Bwd Packet Length Max", "Bwd Pkt Len Min": "Bwd Packet Length Min",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean", "Bwd Pkt Len Std": "Bwd Packet Length Std",
    "Flow Byts/s": "Flow Bytes/s", "Flow Pkts/s": "Flow Packets/s",
    "Fwd IAT Tot": "Fwd IAT Total", "Bwd IAT Tot": "Bwd IAT Total",
    "Fwd Header Len": "Fwd Header Length", "Bwd Header Len": "Bwd Header Length",
    "Fwd Pkts/s": "Fwd Packets/s", "Bwd Pkts/s": "Bwd Packets/s",
    "Pkt Len Min": "Min Packet Length", "Pkt Len Max": "Max Packet Length",
    "Pkt Len Mean": "Packet Length Mean", "Pkt Len Std": "Packet Length Std",
    "Pkt Len Var": "Packet Length Variance",
    "FIN Flag Cnt": "FIN Flag Count", "SYN Flag Cnt": "SYN Flag Count", "RST Flag Cnt": "RST Flag Count",
    "PSH Flag Cnt": "PSH Flag Count", "ACK Flag Cnt": "ACK Flag Count", "URG Flag Cnt": "URG Flag Count",
    "ECE Flag Cnt": "ECE Flag Count",
    "Pkt Size Avg": "Average Packet Size",
    "Fwd Seg Size Avg": "Avg Fwd Segment Size", "Bwd Seg Size Avg": "Avg Bwd Segment Size",
    "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk", "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk",
    "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate",
    "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk", "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk",
    "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate",
    "Subflow Fwd Pkts": "Subflow Fwd Packets", "Subflow Fwd Byts": "Subflow Fwd Bytes",
    "Subflow Bwd Pkts": "Subflow Bwd Packets", "Subflow Bwd Byts": "Subflow Bwd Bytes",
    "Init Fwd Win Byts": "Init_Win_bytes_forward", "Init Bwd Win Byts": "Init_Win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_fwd", "Fwd Seg Size Min": "min_seg_size_forward",
}


def _key(s):
    return re.sub(r"[^a-z0-9]+", "", str(s).lower())


def align(raw, feats):
    """Rename incoming columns to the dataset's names. Returns (frame, missing_feature_names)."""
    df = raw.copy()
    df.columns = [str(c).strip() for c in df.columns]
    target = {_key(c): c for c in list(feats) + DISPLAY + EXTRA}
    abbr = {_key(k): v for k, v in _ABBR.items()}
    rename = {}
    for c in df.columns:
        k = _key(c)
        if k in target:
            rename[c] = target[k]
        elif k in abbr:
            rename[c] = abbr[k]
    df = df.rename(columns=rename)
    df = df.loc[:, ~df.columns.duplicated()]
    missing = [c for c in feats if c not in df.columns]
    return df, missing


def finish(df, feats):
    """Clean numbers and fill display columns, so the detector always gets what it needs."""
    df = df.copy()
    for c in feats:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=feats).reset_index(drop=True)

    if "Destination Port" not in df.columns:
        df["Destination Port"] = 0
    df["Destination Port"] = pd.to_numeric(df["Destination Port"], errors="coerce").fillna(0)

    if "Timestamp" in df.columns:
        ts = pd.to_datetime(df["Timestamp"], errors="coerce", dayfirst=True)
    else:
        ts = pd.Series(pd.NaT, index=df.index)
    df["Timestamp"] = ts.fillna(pd.Timestamp.now())

    for c, default in [("Source IP", "unknown"), ("Destination IP", "unknown"), ("Label", "(unlabelled)")]:
        if c not in df.columns:
            df[c] = default
    return df


class CsvTail:
    """Reads only the NEW rows of a CSV that another program keeps appending to."""

    MAX_BYTES = 5_000_000        # at most ~5 MB per read, so a huge file is consumed a little at a time

    def __init__(self, path):
        self.raw_path = path
        self.offset = 0
        self.header = None

    def read_new(self):
        p = Path(self.raw_path)
        if not p.exists():
            return None
        if p.stat().st_size < self.offset:                 # file was replaced or truncated
            self.offset, self.header = 0, None
        with open(p, "rb") as f:
            if self.header is None:
                line = f.readline()
                if not line.endswith(b"\n"):
                    return None
                self.header = [h.strip().strip('"') for h in line.decode("utf-8-sig", "ignore").strip().split(",")]
                self.offset = f.tell()
            f.seek(self.offset)
            data = f.read(self.MAX_BYTES)
        end = data.rfind(b"\n")                            # only complete lines
        if end < 0:
            return None
        self.offset += end + 1
        text = data[: end + 1].decode("utf-8", "ignore")
        return pd.read_csv(StringIO(text), names=self.header, header=None, on_bad_lines="skip")