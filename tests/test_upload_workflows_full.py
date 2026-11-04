"""tests/test_upload_workflows_full.py: Comprehensive integration testing of CSV and PCAP/PCAPNG
upload workflows through the Predictive-IDS application.

Verifies:
- Model input dimensions and original feature ordering (Random Forest & Autoencoder)
- Preprocessing pipelines (reusing existing StandardScaler and threshold)
- Full prediction outputs (predicted, confidence, attack_score, anomaly_score, verdict, severity)
- Invalid CSV handling (empty, malformed, 0 rows, non-numeric)
- Missing features detection and reporting
- Corrupted PCAP/PCAPNG handling (empty, truncated, invalid magic)
- PCAP with no extractable flows (ARP-only, ICMP-only)
- Live server state updates (KPIs, feed, alert queue)
"""
import asyncio
import io
import socket
import struct

import joblib
import numpy as np
import pandas as pd
import pytest
from fastapi import UploadFile

from backend.detector import Detector
from backend.feed import validate_and_preprocess_csv
from backend.pcap import is_pcap_data, process_pcap_to_flows, verify_cicflowmeter
from backend.server import app, det, FEATS, S, state, step_locked, upload


# =====================================================================
# Fixtures & Helpers
# =====================================================================

@pytest.fixture(autouse=True)
def reset_server_state():
    """Ensure clean alert buffer and backlog before each test."""
    S["alerts"] = pd.DataFrame()
    S["backlog"].clear()
    S["next_id"] = 0
    S["error"] = ""
    S["fault"] = ""
    S["version"] = 0
    S["source"] = "replay"
    yield


@pytest.fixture(scope="module")
def sample_csv():
    feats = list(joblib.load("models/feature_cols.joblib"))
    n_rows = 5
    rng = np.random.default_rng(123)
    data = {f: rng.uniform(10, 500, n_rows) for f in feats}
    data["Timestamp"] = ["04/07/2017 10:00:00"] * n_rows
    data["Source IP"] = ["192.168.10.50"] * n_rows
    data["Destination IP"] = ["172.217.12.138"] * n_rows
    data["Destination Port"] = [443] * n_rows
    data["Label"] = ["BENIGN"] * n_rows
    df = pd.DataFrame(data)
    return df.to_csv(index=False).encode("utf-8"), df, feats


def _make_valid_pcap():
    global_hdr = struct.pack(">IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    eth_hdr = b"\x00" * 12 + struct.pack(">H", 0x0800)

    # 1. SYN
    ip1 = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 44, 1, 0, 64, 6, 0, socket.inet_aton("10.0.0.1"), socket.inet_aton("192.168.0.1"))
    tcp1 = struct.pack(">HHIIBBHHH4s", 41234, 80, 100, 0, (6 << 4), 0x02, 64240, 0, 0, b"\x00" * 4)
    pkt1 = eth_hdr + ip1 + tcp1
    hdr1 = struct.pack(">IIII", 1500000000, 0, len(pkt1), len(pkt1))

    # 2. SYN-ACK
    ip2 = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 44, 2, 0, 64, 6, 0, socket.inet_aton("192.168.0.1"), socket.inet_aton("10.0.0.1"))
    tcp2 = struct.pack(">HHIIBBHHH4s", 80, 41234, 500, 101, (6 << 4), 0x12, 64240, 0, 0, b"\x00" * 4)
    pkt2 = eth_hdr + ip2 + tcp2
    hdr2 = struct.pack(">IIII", 1500000000, 5000, len(pkt2), len(pkt2))

    # 3. Data ACK
    payload = b"GET / HTTP/1.1\r\n\r\n"
    ip3 = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 3, 0, 64, 6, 0, socket.inet_aton("10.0.0.1"), socket.inet_aton("192.168.0.1"))
    tcp3 = struct.pack(">HHIIBBHHH", 41234, 80, 101, 501, (5 << 4), 0x18, 64240, 0, 0) + payload
    pkt3 = eth_hdr + ip3 + tcp3
    hdr3 = struct.pack(">IIII", 1500000000, 10000, len(pkt3), len(pkt3))

    return global_hdr + hdr1 + pkt1 + hdr2 + pkt2 + hdr3 + pkt3


def _make_valid_pcapng():
    shb = struct.pack(">IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    idb = struct.pack(">IIHHIi", 1, 20, 1, 0, 65535, 20)
    eth_hdr = b"\x00" * 12 + struct.pack(">H", 0x0800)

    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 48, 1, 0, 64, 6, 0, socket.inet_aton("10.1.1.1"), socket.inet_aton("10.2.2.2"))
    tcp = struct.pack(">HHIIBBHHH8s", 55555, 22, 10, 0, (7 << 4), 0x02, 32000, 0, 0, b"\x00" * 8)
    pkt = eth_hdr + ip + tcp
    pad = (4 - (len(pkt) % 4)) % 4
    pkt_pad = pkt + b"\x00" * pad
    epb_len = 32 + len(pkt_pad)
    epb = struct.pack(">IIIIIII", 6, epb_len, 0, 0x00055B8D, 0x8A920000, len(pkt), len(pkt)) + pkt_pad + struct.pack(">I", epb_len)

    return shb + idb + epb


def _make_arp_only_pcap():
    """Valid PCAP that contains only ARP packets (no transport flows)."""
    global_hdr = struct.pack(">IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    # Ethernet with EtherType 0x0806 (ARP)
    eth_arp = b"\xff" * 6 + b"\x00\x11\x22\x33\x44\x55" + struct.pack(">H", 0x0806)
    arp_body = struct.pack(">HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, b"\x00" * 6, socket.inet_aton("10.0.0.1"), b"\x00" * 6, socket.inet_aton("10.0.0.2"))
    pkt = eth_arp + arp_body
    hdr = struct.pack(">IIII", 1500000000, 0, len(pkt), len(pkt))
    return global_hdr + hdr + pkt


def _make_icmp_only_pcap():
    """Valid PCAP that contains only ICMP packets (protocol 1, no TCP/UDP flows)."""
    global_hdr = struct.pack(">IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    eth_hdr = b"\x00" * 12 + struct.pack(">H", 0x0800)
    # IPv4 header with protocol=1 (ICMP)
    ip_icmp = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 28, 1, 0, 64, 1, 0, socket.inet_aton("10.0.0.1"), socket.inet_aton("10.0.0.2"))
    icmp_body = struct.pack(">BBHHH", 8, 0, 0, 1234, 1)  # Echo request
    pkt = eth_hdr + ip_icmp + icmp_body
    hdr = struct.pack(">IIII", 1500000000, 0, len(pkt), len(pkt))
    return global_hdr + hdr + pkt


# =====================================================================
# Test Cases
# =====================================================================

def test_complete_csv_upload_and_prediction(sample_csv):
    """Test valid CSV upload -> backlog -> scoring step -> alert buffer & state."""
    csv_bytes, orig_df, _ = sample_csv
    f = UploadFile(filename="traffic_sample.csv", file=io.BytesIO(csv_bytes))
    res = asyncio.run(upload(f))

    assert res["ok"] is True
    assert res["queued"] == len(orig_df)
    assert res["type"] == "csv"
    assert S["source"] == "upload"
    assert len(S["backlog"]) == len(orig_df)

    # Verify model input dimensions and order before scoring
    batch = S["backlog"].take(len(orig_df))
    X_rf = det.prepare_rf_input(batch)
    assert isinstance(X_rf, pd.DataFrame)
    assert list(X_rf.columns) == det.feats
    assert X_rf.shape == (len(orig_df), 65)

    Xa = det.prepare_ae_input(batch)
    assert isinstance(Xa, np.ndarray)
    assert Xa.dtype == np.float32
    assert Xa.shape == (len(orig_df), 65)

    # Score batch through Detector.predict()
    predictions = det.predict(batch)
    assert len(predictions) == len(orig_df)
    assert set(predictions["predicted"].unique()).issubset(set(det.le.classes_))
    assert np.all((predictions["confidence"] >= 0) & (predictions["confidence"] <= 1.0))
    assert np.all((predictions["attack_score"] >= 0) & (predictions["attack_score"] <= 1.0))
    assert np.all(predictions["anomaly_score"] >= 0.0)
    assert set(predictions["verdict"].unique()).issubset({"Genuine", "Suspicious", "Malicious"})

    # Ingest and step through server
    S["backlog"].add(batch)
    step_locked()
    assert len(S["alerts"]) == len(orig_df)

    # Verify dashboard state reflects scored alerts
    st = state(sev="Critical,High,Medium,Info")
    assert st["has_data"] is True
    assert st["total"] == len(orig_df)
    assert len(st["feed"]) > 0
    assert len(st["queue"]) > 0


def test_complete_pcap_upload_and_prediction():
    """Test valid PCAP upload -> flow extraction -> prediction pipeline -> state."""
    pcap_bytes = _make_valid_pcap()
    f = UploadFile(filename="capture.pcap", file=io.BytesIO(pcap_bytes))
    res = asyncio.run(upload(f))

    assert res["ok"] is True
    assert res["queued"] == 1
    assert res["type"] == "pcap"
    assert S["source"] == "upload"

    step_locked()
    assert len(S["alerts"]) == 1
    alert = S["alerts"].iloc[0]
    assert alert["dst_port"] == 80
    assert alert["src_ip"] == "10.0.0.1"
    assert alert["dst_ip"] == "192.168.0.1"
    assert alert["verdict"] in ("Genuine", "Suspicious", "Malicious")
    assert alert["severity"] in ("Critical", "High", "Medium", "Info")


def test_complete_pcapng_upload_and_prediction():
    """Test valid PCAPNG upload -> flow extraction -> prediction pipeline -> state."""
    pcapng_bytes = _make_valid_pcapng()
    f = UploadFile(filename="capture.pcapng", file=io.BytesIO(pcapng_bytes))
    res = asyncio.run(upload(f))

    assert res["ok"] is True
    assert res["queued"] == 1
    assert res["type"] == "pcap"

    step_locked()
    assert len(S["alerts"]) == 1
    alert = S["alerts"].iloc[0]
    assert alert["dst_port"] == 22


def test_invalid_csv_empty_file():
    f = UploadFile(filename="empty.csv", file=io.BytesIO(b""))
    res = asyncio.run(upload(f))
    assert res["ok"] is False
    assert "empty" in res["error"].lower()


def test_invalid_csv_malformed_content():
    f = UploadFile(filename="corrupt.csv", file=io.BytesIO(b"\x00\xff\xfe\x01\x80\x99\xaa"))
    res = asyncio.run(upload(f))
    assert res["ok"] is False
    assert any(err in res["error"].lower() for err in ["could not read", "features not found", "no data rows"])


def test_invalid_csv_no_data_rows():
    feats = list(joblib.load("models/feature_cols.joblib"))
    header_only = ",".join(feats).encode("utf-8") + b"\n"
    f = UploadFile(filename="header_only.csv", file=io.BytesIO(header_only))
    res = asyncio.run(upload(f))
    assert res["ok"] is False
    assert "no data rows" in res["error"].lower()


def test_invalid_csv_all_rows_invalid():
    feats = list(joblib.load("models/feature_cols.joblib"))
    bad_rows = f"{','.join(feats)}\n" + f"{','.join(['not_a_number'] * len(feats))}\n"
    f = UploadFile(filename="all_nan.csv", file=io.BytesIO(bad_rows.encode("utf-8")))
    res = asyncio.run(upload(f))
    assert res["ok"] is False
    assert "no usable flow rows" in res["error"].lower()


def test_csv_missing_features():
    feats = list(joblib.load("models/feature_cols.joblib"))
    # Omit 5 features
    missing_5 = feats[-5:]
    kept_feats = feats[:-5]
    df = pd.DataFrame({f: [1.0, 2.0] for f in kept_feats})
    f = UploadFile(filename="missing_features.csv", file=io.BytesIO(df.to_csv(index=False).encode("utf-8")))
    res = asyncio.run(upload(f))
    assert res["ok"] is False
    assert "not found" in res["error"].lower()
    for col in missing_5:
        assert col in res["error"]


def test_corrupted_pcap_empty_file():
    f = UploadFile(filename="empty.pcap", file=io.BytesIO(b""))
    res = asyncio.run(upload(f))
    assert res["ok"] is False
    assert "empty" in res["error"].lower()


def test_corrupted_pcap_truncated():
    # Only 10 bytes (minimum header is 24 bytes)
    truncated = b"\xa1\xb2\xc3\xd4\x00\x02\x00\x04\x00\x00"
    f = UploadFile(filename="truncated.pcap", file=io.BytesIO(truncated))
    res = asyncio.run(upload(f))
    assert res["ok"] is False
    assert "truncated" in res["error"].lower()


def test_corrupted_pcap_invalid_magic_bytes():
    fake_pcap = b"THIS_IS_NOT_A_VALID_PCAP_FILE_AT_ALL_FOR_SURE"
    f = UploadFile(filename="fake.pcap", file=io.BytesIO(fake_pcap))
    res = asyncio.run(upload(f))
    assert res["ok"] is False
    assert "not a valid pcap" in res["error"].lower()


def test_pcap_no_extractable_flows_arp_only():
    arp_pcap = _make_arp_only_pcap()
    f = UploadFile(filename="arp_only.pcap", file=io.BytesIO(arp_pcap))
    res = asyncio.run(upload(f))
    assert res["ok"] is False
    assert "no valid ipv4 tcp/udp packets" in res["error"].lower()


def test_pcap_no_extractable_flows_icmp_only():
    icmp_pcap = _make_icmp_only_pcap()
    f = UploadFile(filename="icmp_only.pcap", file=io.BytesIO(icmp_pcap))
    res = asyncio.run(upload(f))
    assert res["ok"] is False
    assert "no valid ipv4 tcp/udp packets" in res["error"].lower()
