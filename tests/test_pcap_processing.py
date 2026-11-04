"""tests/test_pcap_processing.py: tests for PCAP/PCAPNG parsing, CICFlowMeter verification,
feature extraction, model preprocessing, and prediction pipeline integration.
"""
import asyncio
import io
import socket
import struct

import numpy as np
import pandas as pd
import pytest
from fastapi import UploadFile

from backend.detector import Detector
from backend.pcap import (
    extract_flows_from_packets,
    is_pcap_data,
    parse_pcap_packets,
    predict_pcap_flows,
    process_pcap_to_flows,
    verify_cicflowmeter,
)
from backend.server import det, FEATS, pcap_info, S, step_locked, upload


def _make_pcap_bytes():
    """Builds a realistic synthetic PCAP byte stream (3-packet HTTP flow)."""
    global_hdr = struct.pack(">IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    eth_hdr = b"\x00" * 12 + struct.pack(">H", 0x0800)

    # Packet 1: Client SYN
    ip1 = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, 44, 1, 0, 64, 6, 0,
        socket.inet_aton("192.168.1.100"), socket.inet_aton("10.0.0.1")
    )
    tcp1 = struct.pack(">HHIIBBHHH4s", 50000, 80, 1000, 0, (6 << 4), 0x02, 64240, 0, 0, b"\x00" * 4)
    pkt1 = eth_hdr + ip1 + tcp1
    hdr1 = struct.pack(">IIII", 1500000000, 0, len(pkt1), len(pkt1))

    # Packet 2: Server SYN-ACK
    ip2 = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, 44, 2, 0, 64, 6, 0,
        socket.inet_aton("10.0.0.1"), socket.inet_aton("192.168.1.100")
    )
    tcp2 = struct.pack(">HHIIBBHHH4s", 80, 50000, 5000, 1001, (6 << 4), 0x12, 64240, 0, 0, b"\x00" * 4)
    pkt2 = eth_hdr + ip2 + tcp2
    hdr2 = struct.pack(">IIII", 1500000000, 10000, len(pkt2), len(pkt2))

    # Packet 3: Client ACK with HTTP GET payload
    payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    ip3 = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 3, 0, 64, 6, 0,
        socket.inet_aton("192.168.1.100"), socket.inet_aton("10.0.0.1")
    )
    tcp3 = struct.pack(">HHIIBBHHH", 50000, 80, 1001, 5001, (5 << 4), 0x18, 64240, 0, 0) + payload
    pkt3 = eth_hdr + ip3 + tcp3
    hdr3 = struct.pack(">IIII", 1500000000, 20000, len(pkt3), len(pkt3))

    return global_hdr + hdr1 + pkt1 + hdr2 + pkt2 + hdr3 + pkt3


def _make_pcapng_bytes():
    """Builds a realistic synthetic PCAPNG byte stream (2-packet SSH flow)."""
    # Section Header Block (SHB)
    shb = struct.pack(">IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    # Interface Description Block (IDB)
    idb = struct.pack(">IIHHIi", 1, 20, 1, 0, 65535, 20)

    eth_hdr = b"\x00" * 12 + struct.pack(">H", 0x0800)

    def _epb(src_p, dst_p, ts_hi, ts_lo, payload):
        ip_hdr = struct.pack(
            ">BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 1, 0, 64, 6, 0,
            socket.inet_aton("192.168.1.50"), socket.inet_aton("10.0.0.5")
        )
        tcp_hdr = struct.pack(">HHIIBBHHH", src_p, dst_p, 100, 0, (5 << 4), 0x02, 64240, 0, 0) + payload
        pkt = eth_hdr + ip_hdr + tcp_hdr
        pad = (4 - (len(pkt) % 4)) % 4
        pkt_padded = pkt + b"\x00" * pad
        epb_len = 32 + len(pkt_padded)
        return struct.pack(">IIIIIII", 6, epb_len, 0, ts_hi, ts_lo, len(pkt), len(pkt)) + pkt_padded + struct.pack(">I", epb_len)

    epb1 = _epb(44332, 22, 0x00055B8D, 0x8A920000, b"SSH-2.0-OpenSSH_8.9\r\n")
    epb2 = _epb(44332, 22, 0x00055B8D, 0x8A940000, b"SSH-2.0-client\r\n")

    return shb + idb + epb1 + epb2


def test_verify_cicflowmeter():
    info = verify_cicflowmeter()
    assert "installed" in info
    assert "tool_type" in info
    assert "command_syntax" in info
    assert "installation_requirements" in info
    assert "java_cli_windows" in info["command_syntax"]
    assert "python_cli" in info["command_syntax"]
    assert info["pcap_compatible"] is True
    assert info["pcapng_compatible"]["native_engine"] is True


def test_is_pcap_data():
    pcap = _make_pcap_bytes()
    pcapng = _make_pcapng_bytes()
    assert is_pcap_data(pcap) is True
    assert is_pcap_data(pcapng) is True
    assert is_pcap_data(b"not a pcap file at all") is False
    assert is_pcap_data(b"") is False


def test_parse_pcap_packets():
    pcap = _make_pcap_bytes()
    pkts = parse_pcap_packets(pcap)
    assert len(pkts) == 3
    assert pkts[0]["src_ip"] == "192.168.1.100"
    assert pkts[0]["dst_port"] == 80
    assert pkts[1]["src_ip"] == "10.0.0.1"
    assert pkts[1]["dst_port"] == 50000
    assert pkts[2]["dst_port"] == 80


def test_parse_pcapng_packets():
    pcapng = _make_pcapng_bytes()
    pkts = parse_pcap_packets(pcapng)
    assert len(pkts) == 2
    assert pkts[0]["src_ip"] == "192.168.1.50"
    assert pkts[0]["dst_port"] == 22


def test_extract_flows_from_packets():
    pkts = parse_pcap_packets(_make_pcap_bytes())
    flows_df = extract_flows_from_packets(pkts)
    assert len(flows_df) == 1
    flow = flows_df.iloc[0]
    assert flow["Total Fwd Packets"] == 2
    assert flow["Total Backward Packets"] == 1
    assert flow["Destination Port"] == 80
    assert flow["Flow Duration"] > 0
    assert "Flow Bytes/s" in flow
    assert "Flow Packets/s" in flow
    assert "Init_Win_bytes_forward" in flow


def test_process_pcap_to_flows():
    det_instance = Detector()
    pcap = _make_pcap_bytes()
    fin, err = process_pcap_to_flows(pcap, det_instance.all_feats)
    assert err is None
    assert fin is not None
    assert len(fin) == 1
    for f in det_instance.feats:
        assert f in fin.columns
    for f in det_instance.ae_feats:
        assert f in fin.columns


def test_process_pcapng_to_flows():
    det_instance = Detector()
    pcapng = _make_pcapng_bytes()
    fin, err = process_pcap_to_flows(pcapng, det_instance.all_feats)
    assert err is None
    assert fin is not None
    assert len(fin) == 1
    assert fin.iloc[0]["Destination Port"] == 22


def test_predict_pcap_flows():
    det_instance = Detector()
    pcap = _make_pcap_bytes()
    preds, err = predict_pcap_flows(pcap, det_instance)
    assert err is None
    assert preds is not None
    assert len(preds) == 1
    assert "predicted" in preds.columns
    assert "confidence" in preds.columns
    assert "attack_score" in preds.columns
    assert "anomaly_score" in preds.columns
    assert "verdict" in preds.columns
    assert preds.iloc[0]["verdict"] in ("Genuine", "Suspicious", "Malicious")


def test_pcap_empty_or_corrupt():
    det_instance = Detector()
    fin, err = process_pcap_to_flows(b"", det_instance.all_feats)
    assert fin is None
    assert err is not None

    fin_bad, err_bad = process_pcap_to_flows(b"\xa1\xb2\xc3\xd4" + b"\x00" * 10, det_instance.all_feats)
    assert fin_bad is None
    assert err_bad is not None


def test_server_upload_pcap_and_pcapng():
    # 1. Upload PCAP
    pcap_data = _make_pcap_bytes()
    f_pcap = UploadFile(filename="capture.pcap", file=io.BytesIO(pcap_data))
    res = asyncio.run(upload(f_pcap))
    assert res["ok"] is True
    assert res["queued"] == 1
    assert res["type"] == "pcap"
    assert S["source"] == "upload"

    prev_alerts = len(S["alerts"])
    step_locked()
    assert len(S["alerts"]) > prev_alerts

    # 2. Upload PCAPNG
    pcapng_data = _make_pcapng_bytes()
    f_pcapng = UploadFile(filename="traffic.pcapng", file=io.BytesIO(pcapng_data))
    res_ng = asyncio.run(upload(f_pcapng))
    assert res_ng["ok"] is True
    assert res_ng["queued"] == 1
    assert res_ng["type"] == "pcap"

    # 3. GET /api/pcap/info
    info = pcap_info()
    assert "installed" in info
    assert "command_syntax" in info
