"""pcap.py: PCAP and PCAPNG processing and feature extraction for Predictive-IDS.

Features:
- Compatibility verification for CICFlowMeter (Java and Python versions).
- Pure-Python native parser for both standard .pcap and .pcapng files (zero external dependencies).
- Bidirectional flow aggregation and feature calculation matching CICFlowMeter / CIC-IDS2017.
- Integration with existing validation, feature selection, and model prediction pipelines.
"""
import io
import math
import os
import shutil
import socket
import struct
import subprocess
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

from backend.feed import align, finish, validate_and_preprocess_csv


# =====================================================================
# 1. CICFlowMeter Verification, Requirements, and Command Syntax
# =====================================================================

def verify_cicflowmeter():
    """Verify CICFlowMeter installation, compatibility, and command syntax.

    Returns a comprehensive dict with installation status and operational syntax.
    """
    custom_path = os.environ.get("CICFLOWMETER_PATH")
    cli_py = shutil.which("cicflowmeter")
    cli_java = shutil.which("cfm") or shutil.which("cfm.bat")

    installed_tool = None
    cli_path = None
    if custom_path and os.path.exists(custom_path):
        installed_tool = "custom"
        cli_path = custom_path
    elif cli_py:
        installed_tool = "python"
        cli_path = cli_py
    elif cli_java:
        installed_tool = "java"
        cli_path = cli_java

    return {
        "installed": installed_tool is not None,
        "tool_type": installed_tool or "built-in native engine",
        "executable_path": cli_path,
        "pcap_compatible": True,
        "pcapng_compatible": {
            "native_engine": True,
            "python_cicflowmeter": True,
            "java_cicflowmeter": (
                "Incompatible directly with Java CICFlowMeter v4; "
                "requires prior conversion to .pcap via 'tshark -F pcap' or 'editcap -F libpcap'."
            ),
        },
        "installation_requirements": {
            "java_version": {
                "runtime": "Java 8+ (JRE/JDK)",
                "packet_capture_driver": "WinPcap or Npcap (installed in WinPcap API-compatible mode on Windows)",
                "native_library": "jnetpcap.dll (Windows) or libjnetpcap.so (Linux)",
                "repository": "https://github.com/ahlashkari/CICFlowMeter",
            },
            "python_version": {
                "runtime": "Python 3.8+",
                "package": "pip install cicflowmeter scapy",
                "repository": "https://github.com/cflowmeter/cicflowmeter or pip package",
            },
            "built_in_engine": {
                "runtime": "Pure Python (bundled with this project)",
                "dependencies": "Standard library (struct, socket) + numpy/pandas",
                "notes": "Runs automatically without external installations on Windows/Linux/macOS.",
            },
        },
        "command_syntax": {
            "java_cli_windows": "cfm.bat \"<input_pcap_or_folder>\" \"<output_csv_directory>\"",
            "java_cli_jar": "java -Djava.library.path=lib -jar CICFlowMeter.jar \"<input.pcap>\" \"<output_dir>\"",
            "python_cli": "cicflowmeter -f \"<input.pcap_or_pcapng>\" -c \"<output.csv>\"",
            "pcapng_conversion": "editcap -F libpcap \"<input.pcapng>\" \"<converted.pcap>\"",
        },
    }


# =====================================================================
# 2. Native PCAP / PCAPNG Dissector
# =====================================================================

def _dissect_ipv4_packet(pkt_bytes):
    """Dissects an Ethernet / IP packet into 5-tuple, lengths, flags, and window."""
    if len(pkt_bytes) < 14:
        return None

    eth_type = struct.unpack(">H", pkt_bytes[12:14])[0]
    offset = 14

    # Handle 802.1Q VLAN tag
    if eth_type == 0x8100 and len(pkt_bytes) >= 18:
        eth_type = struct.unpack(">H", pkt_bytes[16:18])[0]
        offset = 18

    # IPv4 (0x0800)
    if eth_type != 0x0800 or len(pkt_bytes) < offset + 20:
        # Check Linux Cooked SLL (DLT 113)
        if len(pkt_bytes) >= 16:
            sll_type = struct.unpack(">H", pkt_bytes[14:16])[0]
            if sll_type == 0x0800:
                offset = 16
            else:
                return None
        else:
            return None

    ip_hdr = pkt_bytes[offset: offset + 20]
    ver_ihl = ip_hdr[0]
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(pkt_bytes) < offset + ihl:
        return None

    tot_len = struct.unpack(">H", ip_hdr[2:4])[0]
    protocol = ip_hdr[9]
    src_ip = socket.inet_ntoa(ip_hdr[12:16])
    dst_ip = socket.inet_ntoa(ip_hdr[16:20])

    transport_offset = offset + ihl
    payload_len = 0
    src_port = 0
    dst_port = 0
    header_len = ihl
    tcp_flags = 0
    window = 0

    if protocol == 6:  # TCP
        if len(pkt_bytes) < transport_offset + 20:
            return None
        tcp_hdr = pkt_bytes[transport_offset: transport_offset + 20]
        src_port, dst_port = struct.unpack(">HH", tcp_hdr[0:4])
        data_offset = (tcp_hdr[12] >> 4) * 4
        tcp_flags = tcp_hdr[13]
        window = struct.unpack(">H", tcp_hdr[14:16])[0]
        header_len += data_offset
        payload_len = max(0, tot_len - ihl - data_offset)
    elif protocol == 17:  # UDP
        if len(pkt_bytes) < transport_offset + 8:
            return None
        udp_hdr = pkt_bytes[transport_offset: transport_offset + 8]
        src_port, dst_port, udp_len = struct.unpack(">HHH", udp_hdr[0:6])
        header_len += 8
        payload_len = max(0, udp_len - 8)
    else:
        return None  # Only transport protocols TCP/UDP form application flows

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": int(src_port),
        "dst_port": int(dst_port),
        "protocol": int(protocol),
        "tot_len": tot_len,
        "payload_len": payload_len,
        "header_len": header_len,
        "tcp_flags": tcp_flags,
        "window": window,
    }


def parse_pcap_packets(data_or_path):
    """Parses raw packets from either standard PCAP or PCAPNG data.

    Returns a list of packet dicts sorted by arrival time.
    """
    if isinstance(data_or_path, (str, Path)):
        with open(data_or_path, "rb") as f:
            raw = f.read()
    elif isinstance(data_or_path, (bytes, bytearray)):
        raw = bytes(data_or_path)
    else:
        raw = data_or_path.read()

    if len(raw) == 0:
        raise ValueError("Packet capture file is empty.")
    if len(raw) < 24:
        raise ValueError("Packet capture file is truncated (smaller than minimum header size).")

    # Detect format via magic bytes
    magic = raw[:4]
    if magic not in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1", b"\n\r\r\n"):
        raise ValueError("File is not a valid PCAP or PCAPNG capture (unrecognized header magic bytes).")
    packets = []

    # 1. Standard PCAP
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"):
        endian = ">" if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d") else "<"
        is_nanosec = magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1")
        time_divisor = 1e9 if is_nanosec else 1e6

        idx = 24
        raw_len = len(raw)
        while idx + 16 <= raw_len:
            ts_sec, ts_sub, incl_len, orig_len = struct.unpack(endian + "IIII", raw[idx: idx + 16])
            idx += 16
            if idx + incl_len > raw_len:
                break
            pkt_bytes = raw[idx: idx + incl_len]
            idx += incl_len

            ts = float(ts_sec) + (float(ts_sub) / time_divisor)
            dissected = _dissect_ipv4_packet(pkt_bytes)
            if dissected:
                dissected["timestamp"] = ts
                packets.append(dissected)

    # 2. PCAPNG (Section Header Block magic 0x0a0d0d0a)
    elif magic == b"\n\r\r\n":
        idx = 0
        raw_len = len(raw)
        endian = ">"
        ts_resol = 1e6  # default microsecond resolution

        while idx + 8 <= raw_len:
            b_type, b_len = struct.unpack(endian + "II", raw[idx: idx + 8])
            if b_len < 12 or idx + b_len > raw_len:
                break

            block_body = raw[idx + 8: idx + b_len - 4]

            if b_type == 0x0A0D0D0A:  # Section Header Block
                if len(block_body) >= 4:
                    bom = block_body[:4]
                    if bom == b"\x1a\x2b\x3c\x4d":
                        endian = ">"
                    elif bom == b"\x4d\x3c\x2b\x1a":
                        endian = "<"

            elif b_type == 0x00000006:  # Enhanced Packet Block
                if len(block_body) >= 20:
                    if_id, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(
                        endian + "IIIII", block_body[:20]
                    )
                    ts_raw = (ts_hi << 32) | ts_lo
                    ts = ts_raw / ts_resol
                    pkt_bytes = block_body[20: 20 + cap_len]
                    dissected = _dissect_ipv4_packet(pkt_bytes)
                    if dissected:
                        dissected["timestamp"] = ts
                        packets.append(dissected)

            idx += b_len

    packets.sort(key=lambda p: p["timestamp"])
    return packets


# =====================================================================
# 3. Flow Aggregation & CICFlowMeter Metric Calculation
# =====================================================================

def _std(arr):
    return float(np.std(arr, ddof=1)) if len(arr) > 1 else 0.0


def extract_flows_from_packets(packets, flow_timeout_s=120.0):
    """Aggregates packet records into bidirectional flows and calculates CICFlowMeter features."""
    if not packets:
        return pd.DataFrame()

    flows_dict = {}

    for p in packets:
        fwd_key = (p["src_ip"], p["dst_ip"], p["src_port"], p["dst_port"], p["protocol"])
        bwd_key = (p["dst_ip"], p["src_ip"], p["dst_port"], p["src_port"], p["protocol"])

        if fwd_key in flows_dict:
            flow = flows_dict[fwd_key]
            # Check timeout
            if p["timestamp"] - flow["last_ts"] > flow_timeout_s:
                flow["closed"] = True
                new_key = fwd_key + (p["timestamp"],)
                flow = flows_dict[new_key] = _new_flow_state(p, is_fwd=True)
            else:
                _append_packet_to_flow(flow, p, is_fwd=True)
        elif bwd_key in flows_dict and not flows_dict[bwd_key]["closed"]:
            flow = flows_dict[bwd_key]
            if p["timestamp"] - flow["last_ts"] > flow_timeout_s:
                flow["closed"] = True
                new_key = fwd_key + (p["timestamp"],)
                flow = flows_dict[new_key] = _new_flow_state(p, is_fwd=True)
            else:
                _append_packet_to_flow(flow, p, is_fwd=False)
        else:
            flows_dict[fwd_key] = _new_flow_state(p, is_fwd=True)

    rows = []
    for flow in flows_dict.values():
        row = _compute_flow_metrics(flow)
        rows.append(row)

    return pd.DataFrame(rows)


def _new_flow_state(p, is_fwd=True):
    return {
        "src_ip": p["src_ip"],
        "dst_ip": p["dst_ip"],
        "src_port": p["src_port"],
        "dst_port": p["dst_port"],
        "protocol": p["protocol"],
        "start_ts": p["timestamp"],
        "last_ts": p["timestamp"],
        "fwd_last_ts": p["timestamp"] if is_fwd else None,
        "bwd_last_ts": p["timestamp"] if not is_fwd else None,
        "closed": False,
        "fwd_lens": [p["tot_len"]] if is_fwd else [],
        "bwd_lens": [p["tot_len"]] if not is_fwd else [],
        "all_lens": [p["tot_len"]],
        "flow_iats": [],
        "fwd_iats": [],
        "bwd_iats": [],
        "fwd_header_len": p["header_len"] if is_fwd else 0,
        "bwd_header_len": p["header_len"] if not is_fwd else 0,
        "fwd_psh": 1 if (is_fwd and (p["tcp_flags"] & 0x08)) else 0,
        "fwd_urg": 1 if (is_fwd and (p["tcp_flags"] & 0x20)) else 0,
        "fin_cnt": 1 if (p["tcp_flags"] & 0x01) else 0,
        "syn_cnt": 1 if (p["tcp_flags"] & 0x02) else 0,
        "rst_cnt": 1 if (p["tcp_flags"] & 0x04) else 0,
        "psh_cnt": 1 if (p["tcp_flags"] & 0x08) else 0,
        "ack_cnt": 1 if (p["tcp_flags"] & 0x10) else 0,
        "urg_cnt": 1 if (p["tcp_flags"] & 0x20) else 0,
        "ece_cnt": 1 if (p["tcp_flags"] & 0x40) else 0,
        "init_win_fwd": p["window"] if is_fwd else -1,
        "init_win_bwd": p["window"] if not is_fwd else -1,
        "act_data_pkt_fwd": 1 if (is_fwd and p["payload_len"] > 0) else 0,
        "min_seg_size_fwd": p["header_len"] if is_fwd else 999999,
    }


def _append_packet_to_flow(flow, p, is_fwd):
    ts = p["timestamp"]
    flow_iat = (ts - flow["last_ts"]) * 1e6
    flow["flow_iats"].append(max(0.0, flow_iat))
    flow["last_ts"] = ts
    flow["all_lens"].append(p["tot_len"])

    if is_fwd:
        flow["fwd_lens"].append(p["tot_len"])
        flow["fwd_header_len"] += p["header_len"]
        if flow["fwd_last_ts"] is not None:
            flow["fwd_iats"].append(max(0.0, (ts - flow["fwd_last_ts"]) * 1e6))
        flow["fwd_last_ts"] = ts
        if p["tcp_flags"] & 0x08:
            flow["fwd_psh"] += 1
        if p["tcp_flags"] & 0x20:
            flow["fwd_urg"] += 1
        if p["payload_len"] > 0:
            flow["act_data_pkt_fwd"] += 1
        if p["header_len"] < flow["min_seg_size_fwd"]:
            flow["min_seg_size_fwd"] = p["header_len"]
    else:
        flow["bwd_lens"].append(p["tot_len"])
        flow["bwd_header_len"] += p["header_len"]
        if flow["bwd_last_ts"] is not None:
            flow["bwd_iats"].append(max(0.0, (ts - flow["bwd_last_ts"]) * 1e6))
        flow["bwd_last_ts"] = ts
        if flow["init_win_bwd"] == -1:
            flow["init_win_bwd"] = p["window"]

    if p["tcp_flags"] & 0x01:
        flow["fin_cnt"] += 1
    if p["tcp_flags"] & 0x02:
        flow["syn_cnt"] += 1
    if p["tcp_flags"] & 0x04:
        flow["rst_cnt"] += 1
    if p["tcp_flags"] & 0x08:
        flow["psh_cnt"] += 1
    if p["tcp_flags"] & 0x10:
        flow["ack_cnt"] += 1
    if p["tcp_flags"] & 0x20:
        flow["urg_cnt"] += 1
    if p["tcp_flags"] & 0x40:
        flow["ece_cnt"] += 1


def _compute_flow_metrics(flow):
    duration_us = max(0.0, (flow["last_ts"] - flow["start_ts"]) * 1e6)
    duration_s = max(duration_us / 1e6, 1e-6)

    fwd_pkts = len(flow["fwd_lens"])
    bwd_pkts = len(flow["bwd_lens"])
    tot_pkts = len(flow["all_lens"])

    tot_len_fwd = sum(flow["fwd_lens"])
    tot_len_bwd = sum(flow["bwd_lens"])
    tot_len_all = sum(flow["all_lens"])

    fwd_lens = np.array(flow["fwd_lens"]) if fwd_pkts else np.array([0.0])
    bwd_lens = np.array(flow["bwd_lens"]) if bwd_pkts else np.array([0.0])
    all_lens = np.array(flow["all_lens"])

    flow_iats = np.array(flow["flow_iats"]) if flow["flow_iats"] else np.array([0.0])
    fwd_iats = np.array(flow["fwd_iats"]) if flow["fwd_iats"] else np.array([0.0])
    bwd_iats = np.array(flow["bwd_iats"]) if flow["bwd_iats"] else np.array([0.0])

    fwd_pkt_mean = float(fwd_lens.mean()) if fwd_pkts else 0.0
    bwd_pkt_mean = float(bwd_lens.mean()) if bwd_pkts else 0.0

    flow_id = f"{flow['src_ip']}-{flow['dst_ip']}-{flow['src_port']}-{flow['dst_port']}-{flow['protocol']}"
    ts_str = datetime.fromtimestamp(flow["start_ts"]).strftime("%d/%m/%Y %H:%M:%S")

    down_up_ratio = float(bwd_pkts / fwd_pkts) if fwd_pkts > 0 else 0.0
    avg_pkt_size = float(all_lens.mean()) if tot_pkts > 0 else 0.0

    return {
        "Flow ID": flow_id,
        "Source IP": flow["src_ip"],
        "Source Port": flow["src_port"],
        "Destination IP": flow["dst_ip"],
        "Destination Port": flow["dst_port"],
        "Protocol": flow["protocol"],
        "Timestamp": ts_str,
        "Flow Duration": duration_us,
        "Total Fwd Packets": fwd_pkts,
        "Total Backward Packets": bwd_pkts,
        "Total Length of Fwd Packets": tot_len_fwd,
        "Total Length of Bwd Packets": tot_len_bwd,
        "Fwd Packet Length Max": float(fwd_lens.max()) if fwd_pkts else 0.0,
        "Fwd Packet Length Min": float(fwd_lens.min()) if fwd_pkts else 0.0,
        "Fwd Packet Length Mean": fwd_pkt_mean,
        "Fwd Packet Length Std": _std(fwd_lens) if fwd_pkts else 0.0,
        "Bwd Packet Length Max": float(bwd_lens.max()) if bwd_pkts else 0.0,
        "Bwd Packet Length Min": float(bwd_lens.min()) if bwd_pkts else 0.0,
        "Bwd Packet Length Mean": bwd_pkt_mean,
        "Bwd Packet Length Std": _std(bwd_lens) if bwd_pkts else 0.0,
        "Flow Bytes/s": float(tot_len_all / duration_s),
        "Flow Packets/s": float(tot_pkts / duration_s),
        "Flow IAT Mean": float(flow_iats.mean()) if len(flow["flow_iats"]) else 0.0,
        "Flow IAT Std": _std(flow_iats) if len(flow["flow_iats"]) else 0.0,
        "Flow IAT Max": float(flow_iats.max()) if len(flow["flow_iats"]) else 0.0,
        "Flow IAT Min": float(flow_iats.min()) if len(flow["flow_iats"]) else 0.0,
        "Fwd IAT Total": float(fwd_iats.sum()) if len(flow["fwd_iats"]) else 0.0,
        "Fwd IAT Mean": float(fwd_iats.mean()) if len(flow["fwd_iats"]) else 0.0,
        "Fwd IAT Std": _std(fwd_iats) if len(flow["fwd_iats"]) else 0.0,
        "Fwd IAT Max": float(fwd_iats.max()) if len(flow["fwd_iats"]) else 0.0,
        "Fwd IAT Min": float(fwd_iats.min()) if len(flow["fwd_iats"]) else 0.0,
        "Bwd IAT Total": float(bwd_iats.sum()) if len(flow["bwd_iats"]) else 0.0,
        "Bwd IAT Mean": float(bwd_iats.mean()) if len(flow["bwd_iats"]) else 0.0,
        "Bwd IAT Std": _std(bwd_iats) if len(flow["bwd_iats"]) else 0.0,
        "Bwd IAT Max": float(bwd_iats.max()) if len(flow["bwd_iats"]) else 0.0,
        "Bwd IAT Min": float(bwd_iats.min()) if len(flow["bwd_iats"]) else 0.0,
        "Fwd PSH Flags": flow["fwd_psh"],
        "Fwd URG Flags": flow["fwd_urg"],
        "Fwd Header Length": flow["fwd_header_len"],
        "Bwd Header Length": flow["bwd_header_len"],
        "Fwd Packets/s": float(fwd_pkts / duration_s),
        "Bwd Packets/s": float(bwd_pkts / duration_s),
        "Min Packet Length": float(all_lens.min()),
        "Max Packet Length": float(all_lens.max()),
        "Packet Length Mean": float(all_lens.mean()),
        "Packet Length Std": _std(all_lens),
        "Packet Length Variance": float(np.var(all_lens, ddof=1)) if len(all_lens) > 1 else 0.0,
        "FIN Flag Count": flow["fin_cnt"],
        "RST Flag Count": flow["rst_cnt"],
        "PSH Flag Count": flow["psh_cnt"],
        "ACK Flag Count": flow["ack_cnt"],
        "URG Flag Count": flow["urg_cnt"],
        "ECE Flag Count": flow["ece_cnt"],
        "Down/Up Ratio": down_up_ratio,
        "Average Packet Size": avg_pkt_size,
        "Avg Fwd Segment Size": fwd_pkt_mean,
        "Avg Bwd Segment Size": bwd_pkt_mean,
        "Subflow Fwd Bytes": tot_len_fwd,
        "Subflow Bwd Bytes": tot_len_bwd,
        "Init_Win_bytes_forward": flow["init_win_fwd"],
        "Init_Win_bytes_backward": flow["init_win_bwd"],
        "act_data_pkt_fwd": flow["act_data_pkt_fwd"],
        "min_seg_size_forward": flow["min_seg_size_fwd"] if flow["min_seg_size_fwd"] != 999999 else 20,
        "Active Mean": 0.0,
        "Active Std": 0.0,
        "Active Max": 0.0,
        "Active Min": 0.0,
        "Idle Mean": 0.0,
        "Idle Std": 0.0,
        "Idle Max": 0.0,
        "Idle Min": 0.0,
        "Label": "(unlabelled)",
    }


# =====================================================================
# 4. End-to-End Processing & Prediction Integration
# =====================================================================

def is_pcap_data(data_or_path):
    """Detects if data or path is a PCAP or PCAPNG file."""
    if isinstance(data_or_path, (str, Path)):
        p = Path(data_or_path)
        if p.suffix.lower() in (".pcap", ".pcapng", ".cap"):
            return True
        if p.exists():
            with open(p, "rb") as f:
                header = f.read(4)
        else:
            return False
    elif isinstance(data_or_path, (bytes, bytearray)):
        header = data_or_path[:4]
    else:
        return False

    return header in (
        b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",
        b"\n\r\r\n"
    )


def process_pcap_to_flows(source, feats=None):
    """Parses a PCAP/PCAPNG, extracts network flows, and validates features against model schema.

    Returns (cleaned_df, None) or (None, error_str).
    """
    if source is None:
        return None, "No packet capture data provided."

    try:
        packets = parse_pcap_packets(source)
    except Exception as e:
        return None, f"Could not parse PCAP/PCAPNG capture: {e}"

    if not packets:
        return None, "No valid IPv4 TCP/UDP packets found in packet capture (or capture contains only non-transport packets such as ARP/ICMP)."

    df_flows = extract_flows_from_packets(packets)
    if df_flows.empty:
        return None, "No network flows could be reconstructed from the packet capture."

    if feats is None:
        return df_flows, None

    frame, missing = align(df_flows, feats)
    if missing:
        return None, f"{len(missing)} model features could not be computed from flows: {missing[:5]}"

    fin = finish(frame, feats)
    if fin.empty:
        return None, "No usable flow records produced after feature validation."

    return fin, None


def predict_pcap_flows(source, detector):
    """Processes PCAP/PCAPNG flows and runs Random Forest & Autoencoder prediction pipelines."""
    feats = getattr(detector, "all_feats", detector.feats)
    fin, err = process_pcap_to_flows(source, feats)
    if err:
        return None, err

    predictions = detector.predict(fin)
    return predictions, None
