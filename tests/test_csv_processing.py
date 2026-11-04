"""tests/test_csv_processing.py: tests for CSV upload validation, preprocessing,
RF feature order preservation, AE input preparation, and prediction pipeline integration.
"""
import asyncio
import io
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest
from fastapi import UploadFile

from backend.detector import Detector
from backend.feed import align, finish, validate_and_preprocess_csv
from backend.server import app, det, FEATS, S, step_locked, upload


@pytest.fixture(scope="module")
def detector_instance():
    return Detector()


@pytest.fixture(scope="module")
def sample_csv_data():
    """Generates a valid CSV with all 65 model features and sample metadata."""
    feats = list(joblib.load("models/feature_cols.joblib"))
    n_rows = 10
    rng = np.random.default_rng(42)
    data = {f: rng.uniform(0, 100, n_rows) for f in feats}
    data["Timestamp"] = ["2017-07-04 10:00:00"] * n_rows
    data["Source IP"] = ["192.168.1.10"] * n_rows
    data["Destination IP"] = ["10.0.0.1"] * n_rows
    data["Destination Port"] = [80] * n_rows
    data["Label"] = ["BENIGN"] * n_rows
    df = pd.DataFrame(data)
    csv_bytes = df.to_csv(index=False).encode("utf-8")
    return csv_bytes, df, feats


def test_validate_and_preprocess_valid_csv(sample_csv_data):
    csv_bytes, orig_df, feats = sample_csv_data
    fin, err = validate_and_preprocess_csv(csv_bytes, feats)
    assert err is None
    assert fin is not None
    assert len(fin) == len(orig_df)
    for f in feats:
        assert f in fin.columns


def test_validate_and_preprocess_empty_bytes(sample_csv_data):
    _, _, feats = sample_csv_data
    fin, err = validate_and_preprocess_csv(b"", feats)
    assert fin is None
    assert "empty" in err.lower()


def test_validate_and_preprocess_no_data_rows(sample_csv_data):
    _, _, feats = sample_csv_data
    header_only = ",".join(feats).encode("utf-8") + b"\n"
    fin, err = validate_and_preprocess_csv(header_only, feats)
    assert fin is None
    assert "no data rows" in err.lower()


def test_validate_and_preprocess_missing_features(sample_csv_data):
    _, _, feats = sample_csv_data
    incomplete_feats = feats[:-3]
    df = pd.DataFrame({f: [1.0, 2.0] for f in incomplete_feats})
    csv_bytes = df.to_csv(index=False).encode("utf-8")
    fin, err = validate_and_preprocess_csv(csv_bytes, feats)
    assert fin is None
    assert "not found" in err.lower()
    for missing_col in feats[-3:]:
        assert missing_col in err


def test_validate_and_preprocess_abbreviations(sample_csv_data):
    """Test that extractor abbreviations like 'Tot Fwd Pkts' and 'Dst Port' are mapped properly."""
    feats = list(joblib.load("models/feature_cols.joblib"))
    df = pd.DataFrame({f: [10.0] for f in feats})
    if "Total Fwd Packets" in df.columns:
        df = df.rename(columns={"Total Fwd Packets": "Tot Fwd Pkts"})
    if "Destination Port" in df.columns:
        df = df.rename(columns={"Destination Port": "Dst Port"})
    csv_bytes = df.to_csv(index=False).encode("utf-8")
    fin, err = validate_and_preprocess_csv(csv_bytes, feats)
    assert err is None
    assert "Total Fwd Packets" in fin.columns
    assert "Destination Port" in fin.columns


def test_validate_and_preprocess_inf_nan_cleaning(sample_csv_data):
    _, _, feats = sample_csv_data
    df = pd.DataFrame({f: [1.0, np.inf, 3.0] for f in feats})
    df.loc[0, feats[0]] = np.nan  # Row 0 has NaN
    # Row 1 has inf (which becomes NaN)
    # Row 2 is fully valid
    csv_bytes = df.to_csv(index=False).encode("utf-8")
    fin, err = validate_and_preprocess_csv(csv_bytes, feats)
    assert err is None
    assert len(fin) == 1  # Only row 2 survives


def test_rf_feature_selection_and_order(detector_instance, sample_csv_data):
    csv_bytes, _, _ = sample_csv_data
    fin, err = validate_and_preprocess_csv(csv_bytes, detector_instance.all_feats)
    assert err is None

    # Verify prepare_rf_input selects exact RF features in original training order
    X_rf = detector_instance.prepare_rf_input(fin)
    assert isinstance(X_rf, pd.DataFrame)
    assert list(X_rf.columns) == detector_instance.feats
    assert len(X_rf.columns) == 65
    assert len(X_rf.columns) == getattr(detector_instance.clf, "n_features_in_", 65)

    # Verify clf.predict_proba runs cleanly
    proba = detector_instance.clf.predict_proba(X_rf)
    assert proba.shape == (len(fin), len(detector_instance.le.classes_))
    assert np.allclose(proba.sum(axis=1), 1.0)


def test_ae_feature_preparation_and_scaling(detector_instance, sample_csv_data):
    csv_bytes, _, _ = sample_csv_data
    fin, err = validate_and_preprocess_csv(csv_bytes, detector_instance.all_feats)
    assert err is None

    # Verify prepare_ae_input selects exact ae_feats and produces float32 array
    Xa = detector_instance.prepare_ae_input(fin)
    if detector_instance.ae is not None:
        assert isinstance(Xa, np.ndarray)
        assert Xa.dtype == np.float32
        assert Xa.shape == (len(fin), len(detector_instance.ae_feats))
        assert Xa.shape[1] == detector_instance.ae.input_shape[-1]

        # Verify autoencoder reconstruction
        recon = detector_instance.ae(Xa, training=False).numpy()
        assert recon.shape == Xa.shape
        anomaly = np.mean((Xa - recon) ** 2, axis=1) / detector_instance.thr
        assert len(anomaly) == len(fin)
        assert np.all(anomaly >= 0)


def test_detector_predict_pipeline_integration(detector_instance, sample_csv_data):
    csv_bytes, _, _ = sample_csv_data
    fin, err = validate_and_preprocess_csv(csv_bytes, detector_instance.all_feats)
    assert err is None

    out = detector_instance.predict(fin)
    assert len(out) == len(fin)
    for col in [
        "seen_at", "capture_time", "src_ip", "dst_ip", "dst_port",
        "predicted", "confidence", "attack_score", "anomaly_score",
        "uncertainty", "top3", "actual", "family", "severity", "verdict"
    ]:
        assert col in out.columns
    assert set(out.verdict.unique()).issubset({"Genuine", "Suspicious", "Malicious"})


def test_api_upload_endpoint(sample_csv_data):
    csv_bytes, orig_df, _ = sample_csv_data

    # Valid upload
    f_valid = UploadFile(filename="test.csv", file=io.BytesIO(csv_bytes))
    res = asyncio.run(upload(f_valid))
    assert res["ok"] is True
    assert res["queued"] == len(orig_df)

    # Check S["backlog"] has rows and step_locked() processes them
    assert S["source"] == "upload"
    assert len(S["backlog"]) == len(orig_df)
    prev_alerts = len(S["alerts"])
    step_locked()
    assert len(S["alerts"]) > prev_alerts

    # Invalid upload: empty file
    f_empty = UploadFile(filename="empty.csv", file=io.BytesIO(b""))
    res_empty = asyncio.run(upload(f_empty))
    assert res_empty["ok"] is False
    assert "empty" in res_empty["error"].lower()

    # Invalid upload: missing features
    bad_csv = b"col1,col2\n1,2\n"
    f_bad = UploadFile(filename="bad.csv", file=io.BytesIO(bad_csv))
    res_bad = asyncio.run(upload(f_bad))
    assert res_bad["ok"] is False
    assert "not found" in res_bad["error"].lower()


def test_live_flows_csv_file():
    """Verify processing works with the actual live/flows.csv in the project."""
    p = Path("live/flows.csv")
    if p.exists():
        fin, err = validate_and_preprocess_csv(p, FEATS)
        assert err is None
        assert fin is not None
        assert len(fin) > 0
        out = det.predict(fin.head(10))
        assert len(out) == 10
