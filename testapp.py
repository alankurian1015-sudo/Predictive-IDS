"""Tests that need no trained models: run `pytest -q` from the project folder.
The detector and the replay stream are replaced by small fakes, so this checks the plumbing
(caching, locking, status updates, incidents, backlog) rather than model quality."""
import sys
import types
from datetime import date

import numpy as np
import pandas as pd
import pytest

from common import family_of, norm_label, severity
from feed import CsvTail, align, finish
from forecast import attack_share_series, backtest, holt_forecast, risk_level

LABELS = ["BENIGN", "DDoS", "PortScan", "SSH-Patator", "Bot"]


class FakeDetector:
    class clf:                                     # only the class name is shown on the page
        pass
    ae = None
    feats = all_feats = ["f1", "f2"]

    def predict(self, batch):
        from common import family_of, severity
        rng = np.random.default_rng(len(batch))
        pred = np.array(LABELS)[rng.integers(0, len(LABELS), len(batch))]
        conf = rng.uniform(0.5, 1.0, len(batch))
        out = pd.DataFrame({
            "seen_at": pd.Timestamp.now(), "capture_time": batch["Timestamp"].values,
            "src_ip": batch["Source IP"].values, "dst_ip": batch["Destination IP"].values,
            "dst_port": batch["Destination Port"].astype(int).values, "predicted": pred,
            "confidence": conf, "attack_score": np.where(pred == "BENIGN", 0.05, 0.95),
            "anomaly_score": np.nan, "uncertainty": 0.1, "top3": "x 0.9 | y 0.1 | z 0.0",
            "actual": batch["Label"].values})
        out["family"] = [family_of(p) for p in out.predicted]
        out["severity"] = [severity(p, c, a, z) for p, c, a, z in
                           zip(out.predicted, out.confidence, out.attack_score, out.anomaly_score)]
        out["verdict"] = np.where(out.family != "Benign", "Malicious", "Genuine")
        return out


class FakeStream:
    held_out = True

    def __init__(self):
        n = 5000
        rng = np.random.default_rng(0)
        self.df = pd.DataFrame({
            "Timestamp": pd.date_range("2017-07-03 09:00", periods=n, freq="1s"),
            "Source IP": rng.choice(["10.0.0.1", "10.0.0.2", "10.0.0.3"], n),
            "Destination IP": "192.168.0.5", "Destination Port": rng.choice([22, 80, 443], n),
            "Label": rng.choice(LABELS, n), "f1": 1.0, "f2": 2.0})

    def days(self):
        return [date(2017, 7, 3)]

    def start_of(self, day):
        return 0

    def batch(self, pos, n):
        pos %= len(self.df)
        chunk = self.df.iloc[pos:pos + n].copy()
        return chunk, pos + len(chunk)


@pytest.fixture()
def srv(monkeypatch):
    monkeypatch.setitem(sys.modules, "detector", types.SimpleNamespace(Detector=FakeDetector))
    monkeypatch.setitem(sys.modules, "stream", types.SimpleNamespace(TrafficStream=FakeStream))
    for m in ("server", "extras"):
        sys.modules.pop(m, None)
    import server
    from fastapi.testclient import TestClient
    server.SELFTEST = None
    return server, TestClient(server.app)          # no `with`: the background loop stays off, tests call step() themselves


# ---------------- unit tests ----------------
def test_labels_and_severity():
    assert family_of("Web Attack \ufffd XSS") == "Web attack"
    assert family_of("DoS Hulk") == "DoS/DDoS" and family_of("PortScan") == "Recon"
    assert norm_label("Web Attack - Brute Force") == "web attack brute force"
    assert severity("Heartbleed", 0.9) == "Critical"
    assert severity("BENIGN", 0.8, 0.5) == "Medium"          # classifier says benign, attack score disagrees
    assert severity("BENIGN", 0.8, 0.0, float("nan")) == "Info"
    assert severity("DDoS", 0.99, 0.99, float("nan")) == "High"


def test_forecast_rises_on_ramp():
    y = np.r_[np.full(10, 0.10), np.linspace(0.10, 0.60, 10)]
    _, fc = holt_forecast(y)
    assert fc.min() >= 0 and fc.max() <= 1
    err_h, err_n = backtest(y)
    assert err_h <= err_n
    assert risk_level(y, fc)[1] == "Rising"


def test_attack_share_series_does_not_mutate_input():
    df = pd.DataFrame({"seen_at": pd.date_range("2026-01-01", periods=100, freq="1s"),
                       "family": ["Benign", "DoS/DDoS"] * 50})
    before = df.copy()
    s = attack_share_series(df)
    assert list(df.columns) == list(before.columns) and 0 <= s.share.min() <= s.share.max() <= 1


def test_align_renames_abbreviations():
    raw = pd.DataFrame({"Src IP": ["1.1.1.1"], "Dst Port": [80], "Tot Fwd Pkts": [3]})
    df, missing = align(raw, ["Total Fwd Packets", "Flow Duration"])
    assert "Total Fwd Packets" in df.columns and missing == ["Flow Duration"]


def test_csvtail_reads_only_complete_new_lines_and_strips_bom(tmp_path):
    p = tmp_path / "flows.csv"
    p.write_bytes("\ufeffa,b\n1,2\n3,".encode("utf-8"))          # BOM + a half-written last line
    t = CsvTail(str(p))
    first = t.read_new()
    assert list(first.columns) == ["a", "b"] and len(first) == 1
    with open(p, "ab") as f:
        f.write(b"4\n")
    second = t.read_new()
    assert second.iloc[0].tolist() == [3, 4]


# ---------------- plumbing tests ----------------
def test_backlog_cursor(srv):
    server, _ = srv
    b = server.Backlog()
    b.add(pd.DataFrame({"x": range(10)}))
    assert len(b) == 10 and list(b.take(4).x) == [0, 1, 2, 3] and len(b) == 6
    b.add(pd.DataFrame({"x": [99]}))
    assert len(b) == 7 and list(b.take(100).x) == [4, 5, 6, 7, 8, 9, 99] and len(b) == 0


def test_state_cache_invalidates_on_status_change(srv):
    server, c = srv
    for _ in range(40):
        server.step_locked()
    a = c.get("/api/state").json()
    assert a["has_data"] and a["total"] == 40 * server.S["rate"]
    ver = server.S["version"]
    assert c.get("/api/state").json()["kpi"] == a["kpi"]            # served from cache
    eid = a["queue"][0]["event_id"]
    assert c.post("/api/status", json={"event_id": eid, "status": "Escalated"}).json()["ok"]
    assert server.S["version"] == ver + 1
    assert c.get("/api/state").json()["kpi"]["escalated"] == a["kpi"]["escalated"] + 1
    assert c.post("/api/status", json={"event_id": eid, "status": "Bogus"}).json()["ok"] is False


def test_incidents_and_status(srv):
    server, c = srv
    for _ in range(40):
        server.step_locked()
    inc = c.get("/api/incidents").json()
    assert inc["incidents_total"] > 0 and inc["alerts_total"] >= inc["incidents_total"]
    r = inc["incidents"][0]
    body = {k: r[k] for k in ("src_ip", "family", "first_id", "last_id")} | {"status": "Acknowledged"}
    assert c.post("/api/incident/status", json=body).json()["updated"] >= 1
    assert c.get("/api/incidents").json()["incidents"][0]["status"] in ("Acknowledged", "New", "Escalated")
    body["status"] = "nope"
    assert c.post("/api/incident/status", json=body).json()["ok"] is False


def test_control_jump_validation(srv):
    _, c = srv
    assert c.post("/api/control", json={"source": "carrier-pigeon"}).json()["ok"] is False
    assert c.post("/api/control", json={"watch_path": "../../etc/passwd"}).json()["ok"] is False
    assert c.post("/api/control", json={"rate": 9999}).json()["ok"] is True
    assert c.post("/api/jump", json={"day": "not-a-date"}).json()["ok"] is False
    assert c.post("/api/jump", json={"day": "1999-01-01"}).json()["ok"] is False
    assert c.post("/api/jump", json={"day": "2017-07-03"}).json()["ok"] is True


def test_fastforward_clear_health_export(srv):
    server, c = srv
    assert c.post("/api/fastforward", json={"ticks": 60}).json()["ok"]
    assert c.get("/api/state").json()["forecast"]["ready"]
    assert c.get("/api/health").json()["labelled"] > 0
    assert c.get("/api/export").text.startswith("event_id,")
    c.post("/api/clear", json={})
    assert c.get("/api/state").json()["has_data"] is False