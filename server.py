"""server.py: FastAPI backend for the HTML/JS dashboard (consolidated version)."""
import asyncio
import datetime as dt
import io
import json
import sys
import threading
from contextlib import asynccontextmanager
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn
from fastapi import FastAPI, File, UploadFile
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sklearn.metrics import precision_recall_fscore_support

import extras
from common import SEV_ORDER, STATUSES, norm_label
from detector import Detector
from feed import CsvTail, align, finish
from forecast import attack_share_series, backtest, holt_forecast, risk_level
from stream import TrafficStream

BASE = Path(__file__).resolve().parent
LIVE_DIR = (BASE / "live").resolve()
TICK_SECONDS = 2                       # one scoring step every 2 s
MAX_ROWS = 20_000                      # alert buffer size
MAX_UPLOAD = 150 * 1024 * 1024         # 150 MB
MAX_UPLOAD_ROWS = 200_000
MAX_BACKLOG = 50_000                  # watch mode stops reading the file while this many rows wait
LOCK = threading.Lock()

det = Detector()
stream = TrafficStream()
FEATS = getattr(det, "all_feats", det.feats)
VERSIONS = f"Python {sys.version.split()[0]} · scikit-learn {sklearn.__version__}"


def _selftest():
    """Agreement between predictions and ground truth on 500 random replay rows."""
    try:
        out = det.predict(stream.df.sample(min(500, len(stream.df)), random_state=0))
        return float((out.actual.map(norm_label).values == out.predicted.map(norm_label).values).mean())
    except Exception:
        return None


SELFTEST = _selftest()


def safe_watch_path(p: str):
    """Only allow .csv files inside the project's live/ folder."""
    cand = Path(p)
    cand = (cand if cand.is_absolute() else BASE / cand).resolve()
    if LIVE_DIR not in cand.parents or cand.suffix.lower() != ".csv":
        return None
    return str(cand)


class Backlog:
    """Rows waiting to be scored. Uses a read cursor, so taking a batch never copies the whole backlog."""

    def __init__(self):
        self.df, self.pos = pd.DataFrame(), 0

    def __len__(self):
        return len(self.df) - self.pos

    def clear(self):
        self.df, self.pos = pd.DataFrame(), 0

    def add(self, rows, replace=False):
        rest = self.df.iloc[self.pos:]
        self.df = rows.reset_index(drop=True) if (replace or rest.empty) else pd.concat([rest, rows], ignore_index=True)
        self.pos = 0

    def take(self, n):
        out = self.df.iloc[self.pos:self.pos + n].copy()
        self.pos += len(out)
        if self.pos >= len(self.df):
            self.clear()
        return out


# All mutable state lives here: one shared session for every browser tab.
# "version" goes up whenever the alert table changes; cached responses are keyed on it.
S = {"alerts": pd.DataFrame(), "next_id": 0, "pos": 0, "live": True, "rate": 20, "version": 0,
     "source": "replay", "backlog": Backlog(), "tail": None,
     "watch_path": str(LIVE_DIR / "flows.csv"), "error": "", "fault": ""}

_CACHE = {}


def memo(name, key, ver, fn):
    """Recompute only when the alert table changed (or the request parameters did)."""
    hit = _CACHE.get((name, key))
    if hit and hit[0] == ver:
        return hit[1]
    val = fn()
    if len(_CACHE) > 32:
        _CACHE.clear()
    _CACHE[(name, key)] = (ver, val)
    return val


def records(df):
    return json.loads(df.to_json(orient="records", date_format="iso"))     # NaN becomes null


# ---------------- request bodies (defined BEFORE the endpoints that use them) ----------------
class Control(BaseModel):
    live: bool | None = None
    rate: int | None = None
    source: str | None = None
    watch_path: str | None = None


class Jump(BaseModel):
    day: str


class Status(BaseModel):
    event_id: int
    status: str


class FF(BaseModel):
    ticks: int = 60


# ---------------- scoring loop ----------------
def step():
    """Ingest and score one batch. Caller holds LOCK."""
    if not S["live"]:
        return
    if S["source"] == "replay":
        batch, S["pos"] = stream.batch(S["pos"], S["rate"])
    else:
        if S["source"] == "watch" and len(S["backlog"]) < MAX_BACKLOG:
            if S["tail"] is None or S["tail"].raw_path != S["watch_path"]:
                S["tail"] = CsvTail(S["watch_path"])
            raw = S["tail"].read_new()
            if raw is not None and len(raw):
                frame, missing = align(raw, FEATS)
                if missing:
                    S["error"] = f"Incoming flows lack {len(missing)} model features, e.g. {missing[:5]}"
                    return
                S["error"] = ""
                S["backlog"].add(finish(frame, FEATS))
        batch = S["backlog"].take(S["rate"])
    if len(batch) == 0:
        return
    new = det.predict(batch)
    new["seen_at"] = pd.Timestamp.now()
    new.insert(0, "event_id", range(S["next_id"], S["next_id"] + len(new)))
    new["status"] = "New"
    S["next_id"] += len(new)
    S["alerts"] = pd.concat([S["alerts"], new], ignore_index=True).tail(MAX_ROWS)
    S["version"] += 1


def step_locked():
    with LOCK:
        step()


async def loop():
    while True:
        try:
            await asyncio.to_thread(step_locked)
            S["fault"] = ""                          # a good tick clears an old scoring error
        except Exception as e:                       # show the problem on the page instead of dying
            S["fault"] = f"{type(e).__name__}: {e}"
        await asyncio.sleep(TICK_SECONDS)


@asynccontextmanager
async def lifespan(app):
    task = asyncio.create_task(loop())
    yield
    task.cancel()


app = FastAPI(lifespan=lifespan)


# ---------------- read endpoints ----------------
@app.get("/api/days")
def days():
    return [d.isoformat() for d in stream.days()]


def _views(df, min_conf, sev, fams):
    """Everything derived from the alert table. Cached per table version and filter."""
    out = {}
    attacks = df[df.family != "Benign"]
    has_ae = bool(df.anomaly_score.notna().any())
    out["kpi"] = {
        "attack_rate": len(attacks) / len(df),
        "open_critical": int(((df.severity == "Critical") & (df.status == "New")).sum()),
        "escalated": int((df.status == "Escalated").sum()),
        "avg_conf": float(df.confidence.mean()),
        "anomalies": int((df.anomaly_score > 1).sum()) if has_ae else None,
    }

    feed_cols = ["event_id", "capture_time", "src_ip", "dst_ip", "dst_port", "verdict", "predicted", "confidence"]
    out["feed"] = records(df.tail(15).iloc[::-1][feed_cols])               # event_id only ever increases

    sevs = [x for x in sev.split(",") if x]
    view = df[(df.confidence >= min_conf) & df.severity.isin(sevs)]
    if fams:
        view = view[view.family.isin(fams.split(","))]
    rank = {s: i for i, s in enumerate(SEV_ORDER)}
    view = (view.assign(_s=view.severity.map(rank))
                .sort_values(["_s", "event_id"], ascending=[True, False]).head(50))
    q_cols = ["event_id", "severity", "status", "predicted", "confidence", "attack_score",
              "anomaly_score", "src_ip", "dst_ip", "dst_port", "top3"]
    out["queue"] = records(view[q_cols])

    tr = (df.groupby([df.seen_at.dt.floor("10s").rename("bucket"), "family"]).size()
            .unstack(fill_value=0).tail(30))
    out["traffic"] = {"labels": [b.strftime("%H:%M:%S") for b in tr.index],
                      "series": {c: [int(v) for v in tr[c]] for c in tr.columns}}
    out["families"] = {k: int(v) for k, v in attacks.family.value_counts().items()}
    out["top_ips"] = [[ip, int(n)] for ip, n in attacks.src_ip.value_counts().head(8).items()]
    out["top_ports"] = [[str(int(p)), int(n)] for p, n in attacks.dst_port.value_counts().head(8).items()]

    score = df.anomaly_score.dropna() if has_ae else df.attack_score
    hi = 3.0 if has_ae else 1.0
    counts, edges = np.histogram(score.clip(0, hi), bins=20, range=(0, hi))
    out["hist"] = {"ae": has_ae, "edges": [round(float(e), 2) for e in edges[:-1]],
                   "counts": [int(c) for c in counts]}

    series = attack_share_series(df)
    if len(series) < 8:
        out["forecast"] = {"ready": False, "buckets": len(series)}
    else:
        y = series["share"].to_numpy()
        _, fc = holt_forecast(y, steps=6)
        err_h, err_n = backtest(y)
        skill = (1 - err_h / err_n) if err_n > 0 else None
        level, trend = risk_level(y, fc)
        recent = attacks[attacks.seen_at >= df.seen_at.max() - pd.Timedelta("60s")]
        top = recent.family.value_counts(normalize=True)
        idx = series.index
        fut = pd.date_range(idx[-1] + pd.Timedelta("10s"), periods=len(fc), freq="10s")
        out["forecast"] = {
            "ready": True, "level": level, "trend": trend,
            "now": float(y[-3:].mean()), "next": float(fc.mean()), "next30": float(fc[:3].mean()),
            "skill": None if skill is None or np.isnan(skill) else float(skill),
            "labels": [x.strftime("%H:%M:%S") for x in list(idx) + list(fut)],
            "observed": [float(v) for v in y], "forecast": [float(v) for v in fc],
            "top_family": None if top.empty else top.index[0],
            "top_family_share": None if top.empty else float(top.iloc[0]),
        }
    return out


@app.get("/api/state")
def state(min_conf: float = 0.0, sev: str = "Critical,High,Medium", fams: str = ""):
    ver = S["version"]                      # read the version BEFORE the table (see memo)
    df = S["alerts"]
    out = {"live": S["live"], "rate": S["rate"], "source": S["source"], "watch_path": S["watch_path"],
           "error": S["fault"] or S["error"], "queued": len(S["backlog"]), "total": S["next_id"],
           "model": type(det.clf).__name__, "autoencoder": det.ae is not None,
           "held_out": bool(getattr(stream, "held_out", False)), "has_data": not df.empty,
           "selftest": SELFTEST, "versions": VERSIONS}
    if df.empty:
        return out
    out.update(memo("views", (min_conf, sev, fams), ver, lambda: _views(df, min_conf, sev, fams)))
    return out


@app.get("/api/alert/{event_id}")
def alert(event_id: int):
    df = S["alerts"]
    row = df[df.event_id == event_id]
    if row.empty:
        return {"found": False}
    r = records(row.iloc[[0]])[0]
    r["found"] = True
    return r


@app.get("/api/health")
def health():
    """Model health against ground truth (replay rows only; live feeds have no labels)."""
    ver = S["version"]
    df = S["alerts"]
    if df.empty:
        return {"ready": False}
    return memo("health", None, ver, lambda: _health(df))


def _health(df):
    lab = df[df.actual != "(unlabelled)"]
    if lab.empty:
        return {"ready": True, "labelled": 0}
    a = lab.actual.map(norm_label)
    p = lab.predicted.map(norm_label)
    classes = sorted(set(a) | set(p))
    prec, rec, _, sup = precision_recall_fscore_support(a, p, labels=classes, zero_division=0)
    cm = pd.crosstab(a, p, normalize="index").reindex(index=classes, columns=classes, fill_value=0.0)
    cal = pd.DataFrame({"bin": pd.cut(lab.confidence, [0, .5, .6, .7, .8, .9, 1.0]).astype(str).values,
                        "correct": (a.values == p.values)})
    cal = cal.groupby("bin", observed=True)["correct"].agg(["mean", "size"]).reset_index()
    return {"ready": True, "labelled": int(len(lab)), "classes": classes,
            "precision": [float(x) for x in prec], "recall": [float(x) for x in rec],
            "support": [int(x) for x in sup], "matrix": cm.values.tolist(),
            "calib": [{"bin": r["bin"], "accuracy": float(r["mean"]), "n": int(r["size"])}
                      for _, r in cal.iterrows()]}


@app.get("/api/export")
def export():
    cols = ["event_id", "seen_at", "capture_time", "src_ip", "dst_ip", "dst_port", "predicted", "verdict",
            "severity", "status", "confidence", "attack_score", "anomaly_score", "top3"]
    df = S["alerts"]
    out = df[cols].copy() if not df.empty else pd.DataFrame(columns=cols)
    for c in ("src_ip", "dst_ip", "predicted", "top3"):          # neutralise spreadsheet formulas
        out[c] = out[c].astype(str).str.replace(r"^([=+\-@])", r"'\1", regex=True)
    return Response(out.to_csv(index=False), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=pids_alerts.csv"})


# ---------------- write endpoints ----------------
@app.post("/api/control")
def control(c: Control):
    if c.source is not None and c.source not in ("replay", "watch", "upload"):
        return {"ok": False, "error": f"Unknown source: {c.source}"}
    safe = None
    if c.watch_path:
        safe = safe_watch_path(c.watch_path)
        if safe is None:
            return {"ok": False, "error": "Only .csv files inside the project's live/ folder are allowed"}
    with LOCK:                              # never change settings in the middle of a scoring step
        if c.live is not None:
            S["live"] = c.live
        if c.rate is not None:
            S["rate"] = max(1, min(500, c.rate))
        if c.source is not None:
            S["source"] = c.source
        if safe is not None:
            S["watch_path"] = safe
    return {"ok": True}


@app.post("/api/jump")
def jump(j: Jump):
    try:
        day = dt.date.fromisoformat(j.day)
    except ValueError:
        return {"ok": False, "error": "Invalid date"}
    if day not in stream.days():
        return {"ok": False, "error": "No replay data for that day"}
    with LOCK:
        S["pos"] = stream.start_of(day)
    return {"ok": True}


@app.post("/api/clear")
def clear():
    with LOCK:
        S["alerts"] = pd.DataFrame()
        S["backlog"].clear()
        S["next_id"], S["error"], S["fault"] = 0, "", ""
        S["version"] += 1
    return {"ok": True}


@app.post("/api/status")
def set_status(s: Status):
    if s.status not in STATUSES:
        return {"ok": False, "error": f"Unknown status: {s.status}"}
    with LOCK:
        df = S["alerts"]
        if not df.empty:
            m = df.event_id == s.event_id
            if m.any():
                df = df.copy()              # copy-on-write: readers keep a consistent table
                df.loc[m, "status"] = s.status
                S["alerts"] = df
                S["version"] += 1
    return {"ok": True}


@app.post("/api/fastforward")
def fastforward(f: FF):
    """Replay mode: score ~2 minutes of traffic at once, so the forecast has history immediately."""
    if S["source"] != "replay":
        return {"ok": False, "error": "Fast-forward works in replay mode only"}
    n_ticks = max(1, min(f.ticks, 180))
    with LOCK:
        S["alerts"] = pd.DataFrame()
        S["backlog"].clear()
        batch, S["pos"] = stream.batch(S["pos"], S["rate"] * n_ticks)
        new = det.predict(batch)
        tick_no = np.arange(len(new)) // max(S["rate"], 1)
        end = pd.Timestamp.now()
        new["seen_at"] = end - pd.to_timedelta((tick_no.max() - tick_no) * TICK_SECONDS, unit="s")
        new.insert(0, "event_id", range(0, len(new)))
        new["status"] = "New"
        S["next_id"] = len(new)
        S["alerts"] = new.tail(MAX_ROWS).reset_index(drop=True)
        S["version"] += 1
    return {"ok": True, "scored": len(new)}


@app.post("/api/upload")
async def upload(file: UploadFile = File(...)):
    data = await file.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        return {"ok": False, "error": "File too large (limit 150 MB). Make a smaller sample."}
    try:
        raw = pd.read_csv(io.BytesIO(data), nrows=MAX_UPLOAD_ROWS, low_memory=False, encoding_errors="replace")
    except Exception:
        return {"ok": False, "error": "Could not read this file as a CSV."}
    frame, missing = align(raw, FEATS)
    if missing:
        return {"ok": False, "error": f"{len(missing)} model features not found in this file, e.g. {missing[:5]}"}
    fin = finish(frame, FEATS)
    with LOCK:
        S["backlog"].add(fin, replace=True)
        S["source"] = "upload"
        S["error"] = ""
    return {"ok": True, "queued": int(len(fin))}


# Extra endpoints (incidents, feature importance). Must be registered BEFORE the static mount below.
extras.ctx.update(S=S, LOCK=LOCK, det=det, stream=stream)
app.include_router(extras.router)

# Must come LAST: it serves the web page at "/"
app.mount("/", StaticFiles(directory=BASE / "static", html=True), name="static")