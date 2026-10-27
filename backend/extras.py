"""extras.py: incident grouping and model-explanation endpoints.
Kept in its own file so server.py only needs to register the router."""
import copy
import threading
import time

import numpy as np
import pandas as pd
from fastapi import APIRouter
from pydantic import BaseModel

from backend.common import SEV_ORDER, STATUSES, family_of

router = APIRouter()
ctx = {}                       # filled in by server.py: S, LOCK, det, stream

RANK = {s: i for i, s in enumerate(SEV_ORDER)}
GAP_SECONDS = 60
_inc_cache = {"ver": None, "payload": None}     # incidents only change when the alert table does


# =============================== incidents ===============================
def _group_status(s):
    u = set(s)
    for k in ("New", "Escalated", "Acknowledged"):
        if k in u:
            return k
    return "False positive"


def _top_label(s):
    return s.value_counts().idxmax()


def build_incidents(df, gap_s=GAP_SECONDS):
    """One row per (source IP, attack family) burst: alerts less than gap_s seconds apart are merged."""
    atk = df[df.family != "Benign"]
    if atk.empty:
        return pd.DataFrame()
    d = atk.sort_values(["src_ip", "family", "seen_at"]).copy()
    prev = d.groupby(["src_ip", "family"])["seen_at"].shift()
    d["inc"] = (prev.isna() | ((d["seen_at"] - prev).dt.total_seconds() > gap_s)).cumsum()
    d["sev_rank"] = d["severity"].map(RANK).fillna(len(SEV_ORDER) - 1)
    g = d.groupby("inc")
    out = g.agg(src_ip=("src_ip", "first"), family=("family", "first"), n=("event_id", "size"),
                first_id=("event_id", "min"), last_id=("event_id", "max"),
                first_seen=("seen_at", "min"), last_seen=("seen_at", "max"),
                sev_rank=("sev_rank", "min"), mean_conf=("confidence", "mean"),
                dst_ips=("dst_ip", "nunique"), dst_ports=("dst_port", "nunique"))
    out["label"] = g["predicted"].agg(_top_label)
    out["status"] = g["status"].agg(_group_status)
    out["severity"] = out["sev_rank"].astype(int).map(lambda r: SEV_ORDER[min(r, len(SEV_ORDER) - 1)])
    out["duration_s"] = (out["last_seen"] - out["first_seen"]).dt.total_seconds()
    return out.sort_values(["sev_rank", "last_seen"], ascending=[True, False]).reset_index(drop=True)


def _incident_payload(df):
    inc = build_incidents(df) if not df.empty else pd.DataFrame()
    if inc.empty:
        return {"alerts_total": 0, "incidents_total": 0, "incidents": []}
    rows = []
    for r in inc.head(100).itertuples():
        rows.append({
            "src_ip": str(r.src_ip), "family": str(r.family), "label": str(r.label), "n": int(r.n),
            "first_id": int(r.first_id), "last_id": int(r.last_id),
            "first": r.first_seen.strftime("%H:%M:%S"), "last": r.last_seen.strftime("%H:%M:%S"),
            "duration_s": float(r.duration_s), "severity": r.severity, "status": r.status,
            "mean_conf": float(r.mean_conf), "dst_ips": int(r.dst_ips), "dst_ports": int(r.dst_ports)})
    return {"alerts_total": int(inc["n"].sum()), "incidents_total": int(len(inc)), "incidents": rows}


@router.get("/api/incidents")
def incidents():
    S = ctx["S"]
    ver = S["version"]                      # read the version BEFORE the table, so a stale cache can't outlive a change
    df = S["alerts"]
    if _inc_cache["ver"] != ver:
        _inc_cache.update(ver=ver, payload=_incident_payload(df))
    return _inc_cache["payload"]


class IncidentStatus(BaseModel):
    src_ip: str
    family: str
    first_id: int
    last_id: int
    status: str


@router.post("/api/incident/status")
def incident_status(b: IncidentStatus):
    if b.status not in STATUSES:
        return {"ok": False, "error": f"Unknown status: {b.status}"}
    S = ctx["S"]
    with ctx["LOCK"]:
        df = S["alerts"]
        if df.empty:
            return {"ok": True, "updated": 0}
        m = (df.src_ip == b.src_ip) & (df.family == b.family) & df.event_id.between(b.first_id, b.last_id)
        if m.any():
            df = df.copy()                  # copy-on-write: readers keep a consistent table
            df.loc[m, "status"] = b.status
            S["alerts"] = df
            S["version"] += 1
    return {"ok": True, "updated": int(m.sum())}


# ============================ model explanation ============================
_state = {"status": "idle", "result": None, "error": "", "seconds": None, "progress": None, "cancel": False}
_run_lock = threading.Lock()    # makes "check not running, then start" a single step


def _class_names():
    det = ctx["det"]
    names = getattr(det, "class_names", None)
    if names is None:
        names = getattr(getattr(det, "le", None), "classes_", [])
    return [str(c) for c in names]


def _top(vals, feats, k=10):
    vals = np.asarray(vals, dtype=float)
    order = np.argsort(-vals)[:k]
    total = float(vals.sum()) or 1.0
    return [{"feature": str(feats[i]), "share": float(vals[i] / total)} for i in order]


def _builtin(k=10):
    det = ctx["det"]
    imp = getattr(det.clf, "feature_importances_", None)
    if imp is None or len(imp) != len(det.feats):
        return None
    return _top(imp, list(det.feats), k)


def _prepare(det, stream, n_total):
    """Attack-only, class-balanced sample, in the representation the classifier receives."""
    feats = list(det.feats)
    df = stream.df
    is_attack = {lab: family_of(lab) != "Benign" for lab in df["Label"].unique()}
    atk = df[df["Label"].map(is_attack)]
    if atk.empty:
        raise ValueError("The replay file has no attack rows.")
    n_labels = max(1, atk["Label"].nunique())
    per = max(2, -(-n_total // n_labels))                                   # ceiling division
    samp = pd.concat([g.sample(min(len(g), per), random_state=0) for _, g in atk.groupby("Label")])
    pre = getattr(det, "pre", None)

    def rep(frame):
        raw = frame[feats].replace([np.inf, -np.inf], np.nan).fillna(0.0)
        return np.asarray(pre.transform(raw.values) if pre is not None else raw.values, dtype=np.float64)

    return feats, samp, rep


def _as_3d(sv):
    """Newer SHAP returns one array (samples, features, outputs); older versions return a list per output."""
    arr = np.stack([np.asarray(a) for a in sv], axis=-1) if isinstance(sv, list) else np.asarray(sv)
    return arr[..., None] if arr.ndim == 2 else arr


def _attack_columns(n_outputs):
    names = _class_names()
    keep = [i for i in range(n_outputs) if i < len(names) and family_of(names[i]) != "Benign"]
    if not keep:
        raise ValueError("No attack classes found among the model's classes.")
    return keep, [names[i] for i in keep]


def _kernel(shap, opt, t0):
    det, stream = ctx["det"], ctx["stream"]
    feats, samp, rep = _prepare(det, stream, opt["n"])
    X = rep(samp)

    # background: typical BENIGN flows, summarised to 10 weighted points
    df = stream.df
    ben = df[df["Label"].map(lambda lab: family_of(lab) == "Benign")]
    Xb = rep(ben.sample(min(len(ben), 300), random_state=1))
    try:
        bg = shap.kmeans(Xb, 10)
    except Exception:
        bg = shap.sample(Xb, 10, random_state=0)

    model = copy.copy(det.clf)                                              # own copy: more threads here, scoring unaffected
    if hasattr(model, "n_jobs"):
        model.n_jobs = -1
    keep, att_names = _attack_columns(len(getattr(model, "classes_", _class_names())))
    names_in = getattr(model, "feature_names_in_", None)

    def f(A):
        A = np.asarray(A, dtype=np.float64)
        inp = (pd.DataFrame(A, columns=list(names_in))
               if names_in is not None and len(names_in) == A.shape[1] else A)
        return model.predict_proba(inp)[:, keep]                            # attack-class probabilities only

    explainer = shap.KernelExplainer(f, bg)
    rows = []
    for i in range(len(X)):
        if _state["cancel"] or time.time() - t0 > opt["budget"]:
            break
        sv = explainer.shap_values(X[i:i + 1], nsamples=opt["nsamples"], silent=True)
        rows.append(_as_3d(sv)[0])                                          # (features, attack classes)
        _state["progress"] = {"done": i + 1, "total": len(X)}
    if not rows:
        raise RuntimeError("Stopped before the first flow finished. Raise the time limit or lower the evaluations.")
    return feats, np.stack(rows, axis=0), att_names, len(rows), len(X)


def _tree(shap, opt, t0):
    det, stream = ctx["det"], ctx["stream"]
    feats, samp, rep = _prepare(det, stream, opt["n"])
    X = rep(samp)
    names_in = getattr(det.clf, "feature_names_in_", None)
    X_in = pd.DataFrame(X, columns=list(names_in)) if names_in is not None and len(names_in) == X.shape[1] else X
    explainer = shap.TreeExplainer(det.clf, feature_perturbation="tree_path_dependent")
    arr = _as_3d(explainer.shap_values(X_in, check_additivity=False, tree_limit=(opt["trees"] or None)))
    keep, att_names = _attack_columns(arr.shape[2])
    return feats, arr[:, :, keep], att_names, len(X), len(X)


def _worker(opt):
    t0 = time.time()
    try:
        import shap
    except ImportError:
        _state.update(status="error", error="SHAP is not installed. Run: pip install shap")
        return
    try:
        run = _kernel if opt["method"] == "kernel" else _tree
        feats, arr, att_names, done, total = run(shap, opt, t0)
        per_class = {nm: _top(np.abs(arr[:, :, k]).mean(axis=0), feats) for k, nm in enumerate(att_names)}
        glob = np.abs(arr).mean(axis=(0, 2))
        _state.update(status="done", error="", seconds=round(time.time() - t0, 1), progress=None,
                      result={"global": _top(glob, feats), "per_class": per_class, "method": opt["method"],
                              "n": int(done), "planned": int(total), "partial": bool(done < total),
                              "nsamples": opt["nsamples"], "trees": opt["trees"]})
    except Exception as e:
        _state.update(status="error", error=f"{type(e).__name__}: {e}", progress=None)


class ExplainReq(BaseModel):
    method: str = "kernel"        # "kernel" or "tree"
    n: int = 40                   # flows to explain
    trees: int = 0                # tree method only: 0 = whole forest
    nsamples: int = 500           # kernel method only: evaluations per flow
    budget: int = 120             # kernel method only: time limit in seconds


@router.post("/api/explain/run")
def explain_run(r: ExplainReq):
    method = r.method if r.method in ("kernel", "tree") else "kernel"
    opt = {"method": method,
           "n": max(10, min(r.n, 100 if method == "kernel" else 300)),
           "trees": max(0, min(r.trees, 1000)),
           "nsamples": max(100, min(r.nsamples, 3000)),
           "budget": max(30, min(r.budget, 900))}
    with _run_lock:
        if _state["status"] == "running":
            return {"ok": False, "error": "Already running"}
        _state.update(status="running", error="", result=None, seconds=None, progress=None, cancel=False)
    threading.Thread(target=_worker, args=(opt,), daemon=True).start()
    return {"ok": True}


@router.post("/api/explain/cancel")
def explain_cancel():
    _state["cancel"] = True
    return {"ok": True}


@router.get("/api/explain")
def explain_get():
    return {"builtin": _builtin(), "status": _state["status"], "error": _state["error"],
            "seconds": _state["seconds"], "progress": _state["progress"], "shap": _state["result"]}