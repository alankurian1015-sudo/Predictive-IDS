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

def predict_next_attack(family, label, top_port, n_ports, count):
    """
    Predicts the adversary's next likely attack stage, probability, estimated time window,
    and proactive SOC countermeasure based on MITRE ATT&CK / Kill-Chain progression.
    Standard MITRE ATT&CK stages:
    1: Reconnaissance
    2: Initial Access
    3: Exploitation
    4: Lateral Movement & C2
    5: Impact & Exfiltration
    """
    fam = str(family or "").strip()
    lab = str(label or "").lower()
    try:
        port = int(top_port or 0)
    except (ValueError, TypeError):
        port = 0
    n_ports = int(n_ports or 1)

    # 1. Reconnaissance (PortScan / Network Sweep)
    if fam == "Recon" or "scan" in lab:
        if port in (22, 2222):
            return {
                "stage": "Reconnaissance",
                "stage_num": 1,
                "next_stage": "Initial Access",
                "next_stage_num": 2,
                "next_vector": "SSH Brute Force",
                "confidence": 0.84,
                "eta": "60–120s",
                "action": "Preemptively rate-limit Port 22 and monitor SSH auth log."
            }
        elif port in (21, 20):
            return {
                "stage": "Reconnaissance",
                "stage_num": 1,
                "next_stage": "Initial Access",
                "next_stage_num": 2,
                "next_vector": "FTP Brute Force",
                "confidence": 0.81,
                "eta": "60–120s",
                "action": "Disable anonymous FTP; block source IP on Port 21."
            }
        elif port in (80, 443, 8080, 8443):
            return {
                "stage": "Reconnaissance",
                "stage_num": 1,
                "next_stage": "Exploitation",
                "next_stage_num": 3,
                "next_vector": "Web Exploit / DoS",
                "confidence": 0.79,
                "eta": "90–180s",
                "action": "Inspect HTTP requests; enforce WAF rate-limiting."
            }
        elif n_ports > 10:
            return {
                "stage": "Reconnaissance",
                "stage_num": 1,
                "next_stage": "Impact & Exfiltration",
                "next_stage_num": 5,
                "next_vector": "Volumetric DoS Flood",
                "confidence": 0.76,
                "eta": "45–90s",
                "action": "Broad sweep detected; prepare edge Anycast/scrubbing filters."
            }
        else:
            return {
                "stage": "Reconnaissance",
                "stage_num": 1,
                "next_stage": "Initial Access",
                "next_stage_num": 2,
                "next_vector": "Targeted Service Probe",
                "confidence": 0.72,
                "eta": "60–150s",
                "action": "Isolate targeted ports and monitor connection states."
            }

    # 2. Credential Access / Brute Force (SSH-Patator, FTP-Patator)
    elif fam == "Brute force" or "patator" in lab:
        return {
            "stage": "Initial Access",
            "stage_num": 2,
            "next_stage": "Exploitation",
            "next_stage_num": 3,
            "next_vector": "Infiltration / C2 Staging",
            "confidence": 0.82,
            "eta": "2–5 min",
            "action": "Enforce MFA lockouts; terminate active sessions from this IP."
        }

    # 3. Web Attacks (SQL Injection, XSS, Command Injection)
    elif fam == "Web attack" or "sql" in lab or "xss" in lab:
        return {
            "stage": "Exploitation",
            "stage_num": 3,
            "next_stage": "Impact & Exfiltration",
            "next_stage_num": 5,
            "next_vector": "Data Exfiltration / Shell",
            "confidence": 0.78,
            "eta": "1–3 min",
            "action": "Sanitize backend queries; inspect outbound traffic volume for exfiltration."
        }

    # 4. Denial of Service (DoS / DDoS)
    elif fam == "DoS/DDoS" or "dos" in lab:
        return {
            "stage": "Impact & Exfiltration",
            "stage_num": 5,
            "next_stage": "Impact & Exfiltration",
            "next_stage_num": 5,
            "next_vector": "Secondary Multi-Vector Surge",
            "confidence": 0.86,
            "eta": "30–60s",
            "action": "Activate SYN cookies; scale server replica pools."
        }

    # 5. Botnet / Command & Control
    elif fam == "Botnet" or "bot" in lab:
        return {
            "stage": "Lateral Movement & C2",
            "stage_num": 4,
            "next_stage": "Impact & Exfiltration",
            "next_stage_num": 5,
            "next_vector": "Coordinated DDoS Attack",
            "confidence": 0.89,
            "eta": "30–90s",
            "action": "Quarantine host immediately; sinkhole outbound C2 domains."
        }

    # 6. Infiltration / Exploits (Heartbleed, etc.)
    elif fam in ("Infiltration", "Exploit") or "heartbleed" in lab:
        return {
            "stage": "Lateral Movement & C2",
            "stage_num": 4,
            "next_stage": "Impact & Exfiltration",
            "next_stage_num": 5,
            "next_vector": "Privilege Escalation / Pivot",
            "confidence": 0.83,
            "eta": "2–4 min",
            "action": "Revoke internal access tokens; segment VLAN."
        }

    # Default fallback
    return {
        "stage": "Reconnaissance",
        "stage_num": 1,
        "next_stage": "Initial Access",
        "next_stage_num": 2,
        "next_vector": "Follow-up Probe",
        "confidence": 0.65,
        "eta": "1–3 min",
        "action": "Monitor flow stream for repeated pattern variations."
    }



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

    def _top_port(s):
        vc = s.value_counts()
        return int(vc.index[0]) if not vc.empty else 0

    out["top_dst_port"] = g["dst_port"].agg(_top_port)
    return out.sort_values(["sev_rank", "last_seen"], ascending=[True, False]).reset_index(drop=True)


def _incident_payload(df):
    inc = build_incidents(df) if not df.empty else pd.DataFrame()
    if inc.empty:
        return {"alerts_total": 0, "incidents_total": 0, "incidents": []}
    rows = []
    for r in inc.head(100).itertuples():
        pred = predict_next_attack(r.family, r.label, getattr(r, "top_dst_port", 0), r.dst_ports, r.n)
        rows.append({
            "src_ip": str(r.src_ip), "family": str(r.family), "label": str(r.label), "n": int(r.n),
            "first_id": int(r.first_id), "last_id": int(r.last_id),
            "first": r.first_seen.strftime("%H:%M:%S"), "last": r.last_seen.strftime("%H:%M:%S"),
            "duration_s": float(r.duration_s), "severity": r.severity, "status": r.status,
            "mean_conf": float(r.mean_conf), "dst_ips": int(r.dst_ips), "dst_ports": int(r.dst_ports),
            "prediction": pred})
    stage_counts = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
    for r in rows:
        sn = int(r.get("prediction", {}).get("stage_num", 1))
        stage_counts[sn] = stage_counts.get(sn, 0) + 1

    stage_summary = [
        {"num": 1, "name": "Reconnaissance", "short": "Recon", "count": stage_counts.get(1, 0)},
        {"num": 2, "name": "Initial Access", "short": "Access", "count": stage_counts.get(2, 0)},
        {"num": 3, "name": "Exploitation", "short": "Exploit", "count": stage_counts.get(3, 0)},
        {"num": 4, "name": "Lateral Movement & C2", "short": "Lateral/C2", "count": stage_counts.get(4, 0)},
        {"num": 5, "name": "Impact & Exfiltration", "short": "Impact", "count": stage_counts.get(5, 0)},
    ]
    return {
        "alerts_total": int(inc["n"].sum()),
        "incidents_total": int(len(inc)),
        "stage_summary": stage_summary,
        "incidents": rows
    }


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
    notify = ctx.get("notify_ws")
    if notify:
        notify()
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