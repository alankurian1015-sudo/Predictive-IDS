import os
from datetime import datetime

import joblib
import numpy as np
import pandas as pd

from backend.common import clip10, family_of, severity  # clip10 import lets joblib unpickle


class Detector:
    def __init__(self, model_dir="models"):
        self.dir = model_dir
        self.clf = self._load_xgb()
        if hasattr(self.clf, "n_jobs"):
            self.clf.n_jobs = 1          # tiny batches: parallelism only adds overhead
        self.le = joblib.load(f"{model_dir}/label_encoder.joblib")
        self.feats = list(joblib.load(f"{model_dir}/feature_cols.joblib"))
        n_in = getattr(self.clf, "n_features_in_", None)
        if n_in is not None and n_in != len(self.feats):
            raise ValueError(f"The classifier expects {n_in} columns but models/feature_cols.joblib lists "
                             f"{len(self.feats)}. The feature list must come from the same training run as the model.")
        ae_f = self._optional("ae_feature_cols.joblib")
        self.ae_feats = [str(c).strip() for c in ae_f] if ae_f is not None else list(self.feats)
        self.all_feats = list(dict.fromkeys(self.feats + self.ae_feats))

        # If XGBoost was trained on a DataFrame, reuse its original column names
        names = getattr(self.clf, "feature_names_in_", None)
        if names is None and hasattr(self.clf, "get_booster"):     # only XGBoost has a booster
            b = self.clf.get_booster().feature_names
            names = b if b and not all(str(n).startswith("f") and str(n)[1:].isdigit() for n in b) else None
        self.model_names = list(names) if names is not None else None

        self.pre = self._optional("preprocessor.joblib")             # what XGBoost saw (None = raw features)
        ae_pre = self._optional("ae_preprocessor.joblib")            # what the autoencoder saw
        self.ae_pre = ae_pre if ae_pre is not None else (self.pre if self.ae_feats == self.feats else None)

        class_names = [str(c).strip().upper() for c in self.le.classes_]
        self.benign_idx = class_names.index("BENIGN")

        # Autoencoder is optional
        self.ae, self.thr = None, None
        for fname in ("autoencoder.keras", "autoencoder.h5"):
            path = f"{model_dir}/{fname}"
            if os.path.exists(path):
                from tensorflow import keras
                self.ae = keras.models.load_model(path, compile=False)
                break
        if self.ae is not None:
            thr_path = f"{model_dir}/ae_threshold.joblib"
            if not os.path.exists(thr_path):
                raise FileNotFoundError("Autoencoder found but models/ae_threshold.joblib is missing")
            self.thr = float(joblib.load(thr_path))
            if self.ae.input_shape[-1] != len(self.ae_feats):
                raise ValueError(f"Autoencoder expects {self.ae.input_shape[-1]} inputs but "
                                 f"the autoencoder feature list has {len(self.ae_feats)}")

    def _optional(self, fname):
        p = f"{self.dir}/{fname}"
        return joblib.load(p) if os.path.exists(p) else None

    def _load_xgb(self):
        """Loads the classifier: a Random Forest if one exists, otherwise XGBoost."""
        import glob
        d = self.dir
        pinned = os.environ.get("PIDS_MODEL")            # e.g. PIDS_MODEL=rf.joblib pins the classifier file
        if pinned:
            m = joblib.load(os.path.join(d, pinned))
            print("classifier file (pinned):", pinned, "|", type(m).__name__)
            return m
        skip = ("label_encoder", "feature_cols", "ae_", "preprocessor", "threshold")
        found = []
        for path in sorted(glob.glob(f"{d}/*.joblib")):
            if any(s in os.path.basename(path).lower() for s in skip):
                continue
            try:
                m = joblib.load(path)
            except Exception as e:
                print(f"could not load {os.path.basename(path)}: {str(e)[:120]}")
                continue
            if hasattr(m, "predict_proba") and hasattr(m, "classes_"):
                found.append((path, m))
        forests = [(p, m) for p, m in found if "forest" in type(m).__name__.lower()]
        chosen = forests or found
        if chosen:
            print("classifier file:", os.path.basename(chosen[0][0]), "|", type(chosen[0][1]).__name__)
            if len(chosen) > 1:
                print("  WARNING: several classifiers matched:", [os.path.basename(p) for p, _ in chosen],
                      "- using the first. Set PIDS_MODEL=<file> to choose explicitly.")
            return chosen[0][1]

        from xgboost import XGBClassifier
        for ext in ("json", "ubj"):
            if os.path.exists(f"{d}/xgb.{ext}"):
                m = XGBClassifier()
                m.load_model(f"{d}/xgb.{ext}")
                return m
        raise FileNotFoundError("No classifier found in models/")

    def _xgb_input(self, arr):
        return pd.DataFrame(arr, columns=self.model_names) if self.model_names else arr

    def predict(self, batch: pd.DataFrame) -> pd.DataFrame:
        raw = batch[self.all_feats].replace([np.inf, -np.inf], np.nan)

        # --- XGBoost: attack type + confidence ---
        X = self.pre.transform(raw.values) if self.pre is not None else raw.values
        proba = self.clf.predict_proba(self._xgb_input(X))
        names = self.le.classes_
        if proba.shape[1] != len(names):
            raise ValueError(f"XGBoost outputs {proba.shape[1]} classes but label_encoder has "
                             f"{len(names)}. They must come from the same training run.")
        order = np.argsort(-proba, axis=1)[:, :3]
        predicted = names[order[:, 0]]
        conf = proba.max(axis=1)
        attack_score = 1.0 - proba[:, self.benign_idx]
        uncertainty = -(proba * np.log(proba + 1e-12)).sum(axis=1) / np.log(proba.shape[1])
        top_p = np.take_along_axis(proba, order, axis=1)
        top_n = names[order]
        top3 = [" | ".join(f"{n} {p:.2f}" for n, p in zip(rn, rp)) for rn, rp in zip(top_n, top_p)]

        # --- Autoencoder (optional): anomaly score, 1.0 = threshold ---
        anomaly = np.full(len(raw), np.nan)
        if self.ae is not None:
            Xa = self.ae_pre.transform(raw.values) if self.ae_pre is not None else raw.values
            Xa = np.asarray(Xa, dtype="float32")
            recon = self.ae(Xa, training=False).numpy()
            anomaly = np.mean((Xa - recon) ** 2, axis=1) / self.thr

        out = pd.DataFrame({
            "seen_at": datetime.now(),
            "capture_time": batch["Timestamp"].values,
            "src_ip": batch["Source IP"].values,
            "dst_ip": batch["Destination IP"].values,
            "dst_port": pd.to_numeric(batch["Destination Port"], errors="coerce").fillna(0).astype(int).values,
            "predicted": predicted,
            "confidence": conf,
            "attack_score": attack_score,
            "anomaly_score": anomaly,
            "uncertainty": uncertainty,
            "top3": top3,
            "actual": batch["Label"].values,   # ground truth: available only because this is a replay
        })
        out["family"] = [family_of(p) for p in out.predicted]
        out["severity"] = [severity(p, c, a, z) for p, c, a, z in
                           zip(out.predicted, out.confidence, out.attack_score, out.anomaly_score)]
        # Genuine / Malicious / Suspicious flag (benign + Medium = the signals disagree)
        out["verdict"] = np.select([out.family != "Benign", out.severity == "Medium"],
                                   ["Malicious", "Suspicious"], default="Genuine")
        return out