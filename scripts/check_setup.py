import os

from backend.common import family_of, norm_label
from backend.detector import Detector
from backend.stream import TrafficStream

print("== Files ==")
for p in ["models/label_encoder.joblib", "models/feature_cols.joblib", "data/test_stream.parquet"]:
    print(("OK       " if os.path.exists(p) else "MISSING  ") + p)
for p in ["models/xgb.joblib", "models/xgb.json", "models/autoencoder.keras",
          "models/ae_threshold.joblib", "models/preprocessor.joblib", "models/ae_preprocessor.joblib"]:
    print(("found    " if os.path.exists(p) else "not found") + "  " + p)

det = Detector()
stream = TrafficStream()
print(f"\n== Stream ==\nrows: {len(stream.df):,}   days: {[str(d) for d in stream.days()]}")
print("held out from training:", stream.held_out)

print("\n== Labels ==")
print("classes:", list(det.le.classes_))
print("not mapped to a family:", [c for c in det.le.classes_ if family_of(c) == "Other"] or "none")

missing = [c for c in det.all_feats if c not in stream.df.columns]
print("\n== Features ==\nmissing from stream file:", missing or "none")

print("\n== Autoencoder ==")
if det.ae is None:
    print("not loaded (dashboard will run with attack score only)")
else:
    print("input size:", det.ae.input_shape[-1], "| features:", len(det.all_feats), "| threshold:", det.thr)

print("\n== Sanity check on 500 random stream rows ==")
sample = stream.df.sample(min(500, len(stream.df)), random_state=0)
out = det.predict(sample)
a, p = out.actual.map(norm_label).values, out.predicted.map(norm_label).values
print(out[["predicted", "confidence", "attack_score", "anomaly_score", "severity"]].head())
print(f"agreement with ground truth: {(a == p).mean():.1%}")
if det.ae is not None:
    benign = out.actual.map(norm_label) == "benign"
    print(f"autoencoder flags {(out.anomaly_score[benign] > 1).mean():.1%} of benign and "
          f"{(out.anomaly_score[~benign] > 1).mean():.1%} of attacks")