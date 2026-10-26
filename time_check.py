import time

from detector import Detector
from stream import TrafficStream

det, strm = Detector(), TrafficStream()
batch = strm.df.sample(20, random_state=0)


def clock(label, fn, n=5):
    fn()                                              # warm-up call
    t = time.perf_counter()
    for _ in range(n):
        fn()
    ms = (time.perf_counter() - t) / n * 1000
    print(f"{label:<28}{ms:8.0f} ms per 20-flow batch")
    return ms


clf = det.clf
print("classifier:", type(clf).__name__,
      "| trees:", len(getattr(clf, "estimators_", [])) or "n/a",
      "| n_jobs:", getattr(clf, "n_jobs", "n/a"))
X = batch[det.feats]
Xin = X if hasattr(clf, "feature_names_in_") else X.values

total = clock("whole predict()", lambda: det.predict(batch))
core = clock("classifier only", lambda: clf.predict_proba(Xin))
print(f"{'autoencoder + the rest':<28}{total - core:8.0f} ms")