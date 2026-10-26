import os
import time

import pandas as pd

from detector import Detector
from feed import CsvTail, align, finish

PATH = "live/flows.csv"
print("working folder:", os.getcwd())
print("file exists:", os.path.exists(PATH), "| size:", os.path.getsize(PATH) if os.path.exists(PATH) else "n/a")

det = Detector()
feats = getattr(det, "all_feats", det.feats)
print("classifier:", type(det.clf).__name__, "| columns needed:", len(feats))

tail = CsvTail(PATH)
pending = pd.DataFrame()
scored = 0
t0 = time.time()

while time.time() - t0 < 30:
    stamp = f"{time.time() - t0:5.1f}s"
    raw = tail.read_new()
    if raw is None or len(raw) == 0:
        print(stamp, "nothing new (file missing, empty, or no complete line yet)")
    else:
        frame, missing = align(raw, feats)
        if missing:
            print(f"{stamp} STOP: {len(missing)} model columns are missing, e.g. {missing[:5]}")
            print("        columns in the file:", list(raw.columns)[:8], "...")
            break
        fin = finish(frame, feats)
        pending = pd.concat([pending, fin], ignore_index=True)
        print(f"{stamp} read {len(raw)} rows -> {len(fin)} usable | queue {len(pending)}")
    if len(pending):
        batch, pending = pending.iloc[:20], pending.iloc[20:]
        out = det.predict(batch)
        scored += len(out)
        print(f"        scored {len(out)} | total {scored} | {out.verdict.value_counts().to_dict()}")
    time.sleep(2)

print("done. total scored:", scored)