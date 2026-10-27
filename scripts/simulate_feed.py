import os
import sys
import time

import pandas as pd

RATE = int(sys.argv[1]) if len(sys.argv) > 1 else 20    # flows written per second
TOTAL = 0                                                # 0 = run until Ctrl+C
INTERVAL = 0.5                                           # seconds between writes

df = pd.read_parquet("data/test_stream.parquet").drop(columns=["Label"], errors="ignore")
df = df.sample(frac=1, random_state=1).reset_index(drop=True)    # shuffled order
os.makedirs("live", exist_ok=True)
out = "live/flows.csv"
open(out, "w").close()                                   # start with an empty file

per_write = max(1, round(RATE * INTERVAL))
written, i, first = 0, 0, True
print(f"writing about {RATE} flows/s to {out} (Ctrl+C to stop)")
try:
    while TOTAL == 0 or written < TOTAL:
        if i + per_write > len(df):                      # reached the end: loop the data
            i = 0
        chunk = df.iloc[i:i + per_write]
        if TOTAL:
            chunk = chunk.iloc[:TOTAL - written]
        chunk.to_csv(out, mode="a", header=first, index=False)
        first = False
        i += per_write
        written += len(chunk)
        print(f"wrote {written:,} flows", end="\r")
        time.sleep(INTERVAL)
except KeyboardInterrupt:
    pass
print(f"\nstopped after {written:,} flows")