import json
import os

import pandas as pd


class TrafficStream:
    """Replays labelled flows in capture-time order, like a live feed."""

    def __init__(self, path="data/test_stream.parquet"):
        df = pd.read_parquet(path)
        df["Timestamp"] = pd.to_datetime(df["Timestamp"])
        self.df = df.sort_values("Timestamp").reset_index(drop=True)
        self._date = self.df["Timestamp"].dt.date

        # True only if the replay rows are known to be unseen by the models
        meta = os.path.join(os.path.dirname(path), "stream_meta.json")
        self.held_out = json.load(open(meta)).get("held_out", False) if os.path.exists(meta) else False

    def days(self):
        return sorted(self._date.unique())

    def start_of(self, day):
        return int(self._date.eq(day).idxmax())      # index of the first row on that day

    def batch(self, pos, n):
        pos = pos % len(self.df)                      # loop when the file ends
        chunk = self.df.iloc[pos:pos + n].copy()
        return chunk, pos + len(chunk)