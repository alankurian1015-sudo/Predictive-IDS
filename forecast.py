"""forecast.py: short-term forecast of the attack share, plus an early-warning level."""
import numpy as np
import pandas as pd

# Risk thresholds on attack share. The demo replay over-represents attacks, so tune these.
LOW, ELEVATED, HIGH = 0.10, 0.30, 0.60


def attack_share_series(df, freq="10s"):
    """Fraction of flows flagged as attacks, per time bucket (by arrival time)."""
    d = pd.DataFrame({"bucket": df.seen_at.dt.floor(freq), "atk": (df.family != "Benign").astype(float)})
    g = d.groupby("bucket").agg(share=("atk", "mean"), n=("atk", "size"))
    g = g.iloc[:-1]                                   # newest bucket is still filling
    if g.empty:
        return g
    g = g.asfreq(freq)                                # insert any gaps (for example while paused)
    g["share"] = g["share"].interpolate(limit_direction="both")
    return g


def holt_forecast(y, steps=6, alpha=0.5, beta=0.3):
    """Holt's linear-trend exponential smoothing.
    Returns (fitted, forecast): fitted[t] is the one-step-ahead prediction made BEFORE seeing y[t]."""
    y = np.asarray(y, dtype=float)
    level = y[0]
    trend = (y[1] - y[0]) if len(y) > 1 else 0.0
    fitted = [y[0]]
    for t in range(1, len(y)):
        fitted.append(level + trend)
        new_level = alpha * y[t] + (1 - alpha) * (level + trend)
        trend = beta * (new_level - level) + (1 - beta) * trend
        level = new_level
    fc = np.array([level + (h + 1) * trend for h in range(steps)])
    return np.array(fitted), np.clip(fc, 0.0, 1.0)    # a share must stay in [0, 1]


def backtest(y, alpha=0.5, beta=0.3):
    """Mean absolute one-step error: Holt vs. the naive guess 'same as last bucket'."""
    y = np.asarray(y, dtype=float)
    fitted, _ = holt_forecast(y, steps=1, alpha=alpha, beta=beta)
    err_holt = float(np.mean(np.abs(y[1:] - fitted[1:])))
    err_naive = float(np.mean(np.abs(y[1:] - y[:-1])))
    return err_holt, err_naive


def risk_level(y, fc):
    """Early-warning level from the recent share and the next ~30 s of forecast."""
    now = float(np.mean(y[-3:]))
    nxt = float(np.mean(fc[:3]))
    peak = max(now, nxt)
    if peak < LOW:
        level = "Low"
    elif peak < ELEVATED:
        level = "Elevated"
    elif peak < HIGH:
        level = "High"
    else:
        level = "Severe"
    delta = nxt - now
    trend = "Rising" if delta > 0.05 else "Falling" if delta < -0.05 else "Steady"
    return level, trend


if __name__ == "__main__":
    # Self-test: quiet traffic, then a ramp-up. Run `python forecast.py`.
    y = np.r_[np.full(10, 0.10), np.linspace(0.10, 0.60, 10)]
    _, fc = holt_forecast(y)
    print("forecast:", np.round(fc, 2))
    print("backtest (holt, naive):", backtest(y))
    print("risk:", risk_level(y, fc))