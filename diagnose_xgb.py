import os, sys, joblib, xgboost
from xgboost import XGBClassifier

print("python", sys.version.split()[0], "| local xgboost", xgboost.__version__)
print("\nfiles in models/:")
for f in sorted(os.listdir("models")):
    print(f"{os.path.getsize(os.path.join('models', f)):>12,} bytes  {f}")

p = "models/xgb.json"
if os.path.exists(p):
    with open(p, "rb") as fh:
        print("\nxgb.json starts with:", fh.read(80))
    try:
        m = XGBClassifier()
        m.load_model(p)
        print("xgb.json loads OK")
    except Exception as e:
        print("xgb.json FAILED:", e)

try:
    joblib.load("models/xgb.joblib")
    print("xgb.joblib loads OK")
except Exception as e:
    print("xgb.joblib FAILED:", type(e).__name__, str(e)[:200])