import argparse, json
from core.db import DB
from core.analyzer import run_analysis

def analyze(cfg):
    db = DB(cfg.get("database_url"))
    logs = db.list_logs(limit=1000)
    alerts = run_analysis(db, logs, cfg)
    print("Generated alerts:", alerts)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    args = ap.parse_args()
    with open(args.config, "r") as fh:
        cfg = json.load(fh)
    analyze(cfg)
