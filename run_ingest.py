import argparse, json
from core.db import DB
from core import parser

def ingest(cfg):
    db = DB(cfg.get("database_url"))
    for src in cfg.get("log_sources", []):
        path = src["path"]
        print("Ingesting:", path)
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if src["type"] == "apache_access":
                    data = parser.parse_apache_line(line)
                elif src["type"] == "syslog":
                    data = parser.parse_syslog_line(line)
                else:
                    continue
                if data:
                    db.add_log(source=src["name"], **data)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    args = ap.parse_args()
    with open(args.config, "r") as fh:
        cfg = json.load(fh)
    ingest(cfg)
