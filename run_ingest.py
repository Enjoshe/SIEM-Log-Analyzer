import argparse
import json
from core.db import DB
from core import parser
from datetime import datetime
from elasticsearch import Elasticsearch

def ingest(cfg):
    # Setup SQLite
    db = DB(cfg.get("database_url"))

    # Setup Elasticsearch
    es_host = cfg.get("elasticsearch", {}).get("host", "http://localhost:9200")
    index_name = cfg.get("elasticsearch", {}).get("index", "logs-siem")
    es = Elasticsearch([es_host])

    for src in cfg.get("log_sources", []):
        path = src["path"]
        print(f"Ingesting file: {path}")

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                # Parse log line based on type
                if src["type"] == "apache_access":
                    data = parser.parse_apache_line(line)
                elif src["type"] == "syslog":
                    data = parser.parse_syslog_line(line)
                else:
                    continue  # skip unknown types

                if data:
                    # Save to SQLite
                    db.add_log(source=src["name"], **data)

                    # Save to Elasticsearch
                    es_doc = {
                        "@timestamp": datetime.utcnow().isoformat(),
                        "source_file": path,
                        **data
                    }
                    es.index(index=index_name, document=es_doc)

                    # >>> Print each log sent
                    print(f"Sent to Elasticsearch: {es_doc}")

if __name__ == "__main__":
    # Parse command-line args
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, help="Path to config.json")
    args = ap.parse_args()

    # Load config
    with open(args.config, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)

    # Run ingestion
    ingest(cfg)
