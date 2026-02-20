import argparse, json
from core.db import DB
from core import parser
from datetime import datetime
from elasticsearch import Elasticsearch  # NEW

def ingest(cfg):
    db = DB(cfg.get("database_url"))
    
    # Setup Elasticsearch
    es_host = cfg.get("elasticsearch", {}).get("host", "http://localhost:9200")
    index_name = cfg.get("elasticsearch", {}).get("index", "logs-siem")
    es = Elasticsearch([es_host])
    
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
                    # Save to SQLite
                    db.add_log(source=src["name"], **data)
                    
                    # ALSO send to Elasticsearch
                    es_doc = {
                        "@timestamp": datetime.utcnow().isoformat(),
                        "source_file": path,
                        **data
                    }
                    es.index(index=index_name, document=es_doc)
