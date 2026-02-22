import json
from datetime import datetime
from core.db import DB
from core import parser
from elasticsearch import Elasticsearch

# Load config
with open("config.json", "r", encoding="utf-8") as f:
    cfg = json.load(f)

# Setup SQLite DB
db = DB(cfg.get("database_url"))

# Setup Elasticsearch
es_host = cfg.get("elasticsearch", {}).get("host", "http://localhost:9200")
index_name = cfg.get("elasticsearch", {}).get("index", "logs-siem")
es = Elasticsearch([es_host])

# Create index if it doesn't exist
if not es.indices.exists(index=index_name):
    es.indices.create(index=index_name)
    print(f" Created Elasticsearch index: {index_name}")
else:
    print(f"ℹ Index already exists: {index_name}")

# List of log files to ingest
log_files = [
    {"path": "logs/apache_access.log", "type": "apache_access", "name": "apache_logs"},
    {"path": "logs/syslog_sample.log", "type": "syslog", "name": "syslog"},
]

# Ingest loop
for log in log_files:
    path = log["path"]
    log_type = log["type"]
    source_name = log["name"]

    try:
        with open(path, "r", encoding="utf-8") as f:
            print(f" Ingesting file: {path}")
            for line in f:
                if log_type == "apache_access":
                    data = parser.parse_apache_line(line)
                elif log_type == "syslog":
                    data = parser.parse_syslog_line(line)
                else:
                    continue

                if data:
                    # Save to SQLite
                    db.add_log(source=source_name, **data)

                    # Save to Elasticsearch
                    es_doc = {
                        "@timestamp": datetime.utcnow().isoformat(),
                        "source_file": path,
                        **data
                    }
                    es.index(index=index_name, document=es_doc)
            print(f" Ingestion complete: {path}")
    except FileNotFoundError:
        print(f"❌ File not found: {path}")
