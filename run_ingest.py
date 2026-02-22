import re
import json
from datetime import datetime, timezone
from elasticsearch import Elasticsearch

# Load config
with open("config.json", "r") as f:
    cfg = json.load(f)

es_host = cfg.get("elasticsearch", {}).get("host", "http://localhost:9200")
index_name = cfg.get("elasticsearch", {}).get("index", "logs-siem")

es = Elasticsearch(es_host)

# ---------------------------
# Helper: Send to Elasticsearch
# ---------------------------
def send_to_es(document):
    es.index(index=index_name, document=document)

# ---------------------------
# Parse Apache Logs
# ---------------------------
def parse_apache(line):
    pattern = r'(\d+\.\d+\.\d+\.\d+).*\[(.*?)\] "(.*?)" (\d{3}) (\d+)'
    match = re.match(pattern, line)
    if not match:
        return None

    ip, raw_time, request, status, bytes_sent = match.groups()

    timestamp = datetime.now(timezone.utc)

    return {
        "@timestamp": timestamp.isoformat(),
        "ip": ip,
        "request": request,
        "status_code": int(status),
        "bytes_sent": int(bytes_sent),
        "event": "web_request",
        "source": "apache"
    }

# ---------------------------
# Parse Syslog (Linux)
# ---------------------------
def parse_syslog(line):
    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
    ip = ip_match.group(1) if ip_match else None

    event_type = "normal_activity"

    if "Failed password" in line:
        event_type = "failed_login"
    elif "session opened for user root" in line:
        event_type = "privilege_escalation"

    timestamp = datetime.now(timezone.utc)

    return {
        "@timestamp": timestamp.isoformat(),
        "ip": ip,
        "message": line.strip(),
        "event": event_type,
        "source": "linux"
    }

# ---------------------------
# Ingest Files
# ---------------------------
def ingest_file(file_path, parser):
    with open(file_path, "r") as f:
        for line in f:
            doc = parser(line)
            if doc:
                send_to_es(doc)

# ---------------------------
# MAIN
# ---------------------------
if __name__ == "__main__":
    print("🚀 Ingesting Apache logs...")
    ingest_file("logs/apache_sample.log", parse_apache)

    print("🚀 Ingesting Syslog logs...")
    ingest_file("logs/syslog_sample.log", parse_syslog)

    print("✅ Ingestion complete.")
