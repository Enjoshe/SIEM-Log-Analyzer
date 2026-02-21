import json
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
from collections import Counter

# Load config
with open("config.json", "r") as f:
    cfg = json.load(f)

es_host = cfg.get("elasticsearch", {}).get("host", "http://localhost:9200")
index_name = cfg.get("elasticsearch", {}).get("index", "logs-siem")

es = Elasticsearch([es_host])

# Define time window (last 15 minutes)
now = datetime.utcnow()
start_time = now - timedelta(minutes=15)

# Brute Force / Failed login detection
failed_login_threshold = cfg.get("alerts", {}).get("failed_login_threshold", 3)

# Query syslog logs in the last 15 min
query = {
    "query": {
        "bool": {
            "must": [
                {"term": {"source_file.keyword": "logs/syslog_sample.log"}},
                {"range": {"@timestamp": {"gte": start_time.isoformat(), "lte": now.isoformat()}}}
            ]
        }
    }
}

res = es.search(index=index_name, body=query, size=1000)
ip_counter = Counter()

for hit in res["hits"]["hits"]:
    msg = hit["_source"].get("message", "")
    ip = hit["_source"].get("ip")
    if "Failed password" in msg and ip:
        ip_counter[ip] += 1

# Print brute-force alerts
for ip, count in ip_counter.items():
    if count >= failed_login_threshold:
        print(f"[ALERT] Brute force detected from IP {ip} ({count} failed logins)")

# Privilege escalation detection
for hit in res["hits"]["hits"]:
    msg = hit["_source"].get("message", "")
    if "root" in msg and "session opened" in msg:
        print(f"[ALERT] Privilege escalation attempt detected: {msg}")

# Basic anomaly detection (Apache logs)
# Query Apache logs
query_apache = {
    "query": {
        "range": {
            "@timestamp": {
                "gte": start_time.isoformat(),
                "lte": now.isoformat()
            }
        }
    }
}

res_ap = es.search(index=index_name, body=query_apache, size=1000)

for hit in res_ap["hits"]["hits"]:
    bytes_sent = hit["_source"].get("bytes_sent", 0)
    if bytes_sent > 100000:  # arbitrary anomaly threshold
        print(f"[ALERT] Large response detected: {bytes_sent} bytes, request={hit['_source'].get('request')}")
