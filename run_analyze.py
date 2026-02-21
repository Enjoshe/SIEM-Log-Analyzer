import json
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta, timezone
from collections import Counter

# ---------------------------
# Load Configuration
# ---------------------------
with open("config.json", "r") as f:
    cfg = json.load(f)

es_host = cfg.get("elasticsearch", {}).get("host", "http://localhost:9200")
index_name = cfg.get("elasticsearch", {}).get("index", "logs-siem")
failed_login_threshold = cfg.get("alerts", {}).get("failed_login_threshold", 3)

# Create ES client
es = Elasticsearch(es_host)

# ---------------------------
# Time Window (Last 15 Minutes)
# ---------------------------
now = datetime.now(timezone.utc)
start_time = now - timedelta(minutes=15)

print(f"\n🔍 Analyzing logs from {start_time} to {now}\n")

# ---------------------------
# 1️⃣ Brute Force Detection
# ---------------------------
syslog_query = {
    "size": 1000,
    "query": {
        "bool": {
            "must": [
                {
                    "range": {
                        "@timestamp": {
                            "gte": start_time.isoformat(),
                            "lte": now.isoformat()
                        }
                    }
                }
            ]
        }
    }
}

response = es.search(index=index_name, body=syslog_query)
ip_counter = Counter()

for hit in response["hits"]["hits"]:
    source = hit["_source"]
    message = source.get("message", "")
    ip = source.get("ip")

    if "Failed password" in message and ip:
        ip_counter[ip] += 1

for ip, count in ip_counter.items():
    if count >= failed_login_threshold:
        print(f"[ALERT] 🚨 Brute force detected from IP {ip} ({count} failed logins)")

# ---------------------------
# 2️⃣ Privilege Escalation Detection
# ---------------------------
for hit in response["hits"]["hits"]:
    message = hit["_source"].get("message", "")
    if "session opened for user root" in message:
        print(f"[ALERT] 🔐 Privilege escalation detected: {message}")

# ---------------------------
# 3️⃣ Apache Anomaly Detection
# ---------------------------
apache_query = {
    "size": 1000,
    "query": {
        "range": {
            "@timestamp": {
                "gte": start_time.isoformat(),
                "lte": now.isoformat()
            }
        }
    }
}

apache_response = es.search(index=index_name, body=apache_query)

for hit in apache_response["hits"]["hits"]:
    source = hit["_source"]
    bytes_sent = source.get("bytes_sent", 0)

    if bytes_sent and bytes_sent > 100000:  # anomaly threshold
        print(
            f"[ALERT] 📦 Large response detected: "
            f"{bytes_sent} bytes | Request: {source.get('request')}"
        )

print("\n✅ Analysis complete.\n")
