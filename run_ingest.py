import os
import re
from datetime import datetime
from elasticsearch import Elasticsearch

# -----------------------------
# Connect to Elasticsearch
# -----------------------------
es = Elasticsearch("http://localhost:9200")

INDEX_NAME = "logs-siem"


# -----------------------------
# Create index if not exists
# -----------------------------
def create_index():
    if not es.indices.exists(index=INDEX_NAME):
        print("🛠 Creating index...")
        es.indices.create(
            index=INDEX_NAME,
            body={
                "mappings": {
                    "properties": {
                        "ip": {"type": "ip"},
                        "timestamp": {"type": "date"},
                        "method": {"type": "keyword"},
                        "url": {"type": "text"},
                        "status": {"type": "integer"},
                        "size": {"type": "integer"},
                    }
                }
            },
        )
        print(" Index created")
    else:
        print(" Index already exists")


# -----------------------------
# Apache log parser
# -----------------------------
def parse_apache(line):
    pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?) (.*?) HTTP.*" (\d+) (\d+)'
    match = re.match(pattern, line)

    if not match:
        return None

    ip, timestamp, method, url, status, size = match.groups()

    # Convert Apache timestamp to ISO format
    dt = datetime.strptime(timestamp.split()[0], "%d/%b/%Y:%H:%M:%S")

    return {
        "ip": ip,
        "timestamp": dt.isoformat(),
        "method": method,
        "url": url,
        "status": int(status),
        "size": int(size),
    }


# -----------------------------
# Ingest file
# -----------------------------
def ingest_file(file_path):
    if not os.path.exists(file_path):
        print(f" File not found: {file_path}")
        return

    print(f"🚀 Ingesting file: {file_path}")

    with open(file_path, "r") as f:
        for line in f:
            parsed = parse_apache(line.strip())
            if parsed:
                es.index(index=INDEX_NAME, document=parsed)

    print(" Ingestion complete")


# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":
    create_index()
    ingest_file("logs/apache_sample.log")
