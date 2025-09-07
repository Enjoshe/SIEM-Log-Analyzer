import streamlit as st
import json
from core.db import DB

st.set_page_config(page_title="SIEM Log Analyzer", layout="wide")

st.title("SIEM Log Analyzer")

try:
    with open("config.json", "r") as fh:
        cfg = json.load(fh)
except Exception:
    cfg = {"database_url": "sqlite:///siem.db"}

db = DB(cfg.get("database_url"))

tab1, tab2 = st.tabs(["Logs", "Alerts"])

with tab1:
    logs = db.list_logs(limit=200)
    st.write("Recent Logs:", len(logs))
    for l in logs:
        st.text(f"[{l.timestamp}] {l.ip} {l.request} {l.status_code} {l.bytes_sent}")

with tab2:
    alerts = db.list_alerts(limit=100)
    st.write("Recent Alerts:", len(alerts))
    for a in alerts:
        st.error(f"[{a.created_at}] Rule: {a.rule} | {a.description}")
