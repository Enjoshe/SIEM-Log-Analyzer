from .rules import detect_bruteforce, detect_blacklisted_ip
from .ml import anomaly_detection

def run_analysis(db, logs, cfg):
    alerts = []
    # Rule: bruteforce
    for ip, desc in detect_bruteforce(logs):
        log = next((l for l in logs if l.ip == ip), None)
        if log:
            db.add_alert(log.id, "bruteforce", desc)
            alerts.append(desc)
    # Rule: blacklist
    blacklist = {"1.2.3.4"}
    for ip, desc in detect_blacklisted_ip(logs, blacklist):
        log = next((l for l in logs if l.ip == ip), None)
        if log:
            db.add_alert(log.id, "blacklist", desc)
            alerts.append(desc)
    # ML anomaly
    if cfg.get("ml", {}).get("enable"):
        feats = cfg.get("ml", {}).get("features", [])
        anomalies = anomaly_detection(logs, feats)
        for log in anomalies:
            db.add_alert(log.id, "anomaly", "Unusual activity detected")
            alerts.append("Anomaly")
    return alerts
