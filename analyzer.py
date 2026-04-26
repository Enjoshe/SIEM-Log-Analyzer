# analyser.py
import json
from parser  import parse_log_file
from rules   import DetectionEngine
from ml      import run_anomaly_detection
from db      import DB

def run_analysis(log_files, cfg, db=None):
    """
    Full analysis pipeline.

    log_files: list of {"path": "...", "type": "windows|linux_auth|apache"}
    cfg:       config dict
    db:        optional DB instance for persisting alerts

    Why accept log_files as a list?
    Real environments have many log sources — Windows servers,
    Linux servers, web servers, all running simultaneously.
    The pipeline needs to handle all of them in one pass.
    """
    if db is None:
        db = DB(cfg.get("database_url", "sqlite:///siem.db"))

    engine    = DetectionEngine(
        brute_force_threshold = cfg.get("alerts", {}).get("failed_login_threshold", 10),
        brute_force_window    = cfg.get("alerts", {}).get("window_seconds", 60)
    )

    all_logs  = []
    total     = 0

    # ── Ingestion + rule-based detection ──────────────────
    for source in log_files:
        path     = source["path"]
        log_type = source["type"]
        print(f"Processing: {path} ({log_type})")

        for log in parse_log_file(path, log_type):
            all_logs.append(log)
            total += 1

            # Run rule-based detections on every log as it arrives
            # Why process one at a time instead of batching?
            # Stateful detections like brute force need to see
            # events in chronological order. Batching can break
            # the sliding window logic.
            new_alerts = engine.process(log)
            for alert in new_alerts:
                if db:
                    db.add_alert(
                        log_id      = id(log),
                        rule        = alert["rule"],
                        description = alert["description"]
                    )

    print(f"\nProcessed {total} log entries across {len(log_files)} sources")

    # ── ML anomaly detection ───────────────────────────────
    # Why run ML after rule-based?
    # ML needs the full dataset to establish a baseline.
    # You can't do Isolation Forest on one log at a time —
    # you need enough data to define what "normal" looks like.
    # Rule-based detection is online (one at a time).
    # ML detection is offline (whole batch).
    if cfg.get("ml", {}).get("enable", True):
        print("\nRunning ML anomaly detection...")
        anomalies = run_anomaly_detection(all_logs)

        for item in anomalies:
            log   = item["log"]
            score = item["anomaly_score"]
            desc  = (f"ML anomaly detected (score: {score}) — "
                     f"unusual {log.get('event_type')} from "
                     f"{log.get('source_ip')} at {log.get('timestamp')}")

            ml_alert = {
                "rule":            "ml_anomaly",
                "severity":        "MEDIUM",
                "description":     desc,
                "mitre_tactic":    "Unknown — behavioral anomaly",
                "mitre_technique": "ML-detected deviation from baseline",
                "timestamp":       log.get("timestamp"),
                "source_ip":       log.get("source_ip"),
                "indicators":      {"anomaly_score": score}
            }
            engine.alerts.append(ml_alert)

            if db:
                db.add_alert(id(log), "ml_anomaly", desc)

        print(f"ML found {len(anomalies)} anomalies")

    # ── Summary ───────────────────────────────────────────
    engine.print_summary()
    return engine.alerts


if __name__ == "__main__":
    with open("config.json") as f:
        cfg = json.load(f)

    log_files = [
        {"path": "logs/windows_events.json", "type": "windows"},
        {"path": "logs/linux_auth.log",       "type": "linux_auth"},
        {"path": "logs/apache_access.log",    "type": "apache"},
    ]

    alerts = run_analysis(log_files, cfg)
    print(f"\nTotal alerts: {len(alerts)}")