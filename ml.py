# ml.py
import pandas as pd
from sklearn.ensemble import IsolationForest

def build_feature_vector(log):
    """
    Extract numerical features from a normalized log entry.

    Why these features?
    ML models only work with numbers, not strings.
    We extract the signals that are meaningful for anomaly
    detection — time of day, data volume, whether it's a
    new device, etc.

    Why hour of day?
    Most legitimate activity happens during business hours.
    Attacks often happen at night to avoid detection.
    Hour-of-day is one of the strongest anomaly signals.
    """
    ts = log.get("timestamp")

    return {
        "hour":        ts.hour if ts else 0,
        "minute":      ts.minute if ts else 0,
        "bytes_sent":  log.get("bytes_sent") or 0,
        "status_code": log.get("status_code") or 0,

        # Why encode boolean as 0/1?
        # ML models need numbers. True/False becomes 1/0.
        "is_root":     1 if log.get("user") == "root" else 0,
        "is_external": 0 if (log.get("source_ip") or "").startswith("10.") else 1,
        "is_failure":  1 if "failure" in (log.get("event_type") or "") else 0,
    }

def run_anomaly_detection(logs, contamination=0.05):
    """
    Run Isolation Forest anomaly detection on a list of logs.

    Why Isolation Forest?
    Security data is almost entirely unlabeled — we don't know
    which logs represent attacks. Isolation Forest is unsupervised:
    it doesn't need labeled examples. It learns what normal looks
    like and flags deviations.

    Why not a supervised classifier?
    To train a classifier you need labeled attack examples.
    In most environments you have millions of normal events
    and perhaps a handful of confirmed attacks — not enough
    to train on. Isolation Forest works on normal data alone.

    contamination=0.05 means we expect ~5% of events to be
    anomalous. Tune this based on your environment's noise level.

    Returns list of (log, anomaly_score) for anomalous entries.
    """
    if not logs:
        return []

    # Build feature matrix
    feature_rows = [build_feature_vector(log) for log in logs]
    df           = pd.DataFrame(feature_rows)

    # Train and predict
    # Why random_state=42? Reproducibility.
    # Same data always produces same results — important for debugging.
    model   = IsolationForest(contamination=contamination, random_state=42)
    preds   = model.fit_predict(df)
    scores  = model.decision_function(df)

    # Return anomalous logs with their scores
    # More negative score = more anomalous
    anomalies = [
        {"log": logs[i], "anomaly_score": round(float(scores[i]), 4)}
        for i, pred in enumerate(preds)
        if pred == -1
    ]

    return anomalies
