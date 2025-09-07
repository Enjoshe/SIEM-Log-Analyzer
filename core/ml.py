import pandas as pd
from sklearn.ensemble import IsolationForest

def anomaly_detection(logs, features):
    """
    logs: list of LogEntry objects
    features: list of fields to extract
    """
    rows = []
    for l in logs:
        row = {}
        for f in features:
            if f == "hour":
                row["hour"] = l.timestamp.hour if l.timestamp else 0
            else:
                row[f] = getattr(l, f, 0) or 0
        rows.append(row)
    if not rows:
        return []
    df = pd.DataFrame(rows)
    clf = IsolationForest(contamination=0.05, random_state=42)
    preds = clf.fit_predict(df)
    anomalies = [logs[i] for i, p in enumerate(preds) if p == -1]
    return anomalies
