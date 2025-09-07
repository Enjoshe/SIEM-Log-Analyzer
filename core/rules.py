from collections import Counter
from datetime import timedelta

def detect_bruteforce(logs, threshold=5, window_minutes=1):
    """
    Detects if same IP had >threshold failed logins in time window.
    Expects logs with status_code 401/403.
    """
    alerts = []
    by_ip = {}
    for l in logs:
        if l.status_code in (401, 403):
            by_ip.setdefault(l.ip, []).append(l.timestamp)
    for ip, times in by_ip.items():
        times.sort()
        for i in range(len(times) - threshold + 1):
            if times[i+threshold-1] - times[i] <= timedelta(minutes=window_minutes):
                alerts.append((ip, f"Bruteforce suspected ({threshold}+ failures in {window_minutes}m)"))
                break
    return alerts

def detect_blacklisted_ip(logs, blacklist):
    alerts = []
    for l in logs:
        if l.ip in blacklist:
            alerts.append((l.ip, "Blacklisted IP detected"))
    return alerts
