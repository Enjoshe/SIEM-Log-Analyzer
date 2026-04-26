# rules.py
from collections import defaultdict
from datetime import timedelta

# ─────────────────────────────────────────────────────────
# MITRE ATT&CK reference
# Why store this here?
# Every detection should be traceable to a specific adversary
# technique. This makes your detection library auditable —
# you can answer "do we have coverage for T1110?" instantly.
# In a real team this feeds into a coverage dashboard.
# ─────────────────────────────────────────────────────────
MITRE = {
    "brute_force": {
        "tactic":    "TA0006 - Credential Access",
        "technique": "T1110.001 - Brute Force: Password Guessing",
        "url":       "https://attack.mitre.org/techniques/T1110/001/"
    },
    "successful_brute_force": {
        "tactic":    "TA0001 - Initial Access",
        "technique": "T1110 - Brute Force (successful compromise)",
        "url":       "https://attack.mitre.org/techniques/T1110/"
    },
    "suspicious_powershell": {
        "tactic":    "TA0002 - Execution",
        "technique": "T1059.001 - Command and Scripting: PowerShell",
        "url":       "https://attack.mitre.org/techniques/T1059/001/"
    },
    "new_user_account": {
        "tactic":    "TA0003 - Persistence",
        "technique": "T1136.001 - Create Local Account",
        "url":       "https://attack.mitre.org/techniques/T1136/001/"
    },
    "admin_group_add": {
        "tactic":    "TA0004 - Privilege Escalation",
        "technique": "T1098 - Account Manipulation",
        "url":       "https://attack.mitre.org/techniques/T1098/"
    },
    "audit_log_cleared": {
        "tactic":    "TA0005 - Defense Evasion",
        "technique": "T1070.001 - Clear Windows Event Logs",
        "url":       "https://attack.mitre.org/techniques/T1070/001/"
    },
    "root_ssh_login": {
        "tactic":    "TA0001 - Initial Access",
        "technique": "T1078 - Valid Accounts",
        "url":       "https://attack.mitre.org/techniques/T1078/"
    },
    "blacklisted_ip": {
        "tactic":    "TA0001 - Initial Access",
        "technique": "T1078 - Valid Accounts (known malicious actor)",
        "url":       "https://attack.mitre.org/techniques/T1078/"
    },
    "large_data_transfer": {
        "tactic":    "TA0010 - Exfiltration",
        "technique": "T1030 - Data Transfer Size Limits",
        "url":       "https://attack.mitre.org/techniques/T1030/"
    },
}

def make_alert(rule_name, severity, description, log, extra=None):
    """
    Standardized alert format.

    Why standardize?
    If every detection produces alerts in the same format,
    downstream systems (SOAR, ticketing, dashboards) only need
    to handle one structure. Inconsistent alert formats are a
    real operational problem in security teams.
    """
    return {
        "rule":             rule_name,
        "severity":         severity,
        "description":      description,
        "mitre_tactic":     MITRE[rule_name]["tactic"],
        "mitre_technique":  MITRE[rule_name]["technique"],
        "mitre_url":        MITRE[rule_name]["url"],
        "timestamp":        log.get("timestamp"),
        "hostname":         log.get("hostname"),
        "source_ip":        log.get("source_ip"),
        "user":             log.get("user"),
        "source":           log.get("source"),
        "indicators":       extra or {},
        "raw":              log.get("raw")
    }


# ─────────────────────────────────────────────────────────
# Stateful detection class
# Why a class instead of functions?
# Some detections need memory across multiple log entries.
# Brute force detection needs to count failures over time.
# A class holds that state between calls.
# Pure functions can't do this without global variables,
# which are messy and hard to test.
# ─────────────────────────────────────────────────────────
class DetectionEngine:

    def __init__(self, brute_force_threshold=10, brute_force_window=60):
        """
        brute_force_threshold: failures before alerting
        brute_force_window:    time window in seconds

        Why configurable?
        Different environments have different baselines.
        A developer machine might have lots of legitimate
        failed logins from testing. A production server
        should have very few. Hardcoding thresholds is
        bad practice.
        """
        self.threshold   = brute_force_threshold
        self.window      = brute_force_window

        # {(ip, user): [list of failure timestamps]}
        # Why defaultdict? Avoids KeyError on first access.
        self.fail_times  = defaultdict(list)
        self.alerts      = []

    def process(self, log):
        """Run all detections against one normalized log entry."""
        new_alerts = []
        new_alerts += self._brute_force(log)
        new_alerts += self._successful_brute_force(log)
        new_alerts += self._suspicious_powershell(log)
        new_alerts += self._new_user_account(log)
        new_alerts += self._admin_group_add(log)
        new_alerts += self._audit_log_cleared(log)
        new_alerts += self._root_ssh_login(log)
        self.alerts.extend(new_alerts)
        return new_alerts

    # ── Individual detections ──────────────────────────────

    def _brute_force(self, log):
        """
        T1110.001 — detect repeated login failures.

        Why sliding window instead of fixed time buckets?
        Fixed buckets miss attacks that straddle a boundary.
        If your bucket is 00:00-01:00 and the attack runs
        00:59-01:01, each bucket only sees half the attempts.
        Sliding window catches it regardless of timing.
        """
        if log.get("event_type") not in (
            "authentication_failure", "http_request"
        ):
            return []

        # For HTTP logs, only count 401/403 as failures
        if log.get("event_type") == "http_request":
            if log.get("status_code") not in (401, 403):
                return []

        ip   = log.get("source_ip", "unknown")
        user = log.get("user", "unknown")
        ts   = log.get("timestamp")

        if not ts:
            return []

        key = (ip, user)
        self.fail_times[key].append(ts)

        # Prune entries outside the sliding window
        # Why prune? Without pruning memory grows forever.
        # In a long-running process this causes a memory leak.
        cutoff = ts - timedelta(seconds=self.window)
        self.fail_times[key] = [
            t for t in self.fail_times[key] if t > cutoff
        ]

        count = len(self.fail_times[key])
        if count >= self.threshold:
            return [make_alert(
                rule_name   = "brute_force",
                severity    = "HIGH",
                description = (f"{ip} made {count} failed login attempts "
                               f"against '{user}' in {self.window}s"),
                log         = log,
                extra       = {"attempt_count": count,
                               "window_seconds": self.window}
            )]
        return []

    def _successful_brute_force(self, log):
        """
        T1110 — success after many failures = likely compromise.

        Why check prior failures?
        A single successful login is normal.
        A successful login after 10 failures from the same IP
        has essentially one explanation: brute force worked.
        Context turns a benign event into a critical one.
        """
        if log.get("event_type") != "authentication_success":
            return []

        ip   = log.get("source_ip", "unknown")
        user = log.get("user", "unknown")
        key  = (ip, user)

        prior_failures = len(self.fail_times.get(key, []))
        if prior_failures >= 5:
            return [make_alert(
                rule_name   = "successful_brute_force",
                severity    = "CRITICAL",
                description = (f"'{user}' logged in successfully from {ip} "
                               f"after {prior_failures} recent failures — "
                               f"possible account compromise"),
                log         = log,
                extra       = {"prior_failures": prior_failures}
            )]
        return []

    def _suspicious_powershell(self, log):
        """
        T1059.001 — PowerShell abuse.

        Why these specific flags?
        -enc hides the command from casual inspection
        -WindowStyle Hidden hides the window from the user
        -ExecutionPolicy Bypass circumvents script security
        Legitimate admin scripts rarely need all three.
        Office spawning PowerShell is almost never legitimate —
        it's the #1 indicator of a malicious macro.
        """
        if log.get("event_type") != "process_created":
            return []

        process = (log.get("process_name") or "").lower()
        cmdline = (log.get("command_line") or "").lower()
        parent  = (log.get("parent_process") or "").lower()

        if "powershell" not in process:
            return []

        alerts = []

        suspicious_flags = [
            "-enc", "-encodedcommand",
            "-windowstyle hidden",
            "-executionpolicy bypass",
            "-noprofile -noninteractive"
        ]
        matched = [f for f in suspicious_flags if f in cmdline]

        if matched:
            alerts.append(make_alert(
                rule_name   = "suspicious_powershell",
                severity    = "HIGH",
                description = f"PowerShell with suspicious flags: {matched}",
                log         = log,
                extra       = {"suspicious_flags": matched,
                               "command_line": log.get("command_line")}
            ))

        office_parents = [
            "winword.exe", "excel.exe",
            "outlook.exe", "powerpnt.exe"
        ]
        if any(p in parent for p in office_parents):
            alerts.append(make_alert(
                rule_name   = "suspicious_powershell",
                severity    = "CRITICAL",
                description = (f"PowerShell spawned by Office app: {parent} "
                               f"— likely malicious macro execution"),
                log         = log,
                extra       = {"parent_process": parent}
            ))

        return alerts

    def _new_user_account(self, log):
        """
        T1136.001 — attacker creates backdoor account for persistence.
        Any new account creation outside IT provisioning is suspicious.
        """
        if log.get("event_type") != "user_account_created":
            return []

        return [make_alert(
            rule_name   = "new_user_account",
            severity    = "HIGH",
            description = (f"New user account created: "
                           f"'{log.get('user')}' on {log.get('hostname')}"),
            log         = log
        )]

    def _admin_group_add(self, log):
        """
        T1098 — adding account to admin group = privilege escalation.
        This is Windows Event 4732. Should always alert, always.
        """
        if log.get("event_type") != "user_added_to_group":
            return []

        group = (log.get("group_name") or "").lower()
        if "admin" not in group:
            return []

        return [make_alert(
            rule_name   = "admin_group_add",
            severity    = "CRITICAL",
            description = (f"User '{log.get('user')}' added to admin group "
                           f"'{log.get('group_name')}' on {log.get('hostname')}"),
            log         = log,
            extra       = {"group": log.get("group_name")}
        )]

    def _audit_log_cleared(self, log):
        """
        T1070.001 — Windows Event 1102.
        There is almost no legitimate reason to clear the
        security event log on a production system.
        Treat as active attacker until proven otherwise.
        """
        if log.get("event_type") != "audit_log_cleared":
            return []

        return [make_alert(
            rule_name   = "audit_log_cleared",
            severity    = "CRITICAL",
            description = (f"Security audit log CLEARED on "
                           f"{log.get('hostname')} by '{log.get('user')}' — "
                           f"assume active attacker"),
            log         = log
        )]

    def _root_ssh_login(self, log):
        """
        T1078 — direct root SSH login.
        Best practice: nobody logs in as root directly.
        Everyone logs in as themselves and uses sudo.
        Direct root login bypasses that audit trail.
        """
        if (log.get("event_type") == "authentication_success"
                and log.get("source") == "linux"
                and log.get("user") == "root"):

            return [make_alert(
                rule_name   = "root_ssh_login",
                severity    = "HIGH",
                description = (f"Direct root SSH login from "
                               f"{log.get('source_ip')} — "
                               f"admins should use personal accounts + sudo"),
                log         = log
            )]
        return []

    def print_summary(self):
        """Print all alerts sorted by severity."""
        if not self.alerts:
            print("✅ No alerts generated")
            return

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        icons          = {"CRITICAL": "🚨", "HIGH": "⚠️ ",
                          "MEDIUM": "🔶", "LOW":  "🔷"}

        sorted_alerts = sorted(
            self.alerts,
            key=lambda x: severity_order.get(x["severity"], 9)
        )

        print(f"\n{'='*60}")
        print(f"DETECTION SUMMARY — {len(self.alerts)} alert(s)")
        print(f"{'='*60}")

        for a in sorted_alerts:
            icon = icons.get(a["severity"], "❓")
            print(f"\n{icon} [{a['severity']}] {a['description']}")
            print(f"   Technique : {a['mitre_technique']}")
            print(f"   Tactic    : {a['mitre_tactic']}")
            print(f"   Time      : {a['timestamp']}")
            if a["indicators"]:
                print(f"   Indicators: {a['indicators']}")
