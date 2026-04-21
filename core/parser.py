# parser.py
import re
import json
from datetime import datetime

# ─────────────────────────────────────────────────────────
# Windows Event ID mapping
# Why: Event IDs are just numbers. Mapping them to human-readable
# types means detection rules can say event_type="authentication_failure"
# instead of remembering that 4625 means failed login.
# ─────────────────────────────────────────────────────────
WINDOWS_EVENT_TYPES = {
    4624: "authentication_success",
    4625: "authentication_failure",
    4648: "explicit_credential_use",
    4688: "process_created",
    4720: "user_account_created",
    4732: "user_added_to_group",
    4698: "scheduled_task_created",
    1102: "audit_log_cleared",
    7045: "service_installed",
}

def normalize_windows_event(raw):
    """
    Normalize a Windows Security Event Log entry.

    Why Windows Event logs?
    Windows is the dominant OS in enterprise environments.
    Windows Security Events are the primary data source for
    detecting credential attacks, persistence, and privilege
    escalation in corporate networks.

    Input:  dict (parsed from JSON Windows event)
    Output: standardized dict all detections can work with
    """
    event_id = raw.get("EventID")

    return {
        "source":        "windows",
        "event_id":      event_id,
        "event_type":    WINDOWS_EVENT_TYPES.get(event_id, f"unknown_{event_id}"),
        "timestamp":     raw.get("TimeCreated"),
        "hostname":      raw.get("Computer"),
        "user":          raw.get("TargetUserName") or raw.get("SubjectUserName"),
        "source_ip":     raw.get("IpAddress"),
        "process_name":  raw.get("NewProcessName"),
        "parent_process":raw.get("ParentProcessName"),
        "command_line":  raw.get("CommandLine"),
        "group_name":    raw.get("GroupName"),
        "raw":           raw
    }


# ─────────────────────────────────────────────────────────
# Linux auth.log parsing
# Why regex? Linux logs are unstructured plain text.
# There's no JSON schema. Regex is the standard tool for
# extracting structured data from unstructured text.
# ─────────────────────────────────────────────────────────

# Why named groups (?P<name>)? Makes the code self-documenting.
# m.group("ip") is clearer than m.group(3).
LINUX_SSH_FAILED  = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+(?P<host>\S+)\s+\S+:\s+'
    r'Failed password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)'
)
LINUX_SSH_SUCCESS = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+(?P<host>\S+)\s+\S+:\s+'
    r'Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)'
)
LINUX_SUDO        = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+(?P<host>\S+)\s+sudo:\s+'
    r'(?P<user>\S+).*COMMAND=(?P<command>.+)'
)

def _parse_linux_timestamp(month, day, time_str):
    """Convert Linux log timestamp to datetime object"""
    try:
        ts_str = f"{month} {day} {time_str} {datetime.now().year}"
        return datetime.strptime(ts_str, "%b %d %H:%M:%S %Y")
    except ValueError:
        return None

def normalize_linux_auth(line):
    """
    Normalize a Linux /var/log/auth.log line.

    Why Linux auth logs?
    SSH brute force is one of the most common attack vectors
    against internet-facing servers. Auth logs capture every
    SSH attempt, sudo usage, and authentication event on Linux.
    Tesla runs Linux on most cloud infrastructure.

    Input:  raw log line string
    Output: standardized dict, or None if line isn't relevant
    """

    # Try SSH failed login
    m = LINUX_SSH_FAILED.search(line)
    if m:
        return {
            "source":     "linux",
            "event_type": "authentication_failure",
            "timestamp":  _parse_linux_timestamp(
                              m.group("month"), m.group("day"), m.group("time")),
            "hostname":   m.group("host"),
            "user":       m.group("user"),
            "source_ip":  m.group("ip"),
            "raw":        line.strip()
        }

    # Try SSH successful login
    m = LINUX_SSH_SUCCESS.search(line)
    if m:
        return {
            "source":      "linux",
            "event_type":  "authentication_success",
            "timestamp":   _parse_linux_timestamp(
                               m.group("month"), m.group("day"), m.group("time")),
            "hostname":    m.group("host"),
            "user":        m.group("user"),
            "source_ip":   m.group("ip"),
            "auth_method": m.group("method"),
            "raw":         line.strip()
        }

    # Try sudo usage
    m = LINUX_SUDO.search(line)
    if m:
        return {
            "source":     "linux",
            "event_type": "sudo_command",
            "timestamp":  _parse_linux_timestamp(
                              m.group("month"), m.group("day"), m.group("time")),
            "hostname":   m.group("host"),
            "user":       m.group("user"),
            "command":    m.group("command").strip(),
            "raw":        line.strip()
        }

    return None  # line not relevant to our detections


# ─────────────────────────────────────────────────────────
# Keep your existing Apache parser — it's good
# We're adding to it, not replacing it
# ─────────────────────────────────────────────────────────
APACHE_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<req>[^"]+)" (?P<status>\d{3}) (?P<bytes>\d+)'
)

def normalize_apache(line):
    """
    Normalize Apache access log line.

    Why Apache logs?
    Web servers are a common initial access vector. HTTP 401/403
    floods indicate credential brute force against web applications.
    Large responses can indicate data exfiltration.
    """
    m = APACHE_RE.match(line)
    if not m:
        return None
    try:
        dt = datetime.strptime(
            m.group("time").split()[0], "%d/%b/%Y:%H:%M:%S"
        )
    except ValueError:
        return None

    return {
        "source":      "apache",
        "event_type":  "http_request",
        "timestamp":   dt,
        "source_ip":   m.group("ip"),
        "request":     m.group("req"),
        "status_code": int(m.group("status")),
        "bytes_sent":  int(m.group("bytes")),
        "raw":         line.strip()
    }


def parse_log_file(filepath, log_type):
    """
    Parse an entire log file, yielding normalized log dicts.

    Why a generator (yield)?
    Log files can be gigabytes. Loading the whole file into memory
    would crash on large files. A generator processes one line at
    a time — constant memory usage regardless of file size.
    This is how real SIEM ingestion pipelines work.
    """
    parsers = {
        "windows":    lambda line: normalize_windows_event(json.loads(line)),
        "linux_auth": normalize_linux_auth,
        "apache":     normalize_apache,
    }

    parse_fn = parsers.get(log_type)
    if not parse_fn:
        raise ValueError(f"Unknown log type: {log_type}")

    with open(filepath, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                result = parse_fn(line)
                if result:
                    yield result
            except Exception as e:
                # Why skip instead of crash?
                # Real log files always have some malformed lines.
                # A production pipeline must handle bad data gracefully.
                print(f"  Skipping line {line_num}: {e}")
