import re
from datetime import datetime

APACHE_RE = re.compile(r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<req>[^"]+)" (?P<status>\d{3}) (?P<bytes>\d+)')

def parse_apache_line(line):
    m = APACHE_RE.match(line)
    if not m:
        return None
    dt = datetime.strptime(m.group("time").split()[0], "%d/%b/%Y:%H:%M:%S")
    return {
        "timestamp": dt,
        "ip": m.group("ip"),
        "request": m.group("req"),
        "status_code": int(m.group("status")),
        "bytes_sent": int(m.group("bytes"))
    }

def parse_syslog_line(line):
    try:
        dt = datetime.strptime(line[:15], "%b %d %H:%M:%S")
        rest = line[16:].strip()
        return {
            "timestamp": dt.replace(year=datetime.now().year),
            "ip": None,
            "request": rest,
            "status_code": None,
            "bytes_sent": None
        }
    except Exception:
        return None
