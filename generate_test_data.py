# generate_test_data.py
import json
import os

os.makedirs("logs", exist_ok=True)

# ── Windows Event Logs ─────────────────────────────────────
windows_events = []

# Brute force — 12 failed logins from same IP
for i in range(12):
    windows_events.append({
        "EventID":        4625,
        "TimeCreated":    f"2026-04-18T03:22:{str(i).zfill(2)}Z",
        "Computer":       "DESKTOP-TESLA-01",
        "TargetUserName": "admin",
        "IpAddress":      "45.33.32.156"
    })

# Successful login after brute force
windows_events.append({
    "EventID":        4624,
    "TimeCreated":    "2026-04-18T03:22:15Z",
    "Computer":       "DESKTOP-TESLA-01",
    "TargetUserName": "admin",
    "IpAddress":      "45.33.32.156"
})

# Backdoor account created
windows_events.append({
    "EventID":          4720,
    "TimeCreated":      "2026-04-18T03:23:00Z",
    "Computer":         "DESKTOP-TESLA-01",
    "SubjectUserName":  "admin",
    "TargetUserName":   "svc-backup-user"
})

# Added to Administrators
windows_events.append({
    "EventID":        4732,
    "TimeCreated":    "2026-04-18T03:23:05Z",
    "Computer":       "DESKTOP-TESLA-01",
    "SubjectUserName":"admin",
    "GroupName":      "Administrators"
})

# Suspicious PowerShell from Word
windows_events.append({
    "EventID":           4688,
    "TimeCreated":       "2026-04-18T03:23:10Z",
    "Computer":          "DESKTOP-TESLA-01",
    "SubjectUserName":   "sarah.chen",
    "NewProcessName":    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "ParentProcessName": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    "CommandLine":       "powershell -enc JABjAGwAaQBlAG4AdA=="
})

# Audit log cleared
windows_events.append({
    "EventID":          1102,
    "TimeCreated":      "2026-04-18T03:24:00Z",
    "Computer":         "DESKTOP-TESLA-01",
    "SubjectUserName":  "admin"
})

with open("logs/windows_events.json", "w") as f:
    for event in windows_events:
        f.write(json.dumps(event) + "\n")

print(f"✅ Created logs/windows_events.json ({len(windows_events)} events)")

# ── Linux Auth Logs ────────────────────────────────────────
linux_lines = []

# SSH brute force
for i in range(12):
    linux_lines.append(
        f"Apr 18 03:22:{str(i).zfill(2)} prod-server-01 sshd[1234]: "
        f"Failed password for ubuntu from 45.33.32.156 port {54230+i} ssh2\n"
    )

# Successful root login
linux_lines.append(
    "Apr 18 03:23:00 prod-server-01 sshd[1234]: "
    "Accepted publickey for root from 45.33.32.156 port 54245 ssh2\n"
)

# Sudo to root
linux_lines.append(
    "Apr 18 03:23:05 prod-server-01 sudo: ubuntu : "
    "TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash\n"
)

with open("logs/linux_auth.log", "w") as f:
    f.writelines(linux_lines)

print(f"✅ Created logs/linux_auth.log ({len(linux_lines)} lines)")

# ── Apache Access Logs ─────────────────────────────────────
apache_lines = []

# Normal traffic
for i in range(20):
    apache_lines.append(
        f'10.0.1.{i} - - [18/Apr/2026:09:00:{str(i).zfill(2)} +0000] '
        f'"GET /index.html HTTP/1.1" 200 1024\n'
    )

# Brute force against login endpoint
for i in range(15):
    apache_lines.append(
        f'45.33.32.156 - - [18/Apr/2026:03:22:{str(i).zfill(2)} +0000] '
        f'"POST /login HTTP/1.1" 401 256\n'
    )

# Large response — possible exfiltration
apache_lines.append(
    '10.0.1.15 - - [18/Apr/2026:03:25:00 +0000] '
    '"GET /api/export/all HTTP/1.1" 200 15000000\n'
)

with open("logs/apache_access.log", "w") as f:
    f.writelines(apache_lines)

print(f"✅ Created logs/apache_access.log ({len(apache_lines)} lines)")
print("\nAll test data generated. Run: python analyser.py")
