# Log-Parser

An OOP-based log classification and reporting system written in Python. Parses raw network, authentication, and system logs — detects brute force attacks, process crashes, and internal threats — and generates a structured report.

Built as part of a 30-day Data Engineering study plan targeting a Senior Data Engineer role (SIEM/cybersecurity).

---

## Class Hierarchy

```
BaseLog
├── NetworkLog          — source/destination IP, internal traffic detection
├── AuthLog             — user, login attempts, brute force detection
├── SystemLog           — process name, exit code, crash detection
└── CriticalNetworkLog  — (NetworkLog + AuthLog) combined correlated event
```

---

## Features

- Parses pipe-separated plain-text log files
- Classifies logs into four types: network, auth, system, critical\_network
- Detects:
  - Brute force login attempts (>5 attempts + CRITICAL level)
  - Process crashes (non-zero exit code)
  - Internal network threats (192.168.x.x source + CRITICAL level)
- Generates a full report with per-log summaries and a flagged events section
- Interactive menu: load from file or run built-in test data
- Graceful error handling for malformed or missing log fields

---

## How to Run

```bash
python oop_4.py
```

You will be prompted:

```
Options:
  1. Load from a log file (.txt)
  2. Run built-in test data
Enter choice (1 or 2):
```

For option 1, enter the path to your log file (e.g. `logs_files_to_be_tested`).

---

## Log File Format

Plain text, pipe-separated. Lines starting with `#` are treated as comments.

```
TYPE | TIMESTAMP | LEVEL | MESSAGE | [type-specific fields]
```

| Type | Fields |
|---|---|
| `network` | src\_ip, dest\_ip |
| `auth` | user, attempts |
| `system` | process, exit\_code |
| `critical_network` | src\_ip, dest\_ip, user, attempts |

### Example

```
# Sample logs
network          | 10:01 | WARNING  | High traffic volume      | 192.168.1.10 | 8.8.8.8
auth             | 10:02 | CRITICAL | Login failed             | admin        | 9
system           | 10:03 | INFO     | Scheduled backup         | backup.py    | 0
system           | 10:06 | CRITICAL | Process crash            | core.py      | 1
critical_network | 10:08 | CRITICAL | Brute force internal IP  | 192.168.1.99 | 10.0.0.1 | root | 12
```

---

## Sample Output

```
======== Log Report ========

--- 1st log ---
Level:     WARNING
Timestamp: 10:01
Message:   High traffic volume
Source IP: 192.168.1.10
Dest IP:   8.8.8.8

--- 2nd log ---
Level:     CRITICAL
Timestamp: 10:02
Message:   Login failed
User:      admin
Attempts:  9

======= Log Synopsis =======

Total logs:            18
Suspicious logs:       15
Crashed processes:     3
Brute force attempts:  6

======= Flagged Events ======

[BRUTE FORCE]     10:02 — user 'admin' (9 attempts)
[CRASH]           10:06 — process 'core.py' exited 1
[INTERNAL THREAT] 10:08 — src 192.168.1.99 → 10.0.0.1
```

---

## Tech

- Python 3.10
- OOP — inheritance, multiple inheritance, method overriding, `super()`
- No external dependencies

---

## Author

Night-pool — Computer Engineering graduate, Backend Developer, Lalitpur, Nepal.
