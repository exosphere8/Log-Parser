# Log Parser

[![CI](https://github.com/exosphere8/Log-Parser/actions/workflows/ci.yml/badge.svg)](https://github.com/exosphere8/Log-Parser/actions/workflows/ci.yml)

OOP-based security log classification and ETL pipeline. Parses network,
auth, system, and correlated critical-network log lines, flags brute
force / crash / internal-threat events, and loads everything into
Postgres.

## Design

Log lines are classified into a small class hierarchy:

```
BaseLog
 |-- NetworkLog        (src_ip, dest_ip)         -> is_internal()
 |-- AuthLog           (user, attempts)          -> is_brute_force()
 |-- SystemLog         (process, exit_code)      -> is_crashed()
 `-- CriticalNetworkLog(NetworkLog, AuthLog)      -- both network AND auth
                                                     signals on one event
```

`CriticalNetworkLog` is a deliberate use of multiple inheritance: some
events (e.g. a brute-force attempt originating from an internal IP) are
simultaneously a network event and an auth event, and should be caught
by both detectors without duplicating fields.

**Pipeline stages**, each in its own module so they can be tested in
isolation:

```
reader.py   -- read_log_file(): text lines -> raw dicts
                (unknown types / malformed fields are logged and
                 skipped, not fatal -- one bad line shouldn't kill a run)
parser.py   -- parse_log(): raw dicts -> typed model objects
analysis.py -- pure functions over model objects: count_enumerator(),
                find_flagged_events() -- no I/O, so no mocking needed to test
report.py   -- build_report(): formats analysis output as text
db.py       -- Postgres schema + idempotent-enough insert
cli.py      -- interactive entry point wiring the above together
```

## Running it

```bash
pip install -r requirements-dev.txt
cp .env.example .env   # then edit with real DB credentials
PYTHONPATH=src python -m log_parser.cli
```

Choose option 2 at the prompt to run against the built-in sample data
without a log file, or option 1 and point it at `tests/fixtures/sample_log.txt`.

## Testing

```bash
pytest -v --ignore=tests/test_db.py   # unit tests, no DB required
ruff check src tests
```

`tests/test_db.py` is a real integration test against Postgres (not
mocked) -- it auto-skips locally if no database is reachable, and runs
for real in CI against a Postgres service container (see `db-integration`
job in `.github/workflows/ci.yml`), so the insert logic is actually
exercised against the real thing, not just asserted against a mock.

## Log format

```
TYPE | TIMESTAMP | LEVEL | MESSAGE | [type-specific fields...]

network          | 10:01 | WARNING  | High traffic volume | 192.168.1.10 | 8.8.8.8
auth             | 10:02 | CRITICAL | Login failed         | admin        | 9
system           | 10:03 | INFO     | Scheduled backup     | backup.py    | 0
critical_network | 10:08 | CRITICAL | Brute force          | 192.168.1.99 | 10.0.0.1 | root | 12
```

Lines starting with `#` are comments. Malformed or unrecognized lines
are logged as warnings and skipped rather than aborting the run.
