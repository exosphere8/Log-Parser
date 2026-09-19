"""Interactive entry point: load a log file (or built-in sample data), report, persist."""
from dotenv import load_dotenv

from log_parser.db import connect_db, init_schema, save_logs_to_db
from log_parser.parser import parse_log
from log_parser.reader import read_log_file
from log_parser.report import generate_report

BUILTIN_LOGS = [
    {"type": "network", "timestamp": "10:01", "level": "WARNING", "message": "High traffic volume",
     "src_ip": "192.168.1.10", "dest_ip": "8.8.8.8"},
    {"type": "auth", "timestamp": "10:02", "level": "CRITICAL", "message": "Login failed", "user": "admin",
     "attempts": 9},
    {"type": "system", "timestamp": "10:03", "level": "INFO", "message": "Scheduled backup", "process": "backup.py",
     "exit_code": 0},
    {"type": "network", "timestamp": "10:04", "level": "INFO", "message": "DNS query", "src_ip": "10.0.0.5",
     "dest_ip": "1.1.1.1"},
    {"type": "auth", "timestamp": "10:05", "level": "WARNING", "message": "Unknown user login", "user": "guest",
     "attempts": 2},
    {"type": "system", "timestamp": "10:06", "level": "CRITICAL", "message": "Process crash", "process": "core.py",
     "exit_code": 1},
    {"type": "network", "timestamp": "10:07", "level": "CRITICAL", "message": "Port scan detected",
     "src_ip": "192.168.1.42", "dest_ip": "10.0.0.1"},
    {"type": "critical_network", "timestamp": "10:08", "level": "CRITICAL", "message": "Brute force from internal IP",
     "src_ip": "192.168.1.99", "dest_ip": "10.0.0.1", "user": "root", "attempts": 12},
]


def main() -> None:
    load_dotenv()

    print("+------------------------------+")
    print("|   Log Parser -- Night-pool   |")
    print("+------------------------------+")
    print("\nOptions:")
    print("  1. Load from a log file (.txt)")
    print("  2. Run built-in test data")
    choice = input("\nEnter choice (1 or 2): ").strip()

    if choice == "1":
        filepath = input("Enter path to log file: ").strip()
        x_raw_logs = read_log_file(filepath)
        if not x_raw_logs:
            print("[ERROR] No valid logs found. Exiting.")
            return
    else:
        print("\n[INFO] Using built-in test data.")
        x_raw_logs = BUILTIN_LOGS

    y_ripe_logs = parse_log(x_raw_logs)
    generate_report(y_ripe_logs)

    conn = connect_db()
    try:
        init_schema(conn)
        inserted = save_logs_to_db(conn, y_ripe_logs)
        print(f"[DB] {inserted} logs inserted successfully!")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
