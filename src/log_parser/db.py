"""Postgres persistence layer for parsed logs."""
import os

import psycopg2

SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    level TEXT NOT NULL,
    message TEXT NOT NULL,
    src_ip TEXT,
    dest_ip TEXT,
    username TEXT,
    attempts INTEGER,
    process TEXT,
    exit_code INTEGER,
    inserted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""


def connect_db():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME", "log_parser"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", ""),
    )


def init_schema(conn) -> None:
    with conn.cursor() as cur:
        cur.execute(SCHEMA)
    conn.commit()


def save_logs_to_db(conn, xx_ripe_logs: list) -> int:
    with conn.cursor() as cur:
        for log in xx_ripe_logs:
            cur.execute(
                """
                INSERT INTO logs (
                    type, timestamp, level, message, src_ip, dest_ip,
                    username, attempts, process, exit_code
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    type(log).__name__,
                    log.timestamp,
                    log.level,
                    log.message,
                    getattr(log, "src_ip", None),
                    getattr(log, "dest_ip", None),
                    getattr(log, "user", None),
                    getattr(log, "attempts", None),
                    getattr(log, "process", None),
                    getattr(log, "exit_code", None),
                ),
            )
    conn.commit()
    return len(xx_ripe_logs)
