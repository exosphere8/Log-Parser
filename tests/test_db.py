"""Integration tests against a real Postgres instance.

Skipped automatically when no database is reachable (e.g. running the
unit tests locally without Postgres). CI runs these for real against a
Postgres service container -- see .github/workflows/ci.yml.
"""
import psycopg2
import pytest

from log_parser.db import connect_db, init_schema, save_logs_to_db
from log_parser.models import AuthLog, NetworkLog


@pytest.fixture
def conn():
    try:
        connection = connect_db()
    except psycopg2.OperationalError:
        pytest.skip("no Postgres instance reachable -- set DB_HOST/DB_PORT/etc to run this test")
    init_schema(connection)
    with connection.cursor() as cur:
        cur.execute("TRUNCATE TABLE logs RESTART IDENTITY")
    connection.commit()
    yield connection
    connection.close()


def test_save_logs_to_db_inserts_rows(conn):
    logs = [
        NetworkLog("10:00", "INFO", "dns query", "1.2.3.4", "5.6.7.8"),
        AuthLog("10:01", "CRITICAL", "login failed", "admin", 9),
    ]
    inserted = save_logs_to_db(conn, logs)
    assert inserted == 2

    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM logs")
        assert cur.fetchone()[0] == 2


def test_save_logs_to_db_preserves_type_specific_fields(conn):
    save_logs_to_db(conn, [AuthLog("10:01", "CRITICAL", "login failed", "admin", 9)])

    with conn.cursor() as cur:
        cur.execute("SELECT type, username, attempts, src_ip FROM logs")
        row = cur.fetchone()
        assert row == ("AuthLog", "admin", 9, None)
