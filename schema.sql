-- Schema for the `logs` table. Applied automatically by log_parser.db.init_schema()
-- on startup; kept here too as a standalone reference for manual setup.

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
