"""Turns raw log dicts (from reader.py) into typed model objects."""
import logging

from log_parser.models import AuthLog, CriticalNetworkLog, NetworkLog, SystemLog

logger = logging.getLogger(__name__)


def parse_log(x_raw_logs: list) -> list:
    y_ripe_logs = []
    for i, log in enumerate(x_raw_logs):
        try:
            t = log["type"]
            if t == "network":
                y_ripe_logs.append(NetworkLog(
                    log["timestamp"], log["level"], log["message"],
                    log["src_ip"], log["dest_ip"],
                ))
            elif t == "auth":
                y_ripe_logs.append(AuthLog(
                    log["timestamp"], log["level"], log["message"],
                    log["user"], log["attempts"],
                ))
            elif t == "system":
                y_ripe_logs.append(SystemLog(
                    log["timestamp"], log["level"], log["message"],
                    log["process"], log["exit_code"],
                ))
            elif t == "critical_network":
                y_ripe_logs.append(CriticalNetworkLog(
                    log["timestamp"], log["level"], log["message"],
                    log["src_ip"], log["dest_ip"], log["user"], log["attempts"],
                ))
        except KeyError as e:
            logger.error("Log #%d missing key %s -- skipped.", i + 1, e)
    return y_ripe_logs
