"""Reads plain-text log files into raw dicts, ready for parsing into model objects."""
import logging
import os

logger = logging.getLogger(__name__)

REQUIRED_FIELDS_BY_TYPE = {
    "network": 6,
    "auth": 6,
    "system": 6,
    "critical_network": 8,
}


def read_log_file(x_filepath: str) -> list:
    """
    Reads a plain-text log file.
    Expected line format:
        TYPE | TIMESTAMP | LEVEL | MESSAGE | [extra fields...]

    Field order per type:
        network:          TYPE | TIMESTAMP | LEVEL | MESSAGE | SRC_IP | DEST_IP
        auth:             TYPE | TIMESTAMP | LEVEL | MESSAGE | USER | ATTEMPTS
        system:           TYPE | TIMESTAMP | LEVEL | MESSAGE | PROCESS | EXIT_CODE
        critical_network: TYPE | TIMESTAMP | LEVEL | MESSAGE | SRC_IP | DEST_IP | USER | ATTEMPTS

    Lines starting with '#' are treated as comments and skipped.
    """
    y_raw_logs = []

    if not os.path.exists(x_filepath):
        logger.error("File not found: %s", x_filepath)
        return y_raw_logs

    with open(x_filepath) as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|")]
            try:
                log_type = parts[0].lower()
                min_fields = REQUIRED_FIELDS_BY_TYPE.get(log_type)
                if min_fields is None or len(parts) < min_fields:
                    logger.warning("Line %d: unrecognised format or missing fields -- skipped.", line_num)
                    continue

                if log_type == "network":
                    y_raw_logs.append({
                        "type": "network", "timestamp": parts[1], "level": parts[2],
                        "message": parts[3], "src_ip": parts[4], "dest_ip": parts[5],
                    })
                elif log_type == "auth":
                    y_raw_logs.append({
                        "type": "auth", "timestamp": parts[1], "level": parts[2],
                        "message": parts[3], "user": parts[4], "attempts": int(parts[5]),
                    })
                elif log_type == "system":
                    y_raw_logs.append({
                        "type": "system", "timestamp": parts[1], "level": parts[2],
                        "message": parts[3], "process": parts[4], "exit_code": int(parts[5]),
                    })
                elif log_type == "critical_network":
                    y_raw_logs.append({
                        "type": "critical_network", "timestamp": parts[1], "level": parts[2],
                        "message": parts[3], "src_ip": parts[4], "dest_ip": parts[5],
                        "user": parts[6], "attempts": int(parts[7]),
                    })
            except (ValueError, IndexError) as e:
                logger.warning("Line %d: parse error (%s) -- skipped.", line_num, e)

    return y_raw_logs
