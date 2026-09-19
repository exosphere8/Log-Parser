"""Builds and prints the human-readable log report."""
from log_parser.analysis import count_enumerator, find_flagged_events, ordinal
from log_parser.models import AuthLog, NetworkLog, SystemLog

FLAGGED_LABELS = {
    "brute_force": "BRUTE FORCE",
    "crash": "CRASH",
    "internal_threat": "INTERNAL THREAT",
}


def _describe_flagged(event) -> str:
    log = event.log
    if event.category == "brute_force" and isinstance(log, AuthLog):
        return f"[BRUTE FORCE] {log.timestamp} -- user '{log.user}' ({log.attempts} attempts)"
    if event.category == "crash" and isinstance(log, SystemLog):
        return f"[CRASH]       {log.timestamp} -- process '{log.process}' exited {log.exit_code}"
    if event.category == "internal_threat" and isinstance(log, NetworkLog):
        return f"[INTERNAL THREAT] {log.timestamp} -- src {log.src_ip} -> {log.dest_ip}"
    return f"[{FLAGGED_LABELS.get(event.category, event.category.upper())}] {log.timestamp}"


def build_report(xx_ripe_logs: list) -> str:
    lines = ["", "======== Log Report ========", ""]
    for i, i_log in enumerate(xx_ripe_logs):
        lines.append(f"--- {ordinal(i + 1)} log ---")
        lines.append(i_log.summary())

    lines.append("======= Log Synopsis =======")
    lines.append("")
    lines.append(f"Total logs:            {len(xx_ripe_logs)}")
    suspicious, crashed, brute_force = count_enumerator(xx_ripe_logs)
    lines.append(f"Suspicious logs:       {suspicious}")
    lines.append(f"Crashed processes:     {crashed}")
    lines.append(f"Brute force attempts:  {brute_force}")

    lines.append("")
    lines.append("======= Flagged Events ======")
    lines.append("")
    flagged = find_flagged_events(xx_ripe_logs)
    if flagged:
        lines.extend(_describe_flagged(event) for event in flagged)
    else:
        lines.append("No flagged events.")

    return "\n".join(lines)


def generate_report(xx_ripe_logs: list) -> None:
    print(build_report(xx_ripe_logs))
