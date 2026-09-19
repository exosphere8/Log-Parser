"""Pure analysis functions over parsed logs -- no I/O, easy to unit test."""
from dataclasses import dataclass

from log_parser.models import AuthLog, BaseLog, NetworkLog, SystemLog


def count_enumerator(xx_log: list) -> tuple:
    suspicious_count = 0
    crashed_count = 0
    brute_force_count = 0
    for i_log in xx_log:
        if i_log.is_suspicious():
            suspicious_count += 1
        if isinstance(i_log, SystemLog) and i_log.is_crashed():
            crashed_count += 1
        if isinstance(i_log, AuthLog) and i_log.is_brute_force():
            brute_force_count += 1
    return suspicious_count, crashed_count, brute_force_count


def ordinal(n: int) -> str:
    suffix = "th" if 11 <= n % 100 <= 13 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


@dataclass(frozen=True)
class FlaggedEvent:
    category: str  # "brute_force" | "crash" | "internal_threat"
    log: BaseLog


def find_flagged_events(xx_ripe_logs: list) -> list:
    """Identify high-signal events worth surfacing in a report or alert."""
    flagged = []
    for i_log in xx_ripe_logs:
        if isinstance(i_log, AuthLog) and i_log.is_brute_force():
            flagged.append(FlaggedEvent("brute_force", i_log))
        if isinstance(i_log, SystemLog) and i_log.is_crashed():
            flagged.append(FlaggedEvent("crash", i_log))
        if isinstance(i_log, NetworkLog) and i_log.is_internal() and i_log.level == "CRITICAL":
            flagged.append(FlaggedEvent("internal_threat", i_log))
    return flagged
