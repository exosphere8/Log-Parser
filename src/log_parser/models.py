# Log Parser -- OOP-based log classification and reporting system.
# Author: Night-pool.
# Naming convention: "x_" prefix for inputs, "y_" prefix for outputs (Engineering Mathematics style).


class BaseLog:
    def __init__(self, timestamp: str, level: str, message: str) -> None:
        self.timestamp = timestamp
        self.level = level
        self.message = message

    def is_suspicious(self) -> bool:
        return self.level in ("CRITICAL", "WARNING")

    def summary(self) -> str:
        return (
            f"Level:     {self.level}\n"
            f"Timestamp: {self.timestamp}\n"
            f"Message:   {self.message}\n"
        )

    def __repr__(self) -> str:
        return f"BaseLog(level={self.level!r}, timestamp={self.timestamp!r}, message={self.message!r})"


class NetworkLog(BaseLog):
    def __init__(self, timestamp: str, level: str, message: str, src_ip: str, dest_ip: str) -> None:
        super().__init__(timestamp, level, message)
        self.src_ip = src_ip
        self.dest_ip = dest_ip

    def summary(self) -> str:
        return (
            super().summary()
            + f"Source IP: {self.src_ip}\n"
            + f"Dest IP:   {self.dest_ip}\n"
        )

    def is_internal(self) -> bool:
        return self.src_ip.startswith("192.168.")


class AuthLog(BaseLog):
    def __init__(self, timestamp: str, level: str, message: str, user: str, attempts: int) -> None:
        super().__init__(timestamp, level, message)
        self.user = user
        self.attempts = attempts

    def summary(self) -> str:
        return (
            super().summary()
            + f"User:     {self.user}\n"
            + f"Attempts: {self.attempts}\n"
        )

    def is_brute_force(self) -> bool:
        return self.attempts > 5 and self.level == "CRITICAL"


class SystemLog(BaseLog):
    def __init__(self, timestamp: str, level: str, message: str, process: str, exit_code: int) -> None:
        super().__init__(timestamp, level, message)
        self.process = process
        self.exit_code = exit_code

    def summary(self) -> str:
        return (
            super().summary()
            + f"Process:   {self.process}\n"
            + f"Exit Code: {self.exit_code}\n"
        )

    def is_crashed(self) -> bool:
        return self.exit_code != 0


class CriticalNetworkLog(NetworkLog, AuthLog):
    """Combined network + auth log for high-severity correlated events."""

    def __init__(
        self, timestamp: str, level: str, message: str,
        src_ip: str, dest_ip: str, user: str, attempts: int,
    ) -> None:
        BaseLog.__init__(self, timestamp, level, message)
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.user = user
        self.attempts = attempts

    def summary(self) -> str:
        return (
            "[CRITICAL NET+AUTH]\n"
            f"Level:     {self.level}\n"
            f"Timestamp: {self.timestamp}\n"
            f"Message:   {self.message}\n"
            f"Source IP: {self.src_ip}\n"
            f"Dest IP:   {self.dest_ip}\n"
            f"User:      {self.user}\n"
            f"Attempts:  {self.attempts}\n"
        )
