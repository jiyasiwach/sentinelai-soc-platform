"""Login throttling: sliding-window failure counters per username and per client IP.

- LOGIN_MAX_FAILURES failed logins for one username within LOGIN_LOCKOUT_MINUTES lock that username.
- LOGIN_IP_MAX_FAILURES failed logins from one client IP (any usernames) lock that IP - this stops password
  spraying across many accounts.
- While locked, even a correct password is refused with HTTP 429 and a Retry-After header, so an attacker
  cannot keep guessing. The window slides: the lock lifts once old failures age out.
- A successful login clears that username's failures.

State is in process memory (thread-safe). That fits the single-container deployment this project ships;
behind several workers or replicas each process keeps its own counters, so put a shared store such as
Redis behind this same interface if you scale out.
"""

from __future__ import annotations

import math
import threading
import time
from collections import deque

from .config import settings


class LoginThrottle:
    def __init__(self, max_user_failures: int, max_ip_failures: int, window_seconds: int, clock=time.monotonic):
        self.max_user = max_user_failures
        self.max_ip = max_ip_failures
        self.window = window_seconds
        self.clock = clock
        self._failures: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _keys(username: str, ip: str) -> tuple[str, str]:
        return f"user:{(username or '').strip().lower()}", f"ip:{ip or 'unknown'}"

    def _prune(self, key: str, now: float) -> deque[float]:
        q = self._failures.get(key)
        if q is None:
            return deque()
        while q and now - q[0] >= self.window:
            q.popleft()
        if not q:
            self._failures.pop(key, None)
        return q

    def retry_after(self, username: str, ip: str) -> int:
        """Seconds until a login attempt is allowed again; 0 when not locked."""
        now = self.clock()
        user_key, ip_key = self._keys(username, ip)
        wait = 0.0
        with self._lock:
            for key, limit in ((user_key, self.max_user), (ip_key, self.max_ip)):
                q = self._prune(key, now)
                if len(q) >= limit:
                    # unlocked once enough of the oldest failures age out of the window
                    oldest_that_must_expire = q[len(q) - limit]
                    wait = max(wait, oldest_that_must_expire + self.window - now)
        return math.ceil(wait) if wait > 0 else 0

    def record_failure(self, username: str, ip: str) -> None:
        now = self.clock()
        with self._lock:
            for key in self._keys(username, ip):
                self._prune(key, now)
                self._failures.setdefault(key, deque()).append(now)

    def record_success(self, username: str, ip: str) -> None:
        with self._lock:
            self._failures.pop(self._keys(username, ip)[0], None)

    def reset(self) -> None:
        with self._lock:
            self._failures.clear()


login_throttle = LoginThrottle(
    max_user_failures=settings.login_max_failures,
    max_ip_failures=settings.login_ip_max_failures,
    window_seconds=settings.login_lockout_minutes * 60,
)
