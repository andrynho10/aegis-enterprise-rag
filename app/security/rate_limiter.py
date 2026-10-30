"""Identity-Scoped Sliding Window Rate Limiter (OWASP LLM04 / LLM10 Unbounded Consumption Defense)."""
from __future__ import annotations

import time
from typing import Any


class IdentityRateLimiter:
    """
    Protects local GPU clusters and enterprise cloud endpoints from automated scraping
    or Denial-of-Wallet attacks by enforcing per-AD-user sliding-window quotas.
    """

    def __init__(self, max_requests_per_window: int = 40, window_seconds: int = 60) -> None:
        self.max_requests_per_window = max_requests_per_window
        self.window_seconds = window_seconds
        self._user_buckets: dict[str, list[float]] = {}

    def check_and_consume(self, user_id: str) -> dict[str, Any]:
        now = time.time()
        cutoff = now - self.window_seconds
        timestamps = [ts for ts in self._user_buckets.get(user_id, []) if ts > cutoff]

        if len(timestamps) >= self.max_requests_per_window:
            self._user_buckets[user_id] = timestamps
            raise PermissionError(
                f"Rate Limit Excedido (OWASP LLM10): La identidad '{user_id}' superó la cuota máxima "
                f"de {self.max_requests_per_window} consultas en {self.window_seconds}s."
            )

        timestamps.append(now)
        self._user_buckets[user_id] = timestamps
        return {
            "user_id": user_id,
            "requests_in_window": len(timestamps),
            "max_requests_per_window": self.max_requests_per_window,
            "remaining_requests": self.max_requests_per_window - len(timestamps),
            "window_seconds": self.window_seconds,
        }
