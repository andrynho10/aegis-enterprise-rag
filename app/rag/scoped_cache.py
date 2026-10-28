"""Permission-Scoped Response Cache (Prevents Cross-Role Information Leakage)."""
from __future__ import annotations

import hashlib
import re
import time
from typing import Any

from app.domain.models import UserIdentity


class ScopedResponseCache:
    """
    Enterprise Cache Partitioned by RBAC Scope.
    Never shares cached answers across users with different AD department permissions,
    preventing side-channel cache poisoning or cross-department data leakage.
    """

    def __init__(self, ttl_seconds: int = 900) -> None:
        self.ttl_seconds = ttl_seconds
        # Key: (query_hash, scope_hash) -> entry dict
        self._store: dict[tuple[str, str], dict[str, Any]] = {}
        self.prevented_cross_role_leaks: int = 0

    @staticmethod
    def normalize_query(query: str) -> str:
        clean = re.sub(r"\s+", " ", query.strip().lower())
        return clean

    @classmethod
    def compute_query_hash(cls, query: str) -> str:
        norm = cls.normalize_query(query)
        return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def compute_rbac_scope_hash(user: UserIdentity, routing_mode: str = "auto") -> str:
        scope_payload = (
            f"depts={','.join(sorted(user.allowed_departments))}|"
            f"roles={','.join(sorted(user.roles))}|"
            f"class={user.max_classification}|"
            f"pii={user.can_view_raw_pii}|"
            f"mode={routing_mode}"
        )
        return hashlib.sha256(scope_payload.encode("utf-8")).hexdigest()[:16]

    def lookup(
        self,
        query: str,
        user: UserIdentity,
        routing_mode: str = "auto",
    ) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        q_hash = self.compute_query_hash(query)
        s_hash = self.compute_rbac_scope_hash(user, routing_mode)
        now = time.time()

        # Check if same query exists in ANOTHER department's cache scope!
        other_scopes = [
            entry["department_owner"]
            for (qh, sh), entry in self._store.items()
            if qh == q_hash and sh != s_hash and (now - entry["created_at"] <= self.ttl_seconds)
        ]
        cross_role_collision_blocked = len(other_scopes) > 0
        if cross_role_collision_blocked:
            self.prevented_cross_role_leaks += 1

        entry = self._store.get((q_hash, s_hash))
        if entry and (now - entry["created_at"] <= self.ttl_seconds):
            return entry["payload"], {
                "cache_hit": True,
                "cache_key": f"q:{q_hash}::rbac:{s_hash}",
                "scope_isolated": True,
                "cross_role_collision_blocked": cross_role_collision_blocked,
                "other_scope_departments_isolated": other_scopes,
            }

        return None, {
            "cache_hit": False,
            "cache_key": f"q:{q_hash}::rbac:{s_hash}",
            "scope_isolated": True,
            "cross_role_collision_blocked": cross_role_collision_blocked,
            "other_scope_departments_isolated": other_scopes,
        }

    def put(
        self,
        query: str,
        user: UserIdentity,
        payload: dict[str, Any],
        routing_mode: str = "auto",
    ) -> str:
        q_hash = self.compute_query_hash(query)
        s_hash = self.compute_rbac_scope_hash(user, routing_mode)
        self._store[(q_hash, s_hash)] = {
            "created_at": time.time(),
            "department_owner": user.primary_department,
            "payload": payload,
        }
        return f"q:{q_hash}::rbac:{s_hash}"

    def invalidate_all(self) -> int:
        count = len(self._store)
        self._store.clear()
        return count
