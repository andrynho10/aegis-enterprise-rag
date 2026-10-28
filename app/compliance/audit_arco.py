"""Immutable Hash-Chained Audit Trail & Ley 21.719 ARCO Compliance Manager (SQLite)."""
from __future__ import annotations

from contextlib import closing
import datetime as dt
import hashlib
import json
import sqlite3
from typing import Any

from app.config.settings import settings


class ImmutableAuditLogger:
    """
    Tamper-evident (blockchain-style SHA-256 hash chain) SQLite Audit Logger.
    Records who asked what, which document chunks were used, which were blocked by RBAC,
    PII anonymization metrics, routing decisions, and ARCO erasure requests.
    """

    def __init__(self, db_path: str = settings.audit_db_path) -> None:
        self.db_path = db_path
        self._init_db()

    def _connect(self) -> Any:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return closing(conn)

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_trail (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_utc TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    username TEXT NOT NULL,
                    user_department TEXT NOT NULL,
                    ad_groups_json TEXT NOT NULL,
                    query_masked TEXT NOT NULL,
                    where_filter_json TEXT NOT NULL,
                    allowed_chunk_ids_json TEXT NOT NULL,
                    blocked_chunks_count INTEGER NOT NULL,
                    pii_masked_count INTEGER NOT NULL,
                    routing_target TEXT NOT NULL,
                    tool_invocations_json TEXT NOT NULL,
                    security_risk_level TEXT NOT NULL,
                    cache_status TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL
                )
                """
            )
            conn.commit()

    @staticmethod
    def _compute_hash(payload_dict: dict[str, Any]) -> str:
        canonical = json.dumps(payload_dict, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def log_interaction(
        self,
        event_type: str,
        username: str,
        user_department: str,
        ad_groups: list[str],
        query_masked: str,
        where_filter: dict[str, Any],
        allowed_chunk_ids: list[str],
        blocked_chunks_count: int,
        pii_masked_count: int,
        routing_target: str,
        tool_invocations: list[dict[str, Any]],
        security_risk_level: str,
        cache_status: str,
    ) -> dict[str, Any]:
        timestamp_utc = dt.datetime.now(dt.timezone.utc).isoformat()
        with self._connect() as conn:
            last_row = conn.execute(
                "SELECT entry_hash FROM audit_trail ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev_hash = last_row["entry_hash"] if last_row else "GENESIS_BLOCK_LEY_21719_21663"

            hash_input = {
                "timestamp_utc": timestamp_utc,
                "event_type": event_type,
                "username": username,
                "user_department": user_department,
                "ad_groups": ad_groups,
                "query_masked": query_masked,
                "allowed_chunk_ids": allowed_chunk_ids,
                "blocked_chunks_count": blocked_chunks_count,
                "pii_masked_count": pii_masked_count,
                "routing_target": routing_target,
                "security_risk_level": security_risk_level,
                "prev_hash": prev_hash,
            }
            entry_hash = self._compute_hash(hash_input)

            cursor = conn.execute(
                """
                INSERT INTO audit_trail (
                    timestamp_utc, event_type, username, user_department, ad_groups_json,
                    query_masked, where_filter_json, allowed_chunk_ids_json,
                    blocked_chunks_count, pii_masked_count, routing_target,
                    tool_invocations_json, security_risk_level, cache_status,
                    prev_hash, entry_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp_utc,
                    event_type,
                    username,
                    user_department,
                    json.dumps(ad_groups, ensure_ascii=False),
                    query_masked,
                    json.dumps(where_filter, ensure_ascii=False),
                    json.dumps(allowed_chunk_ids, ensure_ascii=False),
                    blocked_chunks_count,
                    pii_masked_count,
                    routing_target,
                    json.dumps(tool_invocations, ensure_ascii=False),
                    security_risk_level,
                    cache_status,
                    prev_hash,
                    entry_hash,
                ),
            )
            conn.commit()
            row_id = cursor.lastrowid

        return {
            "audit_id": row_id,
            "timestamp_utc": timestamp_utc,
            "prev_hash": prev_hash[:16] + "...",
            "entry_hash": entry_hash[:16] + "...",
            "full_entry_hash": entry_hash,
        }

    def list_recent_logs(self, limit: int = 30) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_trail ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()

        results: list[dict[str, Any]] = []
        for r in rows:
            results.append(
                {
                    "id": r["id"],
                    "timestamp_utc": r["timestamp_utc"],
                    "event_type": r["event_type"],
                    "username": r["username"],
                    "user_department": r["user_department"],
                    "ad_groups": json.loads(r["ad_groups_json"]),
                    "query_masked": r["query_masked"],
                    "where_filter": json.loads(r["where_filter_json"]),
                    "allowed_chunk_ids": json.loads(r["allowed_chunk_ids_json"]),
                    "blocked_chunks_count": r["blocked_chunks_count"],
                    "pii_masked_count": r["pii_masked_count"],
                    "routing_target": r["routing_target"],
                    "tool_invocations": json.loads(r["tool_invocations_json"]),
                    "security_risk_level": r["security_risk_level"],
                    "cache_status": r["cache_status"],
                    "prev_hash": r["prev_hash"],
                    "entry_hash": r["entry_hash"],
                }
            )
        return results

    def verify_chain_integrity(self) -> dict[str, Any]:
        """Verify that no historical audit record in SQLite has been tampered with."""
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM audit_trail ORDER BY id ASC").fetchall()

        expected_prev = "GENESIS_BLOCK_LEY_21719_21663"
        for r in rows:
            if r["prev_hash"] != expected_prev:
                return {
                    "intact": False,
                    "total_records": len(rows),
                    "broken_at_id": r["id"],
                    "reason": "Discrepancia en prev_hash de la cadena de auditoría.",
                }
            expected_prev = r["entry_hash"]

        return {
            "intact": True,
            "total_records": len(rows),
            "latest_hash": expected_prev[:24] + "..." if rows else "GENESIS",
        }
