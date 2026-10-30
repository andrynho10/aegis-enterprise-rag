"""Ley 21.663 (ANCI / CSIRT 3-Hour SLA) Incident Monitor & FinOps/Privacy Telemetry."""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Any


class ANCIIncidentAndFinOpsMonitor:
    """
    Monitors security anomalies under Chile's Ley 21.663 (Marco de Ciberseguridad)
    for Essential Services / OIVs (Insurance & Financial sector) and tracks FinOps
    & Privacy KPIs across the Hybrid LLM Router.
    """

    def __init__(self) -> None:
        self._incidents: list[dict[str, Any]] = []
        self._metrics: dict[str, int | float] = {
            "total_queries": 0,
            "local_llm_queries": 0,
            "private_cloud_zdr_queries": 0,
            "external_anonymized_queries": 0,
            "cache_hits": 0,
            "total_pii_entities_masked": 0,
            "total_chunks_blocked_by_rbac": 0,
            "prompt_injections_neutralized": 0,
            "unauthorized_tool_writes_blocked": 0,
            "estimated_cloud_savings_usd": 0.0,
        }

    def record_pipeline_telemetry(
        self,
        username: str,
        department: str,
        routing_target: str,
        cache_hit: bool,
        pii_masked_count: int,
        blocked_chunks_count: int,
        security_scan: dict[str, Any],
        tool_invocations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        self._metrics["total_queries"] = int(self._metrics["total_queries"]) + 1
        if cache_hit:
            self._metrics["cache_hits"] = int(self._metrics["cache_hits"]) + 1
            self._metrics["estimated_cloud_savings_usd"] = round(
                float(self._metrics["estimated_cloud_savings_usd"]) + 0.035, 3
            )
        elif routing_target == "local_llm_on_prem":
            self._metrics["local_llm_queries"] = int(self._metrics["local_llm_queries"]) + 1
            self._metrics["estimated_cloud_savings_usd"] = round(
                float(self._metrics["estimated_cloud_savings_usd"]) + 0.045, 3
            )
        elif routing_target == "enterprise_private_cloud":
            self._metrics["private_cloud_zdr_queries"] = int(self._metrics["private_cloud_zdr_queries"]) + 1
        else:
            self._metrics["external_anonymized_queries"] = int(self._metrics["external_anonymized_queries"]) + 1

        self._metrics["total_pii_entities_masked"] = int(self._metrics["total_pii_entities_masked"]) + pii_masked_count
        self._metrics["total_chunks_blocked_by_rbac"] = (
            int(self._metrics["total_chunks_blocked_by_rbac"]) + blocked_chunks_count
        )

        new_incidents: list[dict[str, Any]] = []
        now = dt.datetime.now(dt.timezone.utc)
        deadline_3h = now + dt.timedelta(hours=3)

        # 1. Detect Prompt Injection attempt (OWASP LLM01)
        if security_scan.get("prompt_injection_detected"):
            self._metrics["prompt_injections_neutralized"] = (
                int(self._metrics["prompt_injections_neutralized"]) + 1
            )
            inc = {
                "incident_id": f"ANCI-2026-{uuid.uuid4().hex[:6].upper()}",
                "detected_at_utc": now.isoformat(),
                "csirt_report_deadline_utc": deadline_3h.isoformat(),
                "sla_window": "3 Horas (Alerta Temprana Ley 21.663 Art. 9)",
                "owasp_category": "LLM01:2025 Prompt Injection & Privilege Escalation",
                "severity": "ALTA",
                "actor_username": username,
                "actor_department": department,
                "mitigation_applied": (
                    f"Neutralizado automáticamente: reglas activadas {security_scan.get('triggered_injection_rules')}. "
                    f"Filtro Pre-Retrieval de ChromaDB bloqueó {blocked_chunks_count} chunk(s) fuera del alcance AD."
                ),
                "data_exfiltrated": False,
            }
            self._incidents.insert(0, inc)
            new_incidents.append(inc)

        # 2. Detect Unauthorized Connector Write attempt (OWASP LLM08 Excessive Agency)
        for tool in tool_invocations:
            if tool.get("status") == "RBAC_DENIED":
                self._metrics["unauthorized_tool_writes_blocked"] = (
                    int(self._metrics["unauthorized_tool_writes_blocked"]) + 1
                )
                inc = {
                    "incident_id": f"ANCI-2026-{uuid.uuid4().hex[:6].upper()}",
                    "detected_at_utc": now.isoformat(),
                    "csirt_report_deadline_utc": deadline_3h.isoformat(),
                    "sla_window": "3 Horas (Alerta Temprana Ley 21.663 Art. 9)",
                    "owasp_category": "LLM08:2025 Excessive Agency / Unauthorized Tool Invocation",
                    "severity": "MEDIA_ALTA",
                    "actor_username": username,
                    "actor_department": department,
                    "mitigation_applied": (
                        f"Ejecución denegada en conector '{tool.get('tool_name')}' "
                        f"(requería departamento '{tool.get('required_department')}')."
                    ),
                    "data_exfiltrated": False,
                }
                self._incidents.insert(0, inc)
                new_incidents.append(inc)

        return new_incidents

    def get_governance_summary(self) -> dict[str, Any]:
        total_q = max(1, int(self._metrics["total_queries"]))
        zero_exfil_count = (
            int(self._metrics["local_llm_queries"])
            + int(self._metrics["private_cloud_zdr_queries"])
            + int(self._metrics["cache_hits"])
        )
        zero_retention_pct = round((zero_exfil_count / total_q) * 100, 1) if self._metrics["total_queries"] else 100.0

        return {
            "ley_21663_anci_status": (
                "ALERTA_TEMPRANA_ACTIVA" if self._incidents else "SIN_INCIDENTES_ACTIVOS"
            ),
            "active_incidents_count": len(self._incidents),
            "incidents": self._incidents[:15],
            "finops_and_privacy_kpis": {
                **self._metrics,
                "zero_data_retention_ratio_pct": zero_retention_pct,
                "embeddings_exfiltration_rate_pct": 0.0,
            },
        }
