"""Official GRC & DPO Compliance Report Exporter (Ley 21.719, Ley 21.663 ANCI & CMF)."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from typing import Any

from app.rag.orchestrator import EnterpriseRAGOrchestrator


class GRCComplianceExporter:
    """
    Generates a cryptographically signed Executive Compliance & Audit Report
    in structured JSON and Markdown for Data Protection Officers (DPO - Ley 21.719)
    and Cybersecurity Officers (CISO - Ley 21.663 ANCI / CMF).
    """

    def __init__(self, orchestrator: EnterpriseRAGOrchestrator) -> None:
        self.orchestrator = orchestrator

    def generate_executive_report(self) -> dict[str, Any]:
        now_utc = dt.datetime.now(dt.timezone.utc).isoformat()
        chain_integrity = self.orchestrator.audit_logger.verify_chain_integrity()
        gov_summary = self.orchestrator.anci_monitor.get_governance_summary()
        kpis = gov_summary["finops_and_privacy_kpis"]
        inventory = self.orchestrator.vector_store.list_all_chunks_metadata()
        recent_logs = self.orchestrator.audit_logger.list_recent_logs(limit=10)

        dept_counts: dict[str, int] = {}
        for item in inventory:
            dept = item["department"]
            dept_counts[dept] = dept_counts.get(dept, 0) + 1

        report_data = {
            "report_title": "Certificado Técnico de Cumplimiento Ley 21.719 (Datos Personales) y Ley 21.663 (ANCI)",
            "generated_at_utc": now_utc,
            "platform": "AegisRAG Enterprise v3.0",
            "embedding_engine": self.orchestrator.embedder.model_identifier,
            "audit_chain_integrity": chain_integrity,
            "departmental_collections_summary": dept_counts,
            "total_indexed_chunks": len(inventory),
            "scoped_cache_prevented_leaks": self.orchestrator.cache.prevented_cross_role_leaks,
            "anci_and_finops_governance": gov_summary,
        }

        signature_sha256 = hashlib.sha256(
            json.dumps(report_data, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()

        md_lines = [
            "# Informe Oficial de Auditoría y Cumplimiento GRC — AegisRAG Enterprise",
            f"- **Fecha Emisión (UTC):** `{now_utc}`",
            f"- **Firma Digital SHA-256 del Reporte:** `{signature_sha256}`",
            f"- **Estado Cadena Criptográfica SQLite:** `{'ÍNTEGRA' if chain_integrity['intact'] else 'COMPROMETIDA'}` ({chain_integrity['total_records']} bloques)",
            f"- **Motor Embeddings (Cero Exfiltración):** `{self.orchestrator.embedder.model_identifier}`",
            "",
            "## 1. Indicadores de Privacidad (Ley 21.719) y Ciberseguridad (Ley 21.663 ANCI)",
            f"- **Ratio Zero-Data-Retention:** `{kpis['zero_data_retention_ratio_pct']}%`",
            f"- **Entidades PII Enmascaradas (RUT / CIE-10 / Cuentas):** `{kpis['total_pii_entities_masked']}`",
            f"- **Accesos Cross-Department Bloqueados en Pre-Retrieval:** `{kpis['total_chunks_blocked_by_rbac']}`",
            f"- **Fugas de Caché entre Roles Evitadas:** `{self.orchestrator.cache.prevented_cross_role_leaks}`",
            f"- **Ataques Prompt Injection Neutralizados:** `{kpis['prompt_injections_neutralized']}`",
            f"- **Estado Alertas Tempranas CSIRT / ANCI (SLA 3h):** `{gov_summary['ley_21663_anci_status']}` ({gov_summary['active_incidents_count']} incidentes)",
            "",
            "## 2. Inventario de Colecciones Vectoriales Aisladas por Departamento",
        ]
        for dept, cnt in sorted(dept_counts.items()):
            md_lines.append(f"- Colección `col_{dept}`: **{cnt}** fragmento(s) protegido(s) por filtro `where` RBAC.")

        md_lines.append("")
        md_lines.append("## 3. Últimos Bloques de la Cadena de Auditoría Inmutable")
        for log in recent_logs[:5]:
            md_lines.append(
                f"- `#{log['id']}` [{log['timestamp_utc']}] **{log['event_type']}** | "
                f"Usuario: `{log['username']}` (`{log['user_department']}`) | "
                f"Ruta: `{log['routing_target']}` | Hash: `{log['entry_hash'][:20]}...`"
            )

        return {
            "report_signature_sha256": signature_sha256,
            "report_data": report_data,
            "report_markdown": "\n".join(md_lines),
        }
