"""Framework-Agnostic API Controllers for the Enterprise Agentic RAG Platform."""
from __future__ import annotations

import base64
import json
from typing import Any

from app.config.settings import settings
from app.data.seed_corpus import get_initial_enterprise_corpus
from app.rag.orchestrator import EnterpriseRAGOrchestrator
from app.security.redteam_evaluator import EnterpriseRedTeamEvaluator


class EnterpriseAPIController:
    """Handles all REST API operations with strict JWT Bearer verification."""

    def __init__(self, orchestrator: EnterpriseRAGOrchestrator | None = None) -> None:
        self.orchestrator = orchestrator or EnterpriseRAGOrchestrator()

    @staticmethod
    def _decode_jwt_unverified_for_inspector(token: str) -> dict[str, Any]:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        pad_h = "=" * (-len(parts[0]) % 4)
        pad_p = "=" * (-len(parts[1]) % 4)
        return {
            "header": json.loads(base64.urlsafe_b64decode(parts[0] + pad_h).decode("utf-8")),
            "payload": json.loads(base64.urlsafe_b64decode(parts[1] + pad_p).decode("utf-8")),
            "signature_preview": parts[2][:20] + "...",
        }

    def get_system_health(self) -> dict[str, Any]:
        integrity = self.orchestrator.audit_logger.verify_chain_integrity()
        return {
            "status": "OPERATIONAL",
            "app_name": settings.app_name,
            "architecture": "Hexagonal / Clean Architecture (Ports & Adapters)",
            "idp_mode": settings.idp_mode,
            "embedding_model": self.orchestrator.embedder.model_identifier,
            "privacy_engine": self.orchestrator.privacy_guard.engine_status(),
            "audit_chain_integrity": integrity,
            "scoped_cache_prevented_leaks": self.orchestrator.cache.prevented_cross_role_leaks,
            "connectors_registered": len(self.orchestrator.connectors.list_available_connectors()),
            "compliance_frameworks": [
                "Ley 21.719 (Protección de Datos Personales Chile - Vigencia Dic 2026 / Prórroga Senado Dic 2027)",
                "Ley 21.663 (Ley Marco de Ciberseguridad / ANCI)",
                "ISO/IEC 27001 & Principio de Mínimo Privilegio RBAC",
            ],
        }

    def list_directory_users(self) -> dict[str, Any]:
        users = [u.to_dict() for u in self.orchestrator.idp.list_directory_users()]
        return {
            "idp_provider": "Microsoft Entra ID / Active Directory Simulator (OIDC + LDAP Ready)",
            "users": users,
            "connectors": self.orchestrator.connectors.list_available_connectors(),
            "sync_sources": self.orchestrator.knowledge_sync.list_sync_sources(),
        }

    def login_sso(self, username: str) -> dict[str, Any]:
        token, identity = self.orchestrator.idp.authenticate_and_issue_token(username)
        return {
            "access_token": token,
            "token_type": "Bearer",
            "user": identity.to_dict(),
            "jwt_decoded": self._decode_jwt_unverified_for_inspector(token),
        }

    def execute_rag_query(self, token: str, body: dict[str, Any]) -> dict[str, Any]:
        query = str(body.get("query", "")).strip()
        if not query:
            raise ValueError("La consulta ('query') no puede estar vacía.")
        routing_mode = str(body.get("routing_mode", "auto"))
        explicit_tool = body.get("explicit_tool")
        explicit_tool_params = body.get("explicit_tool_params")
        bypass_cache = bool(body.get("bypass_cache", False))
        require_hitl = bool(body.get("require_hitl", False))
        return self.orchestrator.process_query(
            token=token,
            query=query,
            routing_mode=routing_mode,
            explicit_tool=explicit_tool,
            explicit_tool_params=explicit_tool_params,
            bypass_cache=bypass_cache,
            require_hitl=require_hitl,
        )

    def confirm_hitl_action(self, token: str, body: dict[str, Any]) -> dict[str, Any]:
        action_id = str(body.get("action_id", "")).strip()
        if not action_id:
            raise ValueError("Debe proporcionar 'action_id' para confirmar o rechazar la acción HITL.")
        decision = str(body.get("decision", "APPROVE")).strip().upper()
        return self.orchestrator.confirm_hitl_action(token=token, action_id=action_id, decision=decision)

    def sync_external_repository(self, token: str, body: dict[str, Any]) -> dict[str, Any]:
        connector_id = str(body.get("connector_id", "")).strip()
        if not connector_id:
            raise ValueError("Debe proporcionar 'connector_id' para sincronizar el repositorio.")
        return self.orchestrator.sync_external_repository(token=token, connector_id=connector_id)

    def run_redteam_benchmark(self) -> dict[str, Any]:
        evaluator = EnterpriseRedTeamEvaluator(self.orchestrator)
        return evaluator.run_full_security_suite()

    def ingest_document(self, token: str, body: dict[str, Any]) -> dict[str, Any]:
        return self.orchestrator.ingest_custom_document(
            token=token,
            title=str(body.get("title", "Documento Corporativo")),
            content=str(body.get("content", "")),
            department=str(body.get("department", "publico_corporativo")),
            classification=str(body.get("classification", "confidencial")),
            source_system=str(body.get("source_system", "SharePoint / Carga Directa")),
            titular_rut=str(body.get("titular_rut", "")),
        )

    def execute_arco_erasure(self, token: str, body: dict[str, Any]) -> dict[str, Any]:
        titular_rut = str(body.get("titular_rut", "")).strip()
        if not titular_rut:
            raise ValueError("Debe indicar el 'titular_rut' para ejercer el Derecho de Supresión (Ley 21.719).")
        reason = str(body.get("reason", "Solicitud formal ARCO de Supresión de Datos Personales (Ley 21.719)"))
        return self.orchestrator.execute_arco_right_to_erasure(token=token, titular_rut=titular_rut, reason=reason)

    def reset_seed_corpus(self) -> dict[str, Any]:
        count = self.orchestrator.vector_store.upsert_chunks(get_initial_enterprise_corpus())
        self.orchestrator.cache.invalidate_all()
        return {"status": "RESTORED", "chunks_restored": count}

    def get_compliance_dashboard(self) -> dict[str, Any]:
        return {
            "audit_chain_integrity": self.orchestrator.audit_logger.verify_chain_integrity(),
            "recent_audit_logs": self.orchestrator.audit_logger.list_recent_logs(limit=40),
            "vector_collections_inventory": self.orchestrator.vector_store.list_all_chunks_metadata(),
            "scoped_cache_prevented_leaks": self.orchestrator.cache.prevented_cross_role_leaks,
            "anci_and_finops_governance": self.orchestrator.anci_monitor.get_governance_summary(),
        }
