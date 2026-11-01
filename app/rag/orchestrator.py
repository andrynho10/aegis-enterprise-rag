"""Enterprise Agentic RAG Orchestrator (End-to-End Security, Privacy, Routing & Action Pipeline)."""
from __future__ import annotations

import time
import uuid
from typing import Any

from app.compliance.anci_incident_monitor import ANCIIncidentAndFinOpsMonitor
from app.compliance.audit_arco import ImmutableAuditLogger
from app.connectors.enterprise_tools import EnterpriseConnectorRegistry
from app.connectors.knowledge_sync import EnterpriseKnowledgeSyncConnector
from app.connectors.mcp_server_adapter import EnterpriseMCPServerAdapter
from app.data.seed_corpus import get_initial_enterprise_corpus
from app.domain.models import DataClassification, DocumentChunk, RoutingTarget, UserIdentity
from app.rag.document_processor import EnterpriseDocumentProcessor
from app.rag.embeddings import LocalHybridSemanticEmbedder
from app.rag.hallucination_guard import GroundednessAndOutputGuard
from app.rag.llm_router import HybridLLMRouter
from app.rag.scoped_cache import ScopedResponseCache
from app.rag.vector_store import PermissionAwareVectorStore
from app.security.ad_providers import MockActiveDirectoryProvider
from app.security.pii_anonymizer import ChileanPresidioPrivacyGuard
from app.security.rate_limiter import IdentityRateLimiter
from app.security.rbac_engine import RBACEngine


class EnterpriseRAGOrchestrator:
    """
    Central coordinator of the 8-Stage Enterprise Agentic RAG Pipeline.
    Decoupled via Hexagonal Ports so any component can scale independently.
    """

    def __init__(self, audit_db_path: str | None = None) -> None:
        self.idp = MockActiveDirectoryProvider()
        self.embedder = LocalHybridSemanticEmbedder()
        self.vector_store = PermissionAwareVectorStore(embedder=self.embedder)
        self.privacy_guard = ChileanPresidioPrivacyGuard()
        self.doc_processor = EnterpriseDocumentProcessor(privacy_guard=self.privacy_guard)
        self.hallucination_guard = GroundednessAndOutputGuard(privacy_guard=self.privacy_guard)
        self.rate_limiter = IdentityRateLimiter()
        self.anci_monitor = ANCIIncidentAndFinOpsMonitor()
        self.llm_router = HybridLLMRouter(embedding_model_id=self.embedder.model_identifier)
        self.cache = ScopedResponseCache()
        self.connectors = EnterpriseConnectorRegistry()
        self.knowledge_sync = EnterpriseKnowledgeSyncConnector(
            vector_store=self.vector_store,
            privacy_guard=self.privacy_guard,
        )
        self.mcp_adapter = EnterpriseMCPServerAdapter(self)
        self.audit_logger = ImmutableAuditLogger(db_path=audit_db_path) if audit_db_path else ImmutableAuditLogger()

        # Seed initial corporate knowledge base across departmental collections
        self.vector_store.upsert_chunks(get_initial_enterprise_corpus())

    def process_query(
        self,
        token: str,
        query: str,
        routing_mode: str = "auto",
        explicit_tool: str | None = None,
        explicit_tool_params: dict[str, Any] | None = None,
        bypass_cache: bool = False,
        require_hitl: bool = False,
    ) -> dict[str, Any]:
        t0 = time.perf_counter()

        # STAGE 1: Identity & OIDC JWT Verification (Active Directory / Entra ID) + Rate Limiting
        user: UserIdentity = self.idp.verify_token_and_resolve_user(token)
        rate_limit_meta = self.rate_limiter.check_and_consume(user.user_id)

        # STAGE 2: Prompt Injection & Unauthorized Probing Inspection
        security_scan = RBACEngine.detect_security_threats(query, user)

        # STAGE 3: Permission-Scoped Cache Lookup (Only if no write tool is requested)
        is_action_request = explicit_tool is not None or any(
            kw in query.lower()
            for kw in ["preliquidar", "pre-liquidar", "retener factura", "bloquear pago", "crear ticket", "abrir ticket", "emitir certificado"]
        )
        if not bypass_cache and not is_action_request:
            cached_payload, cache_meta = self.cache.lookup(query, user, routing_mode=routing_mode)
            if cached_payload is not None:
                latency_ms = round((time.perf_counter() - t0) * 1000, 2)
                audit_receipt = self.audit_logger.log_interaction(
                    event_type="RAG_QUERY_CACHED_SCOPED",
                    username=user.username,
                    user_department=user.primary_department,
                    ad_groups=user.ad_groups,
                    query_masked=cached_payload["privacy_telemetry"]["query_anonymized"],
                    where_filter=cached_payload["retrieval_telemetry"]["applied_where_filter"],
                    allowed_chunk_ids=[c["chunk_id"] for c in cached_payload["retrieved_chunks"]],
                    blocked_chunks_count=cached_payload["retrieval_telemetry"]["blocked_by_rbac_count"],
                    pii_masked_count=cached_payload["privacy_telemetry"]["total_pii_entities_detected"],
                    routing_target=cached_payload["routing_decision"]["target"],
                    tool_invocations=[],
                    security_risk_level=security_scan["risk_level"],
                    cache_status=f"HIT ({cache_meta['cache_key']})",
                )
                result_copy = dict(cached_payload)
                result_copy["cache_telemetry"] = cache_meta
                result_copy["audit_receipt"] = audit_receipt
                result_copy["latency_ms"] = latency_ms
                self.anci_monitor.record_pipeline_telemetry(
                    username=user.username,
                    department=user.primary_department,
                    routing_target=cached_payload["routing_decision"]["target"],
                    cache_hit=True,
                    pii_masked_count=cached_payload["privacy_telemetry"]["total_pii_entities_detected"],
                    blocked_chunks_count=cached_payload["retrieval_telemetry"]["blocked_by_rbac_count"],
                    security_scan=security_scan,
                    tool_invocations=[],
                )
                return result_copy
        else:
            _, cache_meta = self.cache.lookup(query, user, routing_mode=routing_mode)

        # STAGE 4: Permission-Aware Vector Retrieval (`where` filter injected BEFORE retrieval)
        retrieval = self.vector_store.retrieve_permission_aware(query=query, user=user, top_k=4)

        # STAGE 5: Privacy & PII Anonymization Gateway (Ley 21.719 / Presidio + RUT + CIE-10)
        query_pii = self.privacy_guard.anonymize(query)
        raw_context_blocks: list[str] = []
        anonymized_context_blocks: list[str] = []
        combined_vault: dict[str, str] = dict(query_pii.vault_mapping)
        all_detected_entities = list(query_pii.entities)
        has_sensitive_art16 = query_pii.has_sensitive_health_or_finance

        for ch in retrieval.allowed_chunks:
            ch_pii = self.privacy_guard.anonymize(ch.content)
            combined_vault.update(ch_pii.vault_mapping)
            all_detected_entities.extend(ch_pii.entities)
            if ch_pii.has_sensitive_health_or_finance:
                has_sensitive_art16 = True

            header_line = f"**[{ch.chunk_id}] {ch.title}** *(Fuente: {ch.source_system} | Depto: `{ch.department}` | Clasificación: `{ch.classification}`)*"
            raw_context_blocks.append(f"{header_line}\n{ch.content}")
            anonymized_context_blocks.append(f"{header_line}\n{ch_pii.anonymized_text}")

        combined_pii_summary = self.privacy_guard.anonymize(
            query + "\n" + "\n".join(c.content for c in retrieval.allowed_chunks)
        )
        combined_pii_summary.has_sensitive_health_or_finance = has_sensitive_art16

        # STAGE 6: Hybrid LLM Router Decision
        routing_decision = self.llm_router.decide_route(
            query=query,
            chunks=retrieval.allowed_chunks,
            pii_result=combined_pii_summary,
            forced_mode=routing_mode,
        )

        # STAGE 7: Enterprise Actionable Connectors (RBAC-gated Tool Execution)
        tool_invocations = self.connectors.detect_and_execute_tools(
            query=query,
            user=user,
            explicit_tool=explicit_tool,
            explicit_params=explicit_tool_params,
            require_hitl=require_hitl,
        )

        # STAGE 8: Grounded Generation + Conditional PII Rehydration
        # If routed to External API or Private Cloud with pre-anonymization, send ONLY masked text to the LLM!
        if routing_decision.requires_pre_anonymization or routing_decision.target != RoutingTarget.LOCAL_LLM_ON_PREM:
            query_sent_to_llm = query_pii.anonymized_text
            context_sent_to_llm = "\n\n".join(anonymized_context_blocks)
        else:
            # Local On-Premise LLM (Zero Exfiltration): can process within internal network,
            # though we still respect `user.can_view_raw_pii` before displaying to user!
            query_sent_to_llm = query if user.can_view_raw_pii else query_pii.anonymized_text
            context_sent_to_llm = (
                "\n\n".join(raw_context_blocks)
                if user.can_view_raw_pii
                else "\n\n".join(anonymized_context_blocks)
            )

        llm_raw_output = self.llm_router.generate_response(
            decision=routing_decision,
            query_for_llm=query_sent_to_llm,
            context_for_llm=context_sent_to_llm,
            user=user,
            tool_results=tool_invocations,
        )

        # Rehydrate placeholders (<RUT_CHILENO_1>, etc.) ONLY if user's AD role authorizes raw PII
        rehydrated_answer = self.privacy_guard.rehydrate(llm_raw_output, combined_vault, user)

        # Verify Groundedness (Anti-Hallucination) & Final Output DLP Guardrail
        groundedness_report = self.hallucination_guard.verify_and_guard_output(
            answer_text=rehydrated_answer,
            allowed_chunks=retrieval.allowed_chunks,
            tool_invocations=tool_invocations,
            user=user,
        )
        final_answer = groundedness_report["guarded_answer"]

        # Prepare chunk cards for UI (respecting PII masking if user lacks `can_view_raw_pii`)
        ui_chunks: list[dict[str, Any]] = []
        for ch in retrieval.allowed_chunks:
            ch_dict = ch.to_dict(include_embedding=False)
            ch_pii = self.privacy_guard.anonymize(ch.content)
            ch_dict["content_anonymized"] = ch_pii.anonymized_text
            ch_dict["content_displayed"] = ch.content if user.can_view_raw_pii else ch_pii.anonymized_text
            ui_chunks.append(ch_dict)

        latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        # STAGE 9: Write Immutable Hash-Chained Audit Log (SQLite)
        event_type = "AGENTIC_TOOL_AND_RAG" if tool_invocations else "RAG_QUERY"
        if security_scan["prompt_injection_detected"]:
            event_type = "PROMPT_INJECTION_BLOCKED_AT_RETRIEVAL"

        audit_receipt = self.audit_logger.log_interaction(
            event_type=event_type,
            username=user.username,
            user_department=user.primary_department,
            ad_groups=user.ad_groups,
            query_masked=query_pii.anonymized_text,
            where_filter=retrieval.applied_where_filter,
            allowed_chunk_ids=[c.chunk_id for c in retrieval.allowed_chunks],
            blocked_chunks_count=retrieval.blocked_by_rbac_count,
            pii_masked_count=len(combined_pii_summary.entities),
            routing_target=routing_decision.target.value,
            tool_invocations=[t.to_dict() for t in tool_invocations],
            security_risk_level=security_scan["risk_level"],
            cache_status=f"MISS ({cache_meta['cache_key']})",
        )

        tool_dicts = [t.to_dict() for t in tool_invocations]
        anci_alerts = self.anci_monitor.record_pipeline_telemetry(
            username=user.username,
            department=user.primary_department,
            routing_target=routing_decision.target.value,
            cache_hit=False,
            pii_masked_count=len(combined_pii_summary.entities),
            blocked_chunks_count=retrieval.blocked_by_rbac_count,
            security_scan=security_scan,
            tool_invocations=tool_dicts,
        )

        response_payload: dict[str, Any] = {
            "answer": final_answer,
            "user_context": user.to_dict(),
            "security_scan": security_scan,
            "anci_ley21663_alerts": anci_alerts,
            "retrieval_telemetry": {
                "applied_where_filter": retrieval.applied_where_filter,
                "collections_searched": retrieval.collections_searched,
                "total_candidates_before_rbac": retrieval.total_candidates_before_rbac,
                "allowed_chunks_count": len(retrieval.allowed_chunks),
                "blocked_by_rbac_count": retrieval.blocked_by_rbac_count,
                "blocked_departments_preview": retrieval.blocked_departments_preview,
                "reranker_strategy": "TwoStage_RRF_k60_plus_CrossEncoder_ExactEntity",
            },
            "retrieved_chunks": ui_chunks,
            "privacy_telemetry": {
                "query_original": query,
                "query_anonymized": query_pii.anonymized_text,
                "context_sent_to_llm_was_anonymized": (
                    routing_decision.requires_pre_anonymization
                    or routing_decision.target != RoutingTarget.LOCAL_LLM_ON_PREM
                    or not user.can_view_raw_pii
                ),
                "pii_rehydrated_for_authorized_user": user.can_view_raw_pii,
                "total_pii_entities_detected": len(combined_pii_summary.entities),
                "detected_entities": [
                    {
                        "type": e.entity_type,
                        "placeholder": e.placeholder,
                        "sensitivity": e.sensitivity,
                        "original_preview": e.original_value if user.can_view_raw_pii else "***PROTEGIDO LEY 21.719***",
                    }
                    for e in combined_pii_summary.entities
                ],
                "has_sensitive_art16_ley21719": has_sensitive_art16,
            },
            "routing_decision": routing_decision.to_dict(),
            "tool_invocations": tool_dicts,
            "groundedness_and_citations": groundedness_report,
            "rate_limit_telemetry": rate_limit_meta,
            "cache_telemetry": cache_meta,
            "audit_receipt": audit_receipt,
            "latency_ms": latency_ms,
        }

        if not is_action_request:
            self.cache.put(query, user, response_payload, routing_mode=routing_mode)

        return response_payload

    def ingest_custom_document(
        self,
        token: str,
        title: str,
        content: str,
        department: str,
        classification: str,
        source_system: str = "Carga Manual GRC / SharePoint",
        titular_rut: str = "",
    ) -> dict[str, Any]:
        user = self.idp.verify_token_and_resolve_user(token)
        if department not in user.allowed_departments:
            raise PermissionError(
                f"RBAC Denegado: Tu usuario ({user.primary_department}) no puede indexar documentos en el departamento '{department}'."
            )

        requested_class = classification or DataClassification.CONFIDENCIAL.value
        chunks, proc_summary = self.doc_processor.process_document_into_chunks(
            title=title,
            content=content,
            department=department,
            requested_classification=requested_class,
            source_system=source_system,
            explicit_titular_rut=titular_rut,
        )
        self.vector_store.upsert_chunks(chunks)
        self.cache.invalidate_all()

        audit_receipt = self.audit_logger.log_interaction(
            event_type="DOCUMENT_INGESTION_DLP_AUTO_CLASSIFY",
            username=user.username,
            user_department=user.primary_department,
            ad_groups=user.ad_groups,
            query_masked=(
                f"Ingesta inteligente '{title}' en '{department}' "
                f"({proc_summary['total_chunks_created']} chunks, {proc_summary['dlp_auto_upgrades_count']} DLP upgrades)"
            ),
            where_filter={
                "department": department,
                "requested_classification": requested_class,
                "final_classifications": proc_summary["final_classifications"],
            },
            allowed_chunk_ids=proc_summary["chunk_ids"],
            blocked_chunks_count=0,
            pii_masked_count=proc_summary["total_pii_entities_detected"],
            routing_target="LOCAL_EMBEDDING_DLP_INDEXER",
            tool_invocations=[],
            security_risk_level="BAJO",
            cache_status="CACHE_INVALIDATED",
        )
        return {
            "status": "INDEXED",
            "chunk": chunks[0].to_dict(include_embedding=False) if chunks else {},
            "chunks_created": [c.to_dict(include_embedding=False) for c in chunks],
            "dlp_processing_summary": proc_summary,
            "embedding_model": self.embedder.model_identifier,
            "pii_detected_on_ingest": proc_summary["total_pii_entities_detected"],
            "audit_receipt": audit_receipt,
        }

    def execute_arco_right_to_erasure(self, token: str, titular_rut: str, reason: str = "Solicitud ARCO Titular Ley 21.719") -> dict[str, Any]:
        """
        Execute Ley 21.719 Right to Erasure / Suppression (`Derecho de Cancelación / Supresión`).
        Only Compliance Officers (`legal_cumplimiento`), HR (`rrhh`), or Health Claims (`salud_siniestros`)
        can trigger an ARCO purge.
        """
        user = self.idp.verify_token_and_resolve_user(token)
        authorized_depts = {"legal_cumplimiento", "salud_siniestros", "rrhh"}
        if not set(user.allowed_departments).intersection(authorized_depts):
            raise PermissionError(
                f"RBAC Denegado: El usuario '{user.username}' no posee facultades de Oficial de Cumplimiento (DPO) "
                "ni gestor de datos personales para ejecutar supresión ARCO Ley 21.719."
            )

        deleted_chunks = self.vector_store.delete_by_titular_rut(titular_rut)
        self.cache.invalidate_all()

        masked_rut = self.privacy_guard.anonymize(titular_rut).anonymized_text
        audit_receipt = self.audit_logger.log_interaction(
            event_type="LEY_21719_ARCO_SUPRESION_OLVIDO",
            username=user.username,
            user_department=user.primary_department,
            ad_groups=user.ad_groups,
            query_masked=f"Derecho de Supresión ARCO ejecutado para titular {masked_rut} ({reason})",
            where_filter={"titular_rut": masked_rut},
            allowed_chunk_ids=deleted_chunks,
            blocked_chunks_count=0,
            pii_masked_count=1,
            routing_target="VECTOR_DB_PURGE_ALL_COLLECTIONS",
            tool_invocations=[],
            security_risk_level="BAJO",
            cache_status="ALL_PARTITIONS_FLUSHED",
        )
        return {
            "status": "PURGED" if deleted_chunks else "NOT_FOUND",
            "titular_rut": titular_rut,
            "deleted_chunk_ids": deleted_chunks,
            "deleted_count": len(deleted_chunks),
            "executed_by": user.email,
            "audit_receipt": audit_receipt,
        }

    def confirm_hitl_action(self, token: str, action_id: str, decision: str = "APPROVE") -> dict[str, Any]:
        """Confirm or reject a pending Human-in-the-Loop write action and record an immutable audit block."""
        user = self.idp.verify_token_and_resolve_user(token)
        invocation = self.connectors.confirm_pending_action(action_id=action_id, user=user, decision=decision)
        audit_receipt = self.audit_logger.log_interaction(
            event_type=f"HITL_ACTION_{decision.upper()}",
            username=user.username,
            user_department=user.primary_department,
            ad_groups=user.ad_groups,
            query_masked=f"Confirmación HITL {action_id} ({decision.upper()}) sobre {invocation.tool_name}",
            where_filter={"required_department": invocation.required_department},
            allowed_chunk_ids=[],
            blocked_chunks_count=0,
            pii_masked_count=0,
            routing_target="ENTERPRISE_CONNECTOR_HITL_GATEWAY",
            tool_invocations=[invocation.to_dict()],
            security_risk_level="BAJO",
            cache_status="BYPASSED_WRITE_OPERATION",
        )
        return {
            "status": invocation.status,
            "invocation": invocation.to_dict(),
            "confirmed_by": user.email,
            "audit_receipt": audit_receipt,
        }

    def sync_external_repository(self, token: str, connector_id: str) -> dict[str, Any]:
        """Synchronize an external enterprise platform repository inheriting Active Directory ACLs."""
        user = self.idp.verify_token_and_resolve_user(token)
        sync_result = self.knowledge_sync.sync_platform_source(connector_id=connector_id, user=user)
        self.cache.invalidate_all()
        audit_receipt = self.audit_logger.log_interaction(
            event_type="EXTERNAL_PLATFORM_ACL_SYNC",
            username=user.username,
            user_department=user.primary_department,
            ad_groups=user.ad_groups,
            query_masked=f"Sincronización ACL desde '{sync_result['platform_name']}' ({sync_result['inherited_ad_group']})",
            where_filter={"department": sync_result["mapped_department"], "classification": sync_result["mapped_classification"]},
            allowed_chunk_ids=sync_result["chunk_ids"],
            blocked_chunks_count=0,
            pii_masked_count=sync_result["pii_entities_cataloged_locally"],
            routing_target="LOCAL_EMBEDDING_ACL_SYNC",
            tool_invocations=[],
            security_risk_level="BAJO",
            cache_status="CACHE_INVALIDATED",
        )
        sync_result["audit_receipt"] = audit_receipt
        return sync_result
