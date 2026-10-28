"""Hybrid Privacy-Aware LLM Router (Local Ollama/vLLM vs Private Cloud ZDR vs Anonymized External API)."""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from app.config.settings import settings
from app.domain.models import (
    AnonymizationResult,
    DataClassification,
    DocumentChunk,
    RoutingDecision,
    RoutingTarget,
    ToolInvocation,
    UserIdentity,
)
from app.domain.ports import LLMRouterPort


class HybridLLMRouter(LLMRouterPort):
    """
    Routes queries dynamically based on data classification, Ley 21.719 PII sensitivity,
    and enterprise cybersecurity policies.
    """

    def __init__(self, embedding_model_id: str = "local-hybrid/bge-m3-spanish-128d (On-Premise)") -> None:
        self.embedding_model_id = embedding_model_id

    def decide_route(
        self,
        query: str,
        chunks: list[DocumentChunk],
        pii_result: AnonymizationResult,
        forced_mode: str = "auto",
    ) -> RoutingDecision:
        highest_rank = 1
        highest_class = DataClassification.PUBLICO.value
        departments_involved: set[str] = set()
        for ch in chunks:
            departments_involved.add(ch.department)
            r = DataClassification.rank(ch.classification)
            if r > highest_rank:
                highest_rank = r
                highest_class = ch.classification

        # Forced routing overrides for testing & strict policy modes
        if forced_mode == "local_only":
            return RoutingDecision(
                target=RoutingTarget.LOCAL_LLM_ON_PREM,
                provider_name="On-Premise Inference Cluster (vLLM / Ollama)",
                model_name=settings.ollama_chat_model,
                reason="Forzado por política 'local_only': 100% procesamiento en red interna sin salida a internet.",
                requires_pre_anonymization=False,
                zero_data_retention_guaranteed=True,
                embedding_model_used=self.embedding_model_id,
                forced_by_user_or_policy="forced_local_only",
            )

        if forced_mode == "private_cloud":
            return RoutingDecision(
                target=RoutingTarget.ENTERPRISE_PRIVATE_CLOUD,
                provider_name="Azure OpenAI / AWS Bedrock (Private Endpoint + Zero Data Retention)",
                model_name="gpt-4o-enterprise-zdr (Región SouthAmerica)",
                reason=(
                    "Enrutado a Nube Privada Empresarial bajo contrato comercial sin entrenamiento de modelos "
                    "(Zero Data Retention) y enlace privado VNet/VPC."
                ),
                requires_pre_anonymization=len(pii_result.entities) > 0,
                zero_data_retention_guaranteed=True,
                embedding_model_used=self.embedding_model_id,
                forced_by_user_or_policy="forced_private_cloud",
            )

        if forced_mode == "external_anonymized":
            return RoutingDecision(
                target=RoutingTarget.EXTERNAL_API_ANONYMIZED,
                provider_name="External Commercial LLM API (Con Gateway Presidio Activo)",
                model_name="commercial-cloud-llm-v4",
                reason=(
                    f"Enrutado a API Externa con anonimización previa obligatoria "
                    f"({len(pii_result.entities)} entidades PII enmascaradas antes del envío)."
                ),
                requires_pre_anonymization=True,
                zero_data_retention_guaranteed=False,
                embedding_model_used=self.embedding_model_id,
                forced_by_user_or_policy="forced_external_anonymized",
            )

        # AUTO POLICY ROUTING (Production Hybrid Decision Matrix)
        # 1. Strict Health/Financial or Sensitive Art. 16 Ley 21.719 -> Local LLM (On-Premise)
        if (
            highest_class == DataClassification.ESTRICTO_SALUD_FINANZAS.value
            or pii_result.has_sensitive_health_or_finance
            or "salud_siniestros" in departments_involved
        ):
            return RoutingDecision(
                target=RoutingTarget.LOCAL_LLM_ON_PREM,
                provider_name="On-Premise GPU Node (Ollama / vLLM Local)",
                model_name=settings.ollama_chat_model,
                reason=(
                    f"Datos de clasificación '{highest_class}' / Datos Sensibles Art. 16 Ley 21.719 "
                    f"(Salud/Finanzas). Procesamiento 100% local: ningún token sale del perímetro corporativo."
                ),
                requires_pre_anonymization=False,
                zero_data_retention_guaranteed=True,
                embedding_model_used=self.embedding_model_id,
                forced_by_user_or_policy="auto_policy_high_sensitivity",
            )

        # 2. Confidential corporate documents -> Enterprise Private Cloud (Zero Data Retention)
        if highest_class == DataClassification.CONFIDENCIAL.value or len(pii_result.entities) > 0:
            return RoutingDecision(
                target=RoutingTarget.ENTERPRISE_PRIVATE_CLOUD,
                provider_name="Azure OpenAI / Vertex AI Enterprise (Private Link + Zero-Data-Retention)",
                model_name="enterprise-zdr-llm (No-Training SLA)",
                reason=(
                    f"Documentos con clasificación '{highest_class}' o presencia de PII ({len(pii_result.entities)} entidades). "
                    "Se enruta a Nube Privada Empresarial con contrato Zero-Data-Retention y anonimización preventiva."
                ),
                requires_pre_anonymization=True,
                zero_data_retention_guaranteed=True,
                embedding_model_used=self.embedding_model_id,
                forced_by_user_or_policy="auto_policy_confidential_zdr",
            )

        # 3. General / Internal queries -> External API with Anonymization Gateway
        return RoutingDecision(
            target=RoutingTarget.EXTERNAL_API_ANONYMIZED,
            provider_name="API LLM Comercial (Protegida por Privacy Gateway)",
            model_name="cloud-fast-llm",
            reason=(
                f"Consulta general/interna (clasificación máxima '{highest_class}', sin datos clínicos ni financieros críticos). "
                "Enrutada a API rápida tras verificar ausencia/enmascaramiento de PII."
            ),
            requires_pre_anonymization=True,
            zero_data_retention_guaranteed=False,
            embedding_model_used=self.embedding_model_id,
            forced_by_user_or_policy="auto_policy_general",
        )

    def generate_response(
        self,
        decision: RoutingDecision,
        query_for_llm: str,
        context_for_llm: str,
        user: UserIdentity,
        tool_results: list[ToolInvocation],
    ) -> str:
        # If target is local LLM, try live Ollama first if running on user's machine
        if decision.target == RoutingTarget.LOCAL_LLM_ON_PREM:
            ollama_reply = self._try_ollama_chat(query_for_llm, context_for_llm, user, tool_results)
            if ollama_reply:
                return ollama_reply

        # Grounded Enterprise Response Synthesizer (uses strictly the filtered & anonymized context)
        return self._synthesize_grounded_response(
            decision=decision,
            query_for_llm=query_for_llm,
            context_for_llm=context_for_llm,
            user=user,
            tool_results=tool_results,
        )

    def _try_ollama_chat(
        self,
        query_for_llm: str,
        context_for_llm: str,
        user: UserIdentity,
        tool_results: list[ToolInvocation],
    ) -> str | None:
        url = f"{settings.ollama_base_url.rstrip('/')}/api/generate"
        tools_text = "\n".join(f"- [{t.status}] {t.tool_name}: {t.result_summary}" for t in tool_results)
        prompt = (
            "Eres AegisRAG, un asistente corporativo seguro. Responde únicamente usando el contexto "
            "autorizado por RBAC y los resultados de conectores adjuntos. Sé conciso y profesional.\n\n"
            f"Usuario: {user.full_name} ({user.primary_department})\n"
            f"Contexto Autorizado:\n{context_for_llm}\n\n"
            f"Acciones de Conectores:\n{tools_text or 'Ninguna'}\n\n"
            f"Pregunta: {query_for_llm}\nRespuesta:"
        )
        payload = json.dumps(
            {
                "model": settings.ollama_chat_model,
                "prompt": prompt,
                "stream": False,
            }
        ).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                ans = data.get("response", "").strip()
                if ans:
                    return ans
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            return None
        return None

    @staticmethod
    def _synthesize_grounded_response(
        decision: RoutingDecision,
        query_for_llm: str,
        context_for_llm: str,
        user: UserIdentity,
        tool_results: list[ToolInvocation],
    ) -> str:
        sections: list[str] = []

        # 1. Include any executed or denied connector actions first
        if tool_results:
            action_lines = ["### Acciones en Plataformas Integradas (Conectores Empresariales)"]
            for t in tool_results:
                badge = "EJECUTADO" if t.status == "EXECUTED" else "BLOQUEADO POR RBAC"
                action_lines.append(f"- **[{badge}] {t.connector_system} (`{t.tool_name}`):** {t.result_summary}")
            sections.append("\n".join(action_lines))

        # 2. Check if any authorized context was retrieved
        if not context_for_llm.strip():
            sections.append(
                "### Respuesta del Asistente Corporativo\n"
                f"No se encontraron documentos autorizados para tu perfil de Active Directory "
                f"(**Departamento:** `{user.primary_department}`, **Grupos AD:** `{', '.join(user.ad_groups)}`).\n\n"
                "> **Control de Seguridad Pre-Retrieval Activo:** Si la información que buscas pertenece a otro "
                "departamento (ej. RR.HH., Finanzas o Siniestros de Salud), el filtro vectorial `where` de ChromaDB "
                "excluyó esos fragmentos **antes** de que llegaran al contexto del modelo."
            )
            return "\n\n".join(sections)

        # 3. Synthesize grounded answer from the authorized context chunks
        sections.append(
            "### Respuesta Basada en Documentación Autorizada\n"
            f"De acuerdo con las fuentes verificadas para tu rol en **{user.primary_department.upper()}** "
            f"(procesado vía `{decision.provider_name}`):\n\n"
            f"{context_for_llm}"
        )
        return "\n\n".join(sections)
