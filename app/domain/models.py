"""Core Domain Models for the Enterprise Agentic RAG System."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class DataClassification(str, Enum):
    """Information security classification aligned with ISO 27001 & Ley 21.719 (Chile)."""

    PUBLICO = "publico"
    INTERNO = "interno"
    CONFIDENCIAL = "confidencial"
    ESTRICTO_SALUD_FINANZAS = "estricto_salud_finanzas"

    @classmethod
    def rank(cls, value: str) -> int:
        order = {
            cls.PUBLICO.value: 1,
            cls.INTERNO.value: 2,
            cls.CONFIDENCIAL.value: 3,
            cls.ESTRICTO_SALUD_FINANZAS.value: 4,
        }
        return order.get(value, 1)


class AppRole(str, Enum):
    """Application RBAC roles mapped from Active Directory / Entra ID security groups."""

    LECTOR_GENERAL = "lector_general"
    ANALISTA_DEPARTAMENTO = "analista_departamento"
    ESPECIALISTA_AUTORIZADO = "especialista_autorizado"
    GESTOR_DOCUMENTAL = "gestor_documental"
    AUDITOR_CUMPLIMIENTO = "auditor_cumplimiento"
    ADMIN_SEGURIDAD = "admin_seguridad"


class RoutingTarget(str, Enum):
    """Target execution environment selected by the Hybrid Privacy Router."""

    LOCAL_LLM_ON_PREM = "local_llm_on_prem"  # Ollama / vLLM (Zero data leaves corporate network)
    ENTERPRISE_PRIVATE_CLOUD = "enterprise_private_cloud"  # Azure OpenAI / Bedrock / Vertex (Zero-Data-Retention + Private Link)
    EXTERNAL_API_ANONYMIZED = "external_api_anonymized"  # Public API after mandatory PII masking


@dataclass
class UserIdentity:
    """Authenticated corporate user resolved from Active Directory / Entra ID token."""

    user_id: str
    username: str
    full_name: str
    email: str
    job_title: str
    primary_department: str
    allowed_departments: list[str]
    ad_groups: list[str]
    roles: list[str]
    max_classification: str
    can_view_raw_pii: bool = False
    can_execute_write_actions: bool = False
    mfa_verified: bool = True
    idp_source: str = "Microsoft Entra ID (OIDC/JWT)"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DocumentChunk:
    """Vector-indexed document chunk with mandatory security & compliance metadata."""

    chunk_id: str
    document_id: str
    title: str
    content: str
    department: str
    classification: str
    allowed_roles: list[str]
    source_system: str  # e.g., "SharePoint Finanzas", "Core Seguros Siniestros", "Buk RRHH"
    titular_rut: str = ""  # Used for Ley 21.719 ARCO (Right to Erasure / Access)
    contains_pii: bool = False
    created_at: str = ""
    embedding: list[float] = field(default_factory=list)
    score: float = 0.0

    def to_dict(self, include_embedding: bool = False) -> dict[str, Any]:
        data = asdict(self)
        if not include_embedding:
            data.pop("embedding", None)
        return data


@dataclass
class PIIEntity:
    """Detected Personal Identifiable Information or sensitive health/financial entity."""

    entity_type: str  # RUT_CHILENO, DIAGNOSTICO_SALUD_CIE10, PERSONA, EMAIL, TELEFONO, POLIZA, MONTO_FINANCIERO
    original_value: str
    placeholder: str
    start: int
    end: int
    sensitivity: str  # DATO_PERSONAL | DATO_SENSIBLE_ART16_LEY21719


@dataclass
class AnonymizationResult:
    """Result of passing text through the Privacy & Anonymization Gateway."""

    original_text: str
    anonymized_text: str
    entities: list[PIIEntity] = field(default_factory=list)
    vault_mapping: dict[str, str] = field(default_factory=dict)  # placeholder -> original_value
    has_sensitive_health_or_finance: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_text": self.original_text,
            "anonymized_text": self.anonymized_text,
            "entities": [asdict(e) for e in self.entities],
            "pii_count": len(self.entities),
            "has_sensitive_health_or_finance": self.has_sensitive_health_or_finance,
        }


@dataclass
class RoutingDecision:
    """Telemetry and policy justification produced by the Hybrid LLM Router."""

    target: RoutingTarget
    provider_name: str
    model_name: str
    reason: str
    requires_pre_anonymization: bool
    zero_data_retention_guaranteed: bool
    embedding_model_used: str = "local/bge-m3-hybrid (On-Premise)"
    forced_by_user_or_policy: str = "auto_policy"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["target"] = self.target.value
        return data


@dataclass
class RetrievalResult:
    """Output of Permission-Aware Vector Retrieval showing allowed vs blocked metrics."""

    allowed_chunks: list[DocumentChunk]
    applied_where_filter: dict[str, Any]
    collections_searched: list[str]
    total_candidates_before_rbac: int
    blocked_by_rbac_count: int
    blocked_departments_preview: list[dict[str, str]]  # Metadata-only summary for audit/telemetry (never content!)


@dataclass
class ToolInvocation:
    """Result of evaluating or executing an actionable enterprise connector."""

    tool_name: str
    connector_system: str
    action_type: str  # READ | WRITE
    status: str  # EXECUTED | RBAC_DENIED | HITL_CONFIRMATION_REQUIRED | SKIPPED
    required_department: str
    parameters: dict[str, Any]
    result_summary: str
    raw_output: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
