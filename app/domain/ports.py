"""Hexagonal Architecture Ports (Interfaces) for Enterprise Scalability."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from app.domain.models import (
    AnonymizationResult,
    DocumentChunk,
    RetrievalResult,
    RoutingDecision,
    ToolInvocation,
    UserIdentity,
)


class IdentityProviderPort(ABC):
    """Port for authenticating users against Active Directory / Microsoft Entra ID."""

    @abstractmethod
    def authenticate_and_issue_token(self, username: str) -> tuple[str, UserIdentity]:
        """Authenticate corporate identity and issue signed JWT containing AD groups."""

    @abstractmethod
    def verify_token_and_resolve_user(self, token: str) -> UserIdentity:
        """Validate JWT signature/claims and map AD security groups to RBAC permissions."""

    @abstractmethod
    def list_directory_users(self) -> list[UserIdentity]:
        """List directory identities available in the current environment."""


class EmbeddingProviderPort(ABC):
    """Port for generating vector embeddings (strictly local by default for data privacy)."""

    @property
    @abstractmethod
    def model_identifier(self) -> str:
        """Human-readable identifier of the local embedding model."""

    @abstractmethod
    def embed_text(self, text: str) -> list[float]:
        """Compute embedding vector for a single document chunk or query."""


class VectorStorePort(ABC):
    """Port for Permission-Aware Vector Database (ChromaDB / Qdrant / Hybrid)."""

    @abstractmethod
    def upsert_chunks(self, chunks: list[DocumentChunk]) -> int:
        """Index document chunks with mandatory department & classification metadata."""

    @abstractmethod
    def retrieve_permission_aware(
        self,
        query: str,
        user: UserIdentity,
        top_k: int = 4,
    ) -> RetrievalResult:
        """Execute pre-filtered vector search strictly scoped by the user's RBAC permissions."""

    @abstractmethod
    def delete_by_titular_rut(self, rut: str) -> list[str]:
        """Execute Ley 21.719 ARCO Right-to-Erasure across all collections for a given RUT."""

    @abstractmethod
    def list_all_chunks_metadata(self) -> list[dict[str, Any]]:
        """Return metadata inventory (without leaking restricted text content)."""


class PrivacyGuardPort(ABC):
    """Port for PII Detection, Anonymization (Presidio / Chilean RUT & Health) and Rehydration."""

    @abstractmethod
    def anonymize(self, text: str) -> AnonymizationResult:
        """Detect and replace PII & sensitive health/financial entities with reversible tokens."""

    @abstractmethod
    def rehydrate(self, text: str, vault_mapping: dict[str, str], user: UserIdentity) -> str:
        """Restore original PII values only if the user's RBAC profile authorizes raw PII view."""


class LLMRouterPort(ABC):
    """Port for Hybrid LLM Routing (Local Ollama/vLLM vs Private Cloud vs Anonymized API)."""

    @abstractmethod
    def decide_route(
        self,
        query: str,
        chunks: list[DocumentChunk],
        pii_result: AnonymizationResult,
        forced_mode: str = "auto",
    ) -> RoutingDecision:
        """Select optimal LLM execution target based on classification, PII, and policy."""

    @abstractmethod
    def generate_response(
        self,
        decision: RoutingDecision,
        query_for_llm: str,
        context_for_llm: str,
        user: UserIdentity,
        tool_results: list[ToolInvocation],
    ) -> str:
        """Generate grounded response using the routed model."""
