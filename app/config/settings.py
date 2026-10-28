"""Enterprise RAG Configuration & Security Policy Settings."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
STORAGE_DIR = BASE_DIR / "storage"
STORAGE_DIR.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True)
class EnterpriseSettings:
    """Centralized configuration supporting 12-Factor App environment overrides."""

    app_name: str = os.getenv("APP_NAME", "AegisRAG Enterprise - Plataforma Agentic RAG")
    environment: str = os.getenv("ENVIRONMENT", "development")
    host: str = os.getenv("HOST", "127.0.0.1")
    port: int = int(os.getenv("PORT", "8080"))

    # Identity Provider (Active Directory / Microsoft Entra ID)
    idp_mode: str = os.getenv("IDP_MODE", "mock_ad")  # mock_ad | entra_id_msal | ad_ldap
    jwt_secret: str = os.getenv("JWT_SECRET", "enterprise-rag-super-secret-signing-key-2026-ley21719")
    jwt_issuer: str = os.getenv("JWT_ISSUER", "https://login.corporativo.cl/entra-id/v2.0")
    jwt_audience: str = os.getenv("JWT_AUDIENCE", "api://enterprise-rag-assistant")
    jwt_ttl_seconds: int = int(os.getenv("JWT_TTL_SECONDS", "3600"))

    # Microsoft Entra ID (Azure AD) Production Settings
    entra_tenant_id: str = os.getenv("ENTRA_TENANT_ID", "")
    entra_client_id: str = os.getenv("ENTRA_CLIENT_ID", "")
    entra_client_secret: str = os.getenv("ENTRA_CLIENT_SECRET", "")

    # On-Premise Active Directory LDAP Production Settings
    ldap_server_uri: str = os.getenv("LDAP_SERVER_URI", "ldaps://dc01.corporativo.local:636")
    ldap_base_dn: str = os.getenv("LDAP_BASE_DN", "DC=corporativo,DC=local")

    # Vector Database & Local Embeddings Settings
    vector_store_backend: str = os.getenv("VECTOR_STORE_BACKEND", "auto")  # auto | chromadb | memory_hybrid
    chroma_persist_dir: str = os.getenv("CHROMA_PERSIST_DIR", str(STORAGE_DIR / "chroma_db"))
    strict_collection_isolation: bool = os.getenv("STRICT_COLLECTION_ISOLATION", "true").lower() == "true"

    # Embeddings: ALWAYS local by default so raw documents never leave company perimeter
    embedding_provider: str = os.getenv("EMBEDDING_PROVIDER", "local_hybrid")  # ollama_local | local_hybrid
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    ollama_embedding_model: str = os.getenv("OLLAMA_EMBEDDING_MODEL", "nomic-embed-text")

    # Hybrid LLM Routing Settings
    ollama_chat_model: str = os.getenv("OLLAMA_CHAT_MODEL", "llama3.1:8b")
    vllm_base_url: str = os.getenv("VLLM_BASE_URL", "")
    private_cloud_provider: str = os.getenv("PRIVATE_CLOUD_PROVIDER", "azure_openai_zdr")  # Zero Data Retention
    private_cloud_endpoint: str = os.getenv("PRIVATE_CLOUD_ENDPOINT", "")
    private_cloud_api_key: str = os.getenv("PRIVATE_CLOUD_API_KEY", "")
    external_api_endpoint: str = os.getenv("EXTERNAL_API_ENDPOINT", "")
    external_api_key: str = os.getenv("EXTERNAL_API_KEY", "")

    # Privacy & Ley 21.719 Compliance
    enable_pii_anonymization: bool = os.getenv("ENABLE_PII_ANONYMIZATION", "true").lower() == "true"
    allow_pii_rehydration_for_authorized_roles: bool = True
    audit_db_path: str = os.getenv("AUDIT_DB_PATH", str(STORAGE_DIR / "enterprise_audit.sqlite3"))

    # Department list recognized by the platform
    departments: tuple[str, ...] = field(
        default=(
            "salud_siniestros",
            "finanzas",
            "rrhh",
            "legal_cumplimiento",
            "ti_operaciones",
            "comercial",
            "publico_corporativo",
        )
    )


settings = EnterpriseSettings()
