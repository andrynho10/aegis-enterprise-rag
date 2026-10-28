# Changelog — AegisRAG Enterprise

Todos los cambios relevantes en la evolución arquitectónica de este proyecto están documentados aquí siguiendo [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/) y [Semantic Versioning](https://semver.org/lang/es/).

## [v2.0.0] — Consola Interactiva, API REST y Suite de Verificación
### Added
- Controladores REST desacoplados (`app/api/controllers.py`) y adaptador OpenAPI/Swagger con FastAPI (`app/api/fastapi_app.py`).
- Servidor unificado zero-dependency (`run_server.py`) y consola web interactiva (`app/web/index.html`) con cambio de usuario AD en vivo, inspector de JWT/filtro `where` y telemetría de privacidad.
- Suite automatizada con 8 pruebas de seguridad, aislamiento departamental, anonimización PII y derechos ARCO (`tests/test_enterprise_rag.py`).

## [v1.2.0] — Cumplimiento Ley 21.719 (ARCO), Auditoría Criptográfica y Orquestador
### Added
- Registro de auditoría inmutable encadenado con hash SHA-256 (`prev_hash -> entry_hash`) sobre SQLite (`app/compliance/audit_arco.py`).
- Ejecución del Derecho de Supresión / Olvido ARCO (Ley 21.719) por RUT titular en todas las colecciones vectoriales.
- Orquestador Agentic RAG de 8 etapas (`app/rag/orchestrator.py`) y corpus empresarial semilla (`app/data/seed_corpus.py`).

## [v1.0.0] — Router Híbrido de LLMs y Conectores Empresariales Accionables
### Added
- Router Híbrido (`app/rag/llm_router.py`): enruta datos sensibles Art. 16 Ley 21.719 (Salud/Finanzas) a LLM Local (Ollama/vLLM), datos confidenciales a Nube Privada con *Zero-Data-Retention* (Azure OpenAI / Bedrock) y consultas generales a API Externa Anonimizada.
- Registro de conectores accionables (`app/connectors/enterprise_tools.py`) para Core Seguros (Siniestros), SAP S/4HANA ERP (Finanzas), Buk/Workday (RR.HH.) y ServiceNow GRC con control RBAC de escritura.

## [v0.3.0] — Permission-Aware Retrieval, Embeddings Locales y Caché Particionado
### Added
- Proveedor de embeddings 100% locales (`app/rag/embeddings.py`) para impedir exfiltración de documentos al vectorizar.
- Base vectorial con aislamiento por colección departamental y filtro duro Pre-Retrieval `where` (`app/rag/vector_store.py`).
- Caché semántico particionado por hash de permisos RBAC (`app/rag/scoped_cache.py`) para evitar fugas de respuestas entre roles.

## [v0.2.0] — Identidad Active Directory / Entra ID (SSO), RBAC y Anonimización PII
### Added
- Gestor OIDC/JWT RFC 7519 (`app/security/jwt_manager.py`) y adaptadores para Microsoft Entra ID (`msal`), Active Directory LDAPS (`ldap3`) y simulador local con revocación en offboarding (`app/security/ad_providers.py`).
- Motor RBAC de mínimo privilegio y detector de *Prompt Injection* (`app/security/rbac_engine.py`).
- Motor de anonimización PII reversible (`app/security/pii_anonymizer.py`) con validador de RUT chileno (Módulo-11), diagnósticos CIE-10 y adaptador Microsoft Presidio.

## [v0.1.0] — Arquitectura Hexagonal Base y Modelos de Dominio
### Added
- Configuración centralizada 12-Factor (`app/config/settings.py`), entidades de dominio (`app/domain/models.py`) y puertos/interfaces hexagonales (`app/domain/ports.py`).
