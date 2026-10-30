# Changelog — AegisRAG Enterprise

Todos los cambios relevantes en la evolución arquitectónica de este proyecto están documentados aquí siguiendo [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/) y [Semantic Versioning](https://semver.org/lang/es/).

## [v2.4.0] — Telemetría FinOps/ANCI en Consola Web y Suite de 14 Tests
### Added
- Panel en tiempo real de Alertas Tempranas ANCI (Ley 21.663 — SLA 3 horas CSIRT) y métricas FinOps/Zero-Data-Retention en la consola interactiva (`app/web/index.html`, `app/api/controllers.py`).
- Ampliación de la suite automatizada a **14 pruebas** (`tests/test_enterprise_rag.py`) verificando auto-upgrade DLP de datos sensibles mal etiquetados, chunking semántico multi-sección y alertas ANCI.

## [v2.3.0] — Chunking Semántico con Auto-Clasificación DLP (Ley 21.719) y Monitor ANCI (Ley 21.663)
### Added
- Procesador documental con chunking semántico estructurado y clasificador automático DLP (`app/rag/document_processor.py`): eleva automáticamente a `estricto_salud_finanzas` cualquier documento subido por error como `publico` o `interno` si detecta diagnósticos CIE-10, RUTs o datos financieros críticos.
- Monitor de incidentes bajo **Ley 21.663 Marco de Ciberseguridad (ANCI / CSIRT)** con ventana legal de 3 horas para Servicios Esenciales / OIVs y KPIs FinOps (`app/compliance/anci_incident_monitor.py`).

## [v2.2.0] — Pipeline CI/CD de Seguridad, Contenedorización y Suite Red-Team (11 Tests)
### Added
- Workflow de integración continua y certificación normativa en GitHub Actions (`.github/workflows/ci-security.yml`).
- `Dockerfile` con usuario de servicio sin privilegios (`aegis`) siguiendo el principio de mínimo privilegio.
- Ampliación de la suite automatizada a 11 pruebas de verificación (`tests/test_enterprise_rag.py`) cubriendo flujo *Human-in-the-Loop*, sincronización con herencia ACL y benchmark Red-Team al 100%.

## [v2.1.0] — Gobernanza Human-in-the-Loop (HITL), Sincronización ACL y Evaluador Red-Team
### Added
- Flujo de aprobación humana en dos pasos (*Human-in-the-Loop*) para acciones de escritura críticas en Core Seguros, SAP ERP y Buk HCM (`POST /api/v1/rag/actions/confirm`).
- Conectores de sincronización documental con herencia automática de grupos Active Directory (`GRP_AD_*`) hacia metadatos de ChromaDB (`app/connectors/knowledge_sync.py`, `POST /api/v1/connectors/sync`).
- Motor automatizado de Red-Teaming y certificación de controles Ley 21.719 / Ley 21.663 con 6 sondas de ataque en tiempo real (`app/security/redteam_evaluator.py`, `POST /api/v1/compliance/redteam`).

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
