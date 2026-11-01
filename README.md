# AegisRAG Enterprise — Sistema Agentic RAG Escalable y Cumplimiento Normativo (Ley 21.719 / Ley 21.663)

Plataforma de **Generación Aumentada por Recuperación y Acción Empresarial (Agentic RAG)** diseñada bajo **Arquitectura Hexagonal (Ports & Adapters)** para industrias reguladas (Seguros, Salud, Banca y Corporaciones).

---

## Pilares Arquitectónicos Implementados

1. **Identidad Federada SSO & RBAC (`app/security/ad_providers.py`, `jwt_manager.py`, `rbac_engine.py`):**
   - Integración nativa con **Microsoft Entra ID (OIDC/MSAL)** y **Active Directory On-Premise (`ldap3`)**, más un simulador local OIDC/JWT para pruebas inmediatas.
   - Hereda el MFA corporativo y revoca el acceso en tiempo real cuando una cuenta es desvinculada (*offboarding*).
   - Mapea grupos de AD (`GRP_AD_SALUD_LIQUIDADORES`, `GRP_AD_FINANZAS_ANALISTAS`, `GRP_AD_RRHH_GESTION`, `GRP_AD_LEGAL_CUMPLIMIENTO`, `GRP_AD_TI_OPERACIONES`) a permisos de mínimo privilegio.

2. **Aislamiento Exclusivo entre Departamentos — *Permission-Aware Retrieval* (`app/rag/vector_store.py`):**
   - **El control de acceso ocurre en la capa de recuperación vectorial, nunca en el prompt.**
   - Doble barrera en ChromaDB / Motor Híbrido:
     - **Aislamiento por Colección:** Cada departamento indexa en su propia colección (`col_salud_siniestros`, `col_finanzas`, `col_rrhh`, etc.).
     - **Filtro Pre-Retrieval (`where`):** Construido en el servidor desde las *claims* verificadas del token JWT antes de ejecutar la búsqueda semántica, haciéndolo **inmune a ataques de Prompt Injection**.

3. **Embeddings 100% Locales & Caché Semántico Aislado (`app/rag/embeddings.py`, `scoped_cache.py`):**
   - Los vectores se calculan localmente (Ollama `nomic-embed-text` / `bge-m3` o motor semántico local en CPU), garantizando que los documentos fuente **jamás** salgan a APIs externas durante la indexación.
   - El caché particiona sus llaves criptográficas por el hash de permisos del usuario (`SHA256(query + rbac_scope)`), impidiendo fugas de respuestas entre usuarios de distintos departamentos.

4. **Gateway de Privacidad PII y Enrutamiento Híbrido (`app/security/pii_anonymizer.py`, `app/rag/llm_router.py`):**
   - Detecta y enmascara **RUT chileno** (con validador Módulo-11), **diagnósticos clínicos CIE-10** (Art. 16 Datos Sensibles Ley 21.719), pólizas/siniestros, cuentas bancarias, nombres, correos y teléfonos con placeholders reversibles (`<RUT_CHILENO_1>`, `<DIAGNOSTICO_SALUD_CIE10_1>`).
   - **Router Híbrido:**
     - *Consultas con datos sensibles de Salud/Finanzas:* Enrutadas a **LLM Local On-Premise** (Ollama / vLLM).
     - *Consultas confidenciales corporativas:* Enrutadas a **Nube Privada Empresarial** (Azure OpenAI / AWS Bedrock / Vertex AI con contrato *Zero-Data-Retention* sin entrenamiento de modelos).
     - *Consultas generales/públicas:* Enrutadas a API externa **únicamente** después de anonimizar PII.

5. **Conectores Empresariales Accionables, Protocolo MCP JSON-RPC 2.0 y Gobernanza *Human-in-the-Loop* (`app/connectors/enterprise_tools.py`, `mcp_server_adapter.py`, `knowledge_sync.py`):**
   - Capacidad de **leer y accionar** sobre **Core Seguros (Siniestros)**, **SAP S/4HANA ERP (Finanzas)**, **Buk/Workday (RR.HH.)** y **ServiceNow GRC**, validando RBAC de escritura antes de cada ejecución.
   - **Servidor Model Context Protocol (MCP) JSON-RPC 2.0 (`POST /api/v1/mcp/rpc`):** Expone `initialize`, `tools/list`, `tools/call`, `resources/list` y `resources/read` filtrando recursos por el alcance RBAC de Active Directory y enmascarando PII según Ley 21.719.
   - **Re-Ranker de Dos Etapas (`RRF` + Cross-Encoder en `app/rag/reranker.py`):** Combina similitud densa y léxica mediante *Reciprocal Rank Fusion* ($k=60$) con verificación Cross-Encoder de códigos exactos (`RUT`, `CIE-10`, `SIN-*`, `FAC-*`).
   - **Aprobación Humana en Dos Pasos (HITL):** Las mutaciones financieras o clínicas generan propuestas pendientes (`HITL_CONFIRMATION_REQUIRED`) que requieren confirmación explícita del usuario autorizado (`POST /api/v1/rag/actions/confirm`).
   - **Sincronización con Herencia ACL de Active Directory:** Ingesta desde SharePoint, SAP DMS, Buk HCM y ServiceNow heredando el grupo de seguridad AD (`GRP_AD_*`) directamente hacia los metadatos de ChromaDB (`POST /api/v1/connectors/sync`).

6. **Auditoría Inmutable Criptográfica, Derechos ARCO Ley 21.719, DLP, Monitor ANCI Ley 21.663 y ADRs (`app/compliance/audit_arco.py`, `anci_incident_monitor.py`, `docs/ARCHITECTURE_DECISIONS_ADR.md`):**
   - Registro SQLite encadenado por hash SHA-256 (*tamper-evident*) de quién preguntó qué, qué `chunk_ids` se usaron, cuántos fragmentos de otras áreas fueron bloqueados y qué modelo respondió.
   - **Auto-Clasificación DLP en Ingesta (Ley 21.719 Art. 16 Safety Net):** Si un documento con diagnósticos CIE-10 o datos financieros se sube por error humano como `publico`, el procesador semántico lo eleva automáticamente a `estricto_salud_finanzas`.
   - **Monitor de Incidentes ANCI / CSIRT (Ley 21.663 — SLA 3 Horas) y FinOps:** Genera alertas tempranas ante intentos de *Prompt Injection* o uso no autorizado de conectores (`OWASP LLM01 / LLM08`) y mide el ahorro FinOps y el ratio de *Zero-Data-Retention*.
   - Endpoint de **Derecho de Supresión / Olvido (ARCO)** que purga todos los vectores asociados al RUT de un titular.
   - **Benchmark Red-Team Continuo (`POST /api/v1/compliance/redteam`)** y **5 Architecture Decision Records (`docs/ARCHITECTURE_DECISIONS_ADR.md`)**.

---

## Ejecución Rápida (Zero-Friction)

### 1. Ejecutar la suite de pruebas automatizadas (22 tests de seguridad, DLP, RRF Re-Ranker, MCP JSON-RPC 2.0, Groundedness, HITL, ACL, ANCI y Red-Team)
```powershell
C:\Users\andry\AppData\Local\Programs\Python\Python312\python.exe -m unittest discover -s tests -t . -v
```

### 2. Ejecutar la demostración interactiva de los 7 escenarios en terminal
```powershell
C:\Users\andry\AppData\Local\Programs\Python\Python312\python.exe demo_cli.py
```

### 3. Iniciar el Servidor y Dashboard Web Interactivo
```powershell
C:\Users\andry\AppData\Local\Programs\Python\Python312\python.exe run_server.py
```
Luego abre en tu navegador: **`http://127.0.0.1:8080`**
