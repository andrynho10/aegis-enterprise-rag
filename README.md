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

5. **Conectores Empresariales Accionables (`app/connectors/enterprise_tools.py`):**
   - Capacidad de **leer y accionar** sobre **Core Seguros (Siniestros)**, **SAP S/4HANA ERP (Finanzas)**, **Buk/Workday (RR.HH.)** y **ServiceNow GRC**, validando RBAC de escritura antes de cada ejecución.

6. **Auditoría Inmutable Criptográfica & Derechos ARCO Ley 21.719 (`app/compliance/audit_arco.py`):**
   - Registro SQLite encadenado por hash SHA-256 (*tamper-evident*) de quién preguntó qué, qué `chunk_ids` se usaron, cuántos fragmentos de otras áreas fueron bloqueados y qué modelo respondió.
   - Endpoint de **Derecho de Supresión / Olvido (ARCO)** que purga todos los vectores asociados al RUT de un titular.

---

## Ejecución Rápida (Zero-Friction)

### 1. Ejecutar la suite de pruebas automatizadas (7 tests de seguridad y cumplimiento)
```powershell
C:\Users\andry\AppData\Local\Programs\Python\Python312\python.exe -m unittest discover -s tests -t . -v
```

### 2. Iniciar el Servidor y Dashboard Web Interactivo
```powershell
C:\Users\andry\AppData\Local\Programs\Python\Python312\python.exe run_server.py
```
Luego abre en tu navegador: **`http://127.0.0.1:8080`**
