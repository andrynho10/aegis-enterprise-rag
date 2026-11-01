# Architecture Decision Records (ADRs) — AegisRAG Enterprise

Este documento registra las decisiones arquitectónicas fundamentales (**ADRs**) tomadas durante el diseño e implementación de **AegisRAG Enterprise**, justificando técnica y regulatoriamente cada elección frente a los estándares de ciberseguridad corporativa (**ISO/IEC 27001**, **OWASP Top 10 for LLM Applications**) y la legislación chilena vigente (**Ley 21.719 de Protección de Datos Personales**, **Ley 21.663 Marco de Ciberseguridad / ANCI** y normativas **CMF** para seguros y servicios financieros).

---

## ADR-001: Control de Acceso Pre-Retrieval en Base Vectorial vs. Filtrado por System Prompt

- **Estado:** Aceptado e Implementado (`v0.3.0+`)
- **Módulos:** [`app/rag/vector_store.py`](../app/rag/vector_store.py), [`app/security/rbac_engine.py`](../app/security/rbac_engine.py)

### Contexto
En una organización con múltiples áreas sensibles (Siniestros de Salud, Finanzas SAP, Recursos Humanos, Legal/Cumplimiento), un asistente RAG jamás debe permitir que un colaborador consulte información de otro departamento que no le compete. Un error común en implementaciones ingenuas consiste en recuperar los $k$ fragmentos más similares de toda la base documental y luego instruir al LLM en el prompt del sistema: *"No respondas con información de RR.HH. si el usuario pertenece a Finanzas"*.

### Decisión
1. **Prohibición absoluta de control de acceso basado en prompt:** El prompt del sistema no se considera una barrera de seguridad válida, ya que es vulnerable a ataques de *Prompt Injection* directo e indirecto (*OWASP LLM01*).
2. **Inyección determinista de filtro `where` antes de la búsqueda vectorial (*Permission-Aware Retrieval*):** Los grupos de seguridad provenientes del token OIDC/JWT de **Microsoft Entra ID / Active Directory** (`GRP_AD_*`) se resuelven en el backend a departamentos y niveles de clasificación permitidos:
   ```json
   {
     "$and": [
       {"department": {"$in": ["finanzas", "publico_corporativo"]}},
       {"classification": {"$in": ["publico", "interno", "confidencial"]}}
     ]
   }
   ```
3. **Aislamiento físico por colección departamental:** Además del filtro lógico `where`, los documentos de alta sensibilidad se almacenan en colecciones físicamente particionadas por departamento (`col_dept_salud_siniestros`, `col_dept_finanzas`, `col_dept_rrhh`, etc.).

### Consecuencias
- **Positivas:** Si un fragmento documental no pertenece al alcance RBAC del usuario, **nunca entra en la ventana de contexto del LLM**. Incluso si un atacante logra inyectar `IGNORE ALL PREVIOUS INSTRUCTIONS`, el contexto del modelo simplemente carece de los datos de otras áreas.
- **Trazabilidad:** Cada consulta registra en la cadena de auditoría cuántos fragmentos candidatos fueron bloqueados por RBAC antes de llegar al modelo.

---

## ADR-002: Generación 100% Local de Embeddings (*Zero Document Exfiltration*)

- **Estado:** Aceptado e Implementado (`v0.3.0+`)
- **Módulos:** [`app/rag/embeddings.py`](../app/rag/embeddings.py), [`app/rag/reranker.py`](../app/rag/reranker.py)

### Contexto
Muchas arquitecturas híbridas configuran un LLM local (`Ollama` / `vLLM`) creyendo que con ello ningún dato abandona la empresa, pero utilizan una API externa (ej. `text-embedding-3-large`) para vectorizar los documentos durante la ingesta y la consulta.

### Decisión
1. **Los embeddings también son datos:** Enviar el texto íntegro de pólizas médicas, liquidaciones de sueldo o contratos a una API externa para obtener vectores constituye una transferencia internacional de datos personales y confidenciales en el momento mismo de la indexación.
2. **Vectorización y Re-Ranking 100% On-Premise:** Tanto el motor de embeddings híbridos como el re-ranker de dos etapas (**Reciprocal Rank Fusion `RRF` + Cross-Encoder**) se ejecutan íntegramente dentro del perímetro local (`local-bge-m3-es-enterprise-384d` / `sentence-transformers` on-premise).

### Consecuencias
- **Positivas:** Garantiza **Cero Exfiltración Documental** durante la indexación de repositorios corporativos (SharePoint, Buk, SAP, Core Seguros).
- **Precisión:** La combinación de similitud densa con fusión de ranking recíproco (`RRF`) y Cross-Encoder local logra alta precisión en códigos exactos (`RUT`, `CIE-10`, números de póliza `POL-*`, facturas `FAC-*`) sin depender de APIs externas.

---

## ADR-003: Particionamiento Criptográfico del Caché Semántico por Alcance RBAC

- **Estado:** Aceptado e Implementado (`v0.3.0+`)
- **Módulo:** [`app/rag/scoped_cache.py`](../app/rag/scoped_cache.py)

### Contexto
Para reducir costos de inferencia y latencia, los sistemas RAG almacenan respuestas en caché. Sin embargo, si dos usuarios con distintos privilegios formulan exactamente la misma pregunta (ej. *"¿Cuál es el resumen ejecutivo de auditoría y presupuestos del Q3?"*), un caché global indexado únicamente por el texto de la pregunta devolvería al usuario sin privilegios la respuesta previamente generada para un directivo o auditor (*Cross-Role Cache Poisoning / Leakage*).

### Decisión
Toda clave de caché incorpora obligatoriamente un hash criptográfico `SHA-256` que combina la consulta normalizada con el alcance RBAC efectivo del usuario y su permiso de visualización de PII:
$$\text{CacheKey} = \text{SHA256}\left(\text{Query}_{\text{norm}} \;\parallel\; \text{Depts}_{\text{sorted}} \;\parallel\; \text{Classifications}_{\text{sorted}} \;\parallel\; \text{CanViewRawPII} \;\parallel\; \text{RoutingMode}\right)$$

### Consecuencias
- **Positivas:** Elimina por completo la filtración accidental de información a través del caché entre usuarios de distintos departamentos o roles.
- **Observabilidad:** El motor detecta y contabiliza (`prevented_cross_role_leaks`) cada vez que una consulta idéntica habría colisionado en un caché ingenuo pero fue aislada en su partición RBAC correspondiente.

---

## ADR-004: Privacidad Reversible (Presidio + RUT Módulo-11 + CIE-10) y Enrutamiento Híbrido (Ley 21.719 / Ley 21.663)

- **Estado:** Aceptado e Implementado (`v0.2.0` – `v2.4.0`)
- **Módulos:** [`app/security/pii_anonymizer.py`](../app/security/pii_anonymizer.py), [`app/rag/llm_router.py`](../app/rag/llm_router.py), [`app/rag/document_processor.py`](../app/rag/document_processor.py)

### Contexto
En la industria aseguradora y financiera chilena se procesan datos personales sensibles protegidos por el **Art. 16 de la Ley 21.719** (vigencia prevista para el 1 de diciembre de 2026, con proyecto de prórroga en el Senado al 1 de diciembre de 2027), tales como diagnósticos clínicos **CIE-10**, **RUT**, números de póliza/siniestro y cuentas bancarias. Usar exclusivamente modelos locales puede limitar el razonamiento en consultas generales, mientras que enviar todo a una API pública vulnera la normativa.

### Decisión
1. **Anonimización Reversible Pre-LLM:** Antes de invocar cualquier modelo externo, el gateway de privacidad ejecuta reconocedores deterministas (incluyendo validación matemática **Módulo-11** para RUT chileno y catálogo clínico **CIE-10**) reemplazando las entidades por tokens sintéticos (`<RUT_CHILENO_1>`, `<DIAGNOSTICO_CIE10_1>`). La bóveda en memoria (`vault_mapping`) solo rehidrata los valores originales si el rol del usuario en Active Directory posee `can_view_raw_pii=True`.
2. **DLP Auto-Upgrade en Ingesta:** Si un usuario intenta indexar un documento con diagnósticos CIE-10 o RUTs bajo clasificación `publico` o `interno`, el procesador documental eleva automáticamente su clasificación a `restringido_ley21719`.
3. **Router Híbrido de 3 Niveles:**
   - **Nivel 1 (`LOCAL_LLM_ON_PREM` — Ollama / vLLM):** Obligatorio para datos sensibles Art. 16 Ley 21.719 (salud/siniestros, remuneraciones, secretos financieros). Cero salida del perímetro.
   - **Nivel 2 (`ENTERPRISE_PRIVATE_CLOUD_ZDR` — Azure OpenAI / AWS Bedrock / Vertex AI):** Para documentos corporativos `confidencial` bajo contrato empresarial **Zero-Data-Retention (ZDR)** (no entrena modelos con datos del cliente y opera sobre Private Endpoint regional).
   - **Nivel 3 (`EXTERNAL_COMMERCIAL_API_ANONYMIZED`):** Para consultas generales o públicas, aplicando siempre enmascaramiento PII previo.

### Consecuencias
- **Positivas:** Combina máxima soberanía de datos en consultas críticas con eficiencia operativa y control de costos FinOps en consultas generales.

---

## ADR-005: Gobernanza Agéntica con *Human-in-the-Loop (HITL)*, Servidor MCP JSON-RPC 2.0 y Cadena de Auditoría Hash-Chained

- **Estado:** Aceptado e Implementado (`v1.2.0` – `v3.1.0`)
- **Módulos:** [`app/connectors/enterprise_tools.py`](../app/connectors/enterprise_tools.py), [`app/connectors/mcp_server_adapter.py`](../app/connectors/mcp_server_adapter.py), [`app/compliance/audit_arco.py`](../app/compliance/audit_arco.py)

### Contexto
Un sistema RAG empresarial moderno no solo lee documentos: también debe **accionar** sobre plataformas corporativas (pre-liquidar siniestros en Core Seguros, bloquear pagos en SAP S/4HANA, emitir certificados en Buk/Workday o exponer herramientas vía **Model Context Protocol - MCP**). Sin embargo, permitir que un LLM ejecute transacciones de escritura de forma autónoma sin validación de permisos ni supervisión humana introduce riesgos operacionales y de cumplimiento severos.

### Decisión
1. **Validación RBAC en cada Conector y en el Servidor MCP (`/api/v1/mcp/rpc`):** Tanto la invocación directa como los métodos JSON-RPC 2.0 de MCP (`tools/list`, `tools/call`, `resources/list`, `resources/read`) verifican criptográficamente el JWT de Active Directory antes de listar o accionar recursos.
2. **Flujo *Human-in-the-Loop (HITL)* de Dos Pasos:** Las acciones transaccionales de escritura pueden requerir estado `PENDING_HITL_APPROVAL`, generando un `action_id` que un supervisor autorizado debe aprobar o rechazar explícitamente (`/api/v1/rag/actions/confirm`).
3. **Auditoría Inmutable Encadenada (`SHA-256`) y Derecho de Supresión ARCO:** Cada consulta, bloqueo RBAC, invocación MCP, aprobación HITL y purga de vectores por RUT (`Derecho de Cancelación / Olvido` Ley 21.719) se registra en SQLite enlazando criptográficamente el `entry_hash` con el `prev_hash` anterior.

### Consecuencias
- **Positivas:** Cumplimiento auditable de extremo a extremo ante inspecciones de la **Agencia de Protección de Datos Personales**, la **ANCI (Ley 21.663)** y auditorías internas de **Seguridad de la Información**.
