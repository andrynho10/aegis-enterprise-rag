"""Realistic Enterprise Seed Corpus (Seguros/Salud, Finanzas, RRHH, Legal/Ley 21.719, TI, Corporativo)."""
from __future__ import annotations

from app.domain.models import AppRole, DataClassification, DocumentChunk


def get_initial_enterprise_corpus() -> list[DocumentChunk]:
    return [
        # --- DEPARTAMENTO: SALUD Y SINIESTROS (Datos Sensibles Art. 16 Ley 21.719) ---
        DocumentChunk(
            chunk_id="CHK-SALUD-001",
            document_id="DOC-SIN-2026-88410",
            title="Expediente Médico y Liquidación Siniestro Oncológico SIN-2026-88410",
            content=(
                "Informe de Liquidación Médica Confidencial - Siniestro SIN-2026-88410 (Póliza POL-2026-55120). "
                "Paciente: Marcela Paz Fuenzalida, RUT 15.432.876-5, correo m.fuenzalida@correo-privado.cl, "
                "teléfono +56 9 8234 5678. Diagnóstico clínico confirmado por biopsia oncológica: "
                "carcinoma ductal infiltrante (código CIE-10 C50.9) con indicación de cirugía y quimioterapia adyuvante. "
                "Gasto médico total presentado: 185,0 UF. Cobertura del plan Catastrófico Salud: 80% tras deducible. "
                "Monto líquido a reembolsar: 148,0 UF en cuenta bancaria CTA-98765432101. Estado: EN_EVALUACION_MEDICA."
            ),
            department="salud_siniestros",
            classification=DataClassification.ESTRICTO_SALUD_FINANZAS.value,
            allowed_roles=[AppRole.ANALISTA_DEPARTAMENTO.value, AppRole.ESPECIALISTA_AUTORIZADO.value],
            source_system="Core Seguros & Salud (Módulo Siniestros)",
            titular_rut="15.432.876-5",
            contains_pii=True,
            created_at="2026-10-15",
        ),
        DocumentChunk(
            chunk_id="CHK-SALUD-002",
            document_id="DOC-SIN-2026-90112",
            title="Expediente de Cobertura Salud Mental y Hospitalización SIN-2026-90112",
            content=(
                "Evaluación de Cobertura de Salud Mental - Siniestro SIN-2026-90112 (Póliza POL-2026-61209). "
                "Asegurado: Carlos Andrés Tapia, RUT 12.987.654-3. Prestación auditada: hospitalización psiquiátrica "
                "de urgencia por cuadro de trastorno depresivo mayor severo (código CIE-10 F32.2). "
                "Monto reclamado: 62,5 UF. Según condiciones particulares de la póliza y circular CMF, aplica tope "
                "de cobertura del 70% equivalente a 43,75 UF. Pendiente de emisión de orden de pre-liquidación."
            ),
            department="salud_siniestros",
            classification=DataClassification.ESTRICTO_SALUD_FINANZAS.value,
            allowed_roles=[AppRole.ANALISTA_DEPARTAMENTO.value, AppRole.ESPECIALISTA_AUTORIZADO.value],
            source_system="Core Seguros & Salud (Módulo Siniestros)",
            titular_rut="12.987.654-3",
            contains_pii=True,
            created_at="2026-10-19",
        ),
        # --- DEPARTAMENTO: FINANZAS (Datos Financieros y Presupuestarios) ---
        DocumentChunk(
            chunk_id="CHK-FIN-001",
            document_id="DOC-SAP-EBITDA-2026Q3",
            title="Reporte Confidencial de EBITDA, Reservas Técnicas y Tesorería Q3 2026",
            content=(
                "Reporte Financiero Interno Dirección de Finanzas (SAP S/4HANA): El EBITDA acumulado al Q3 2026 "
                "alcanzó los $14.820 millones CLP con un margen financiero neto del 18,4%. Las Reservas Técnicas "
                "exigidas por la CMF ascienden a 1.450.000 UF custodiadas en la cuenta corporativa CTA-00984123901. "
                "En tesorería existen dos facturas críticas bajo revisión de flujo de caja: "
                "1) Factura FAC-99201 de Clínica Metropolitana SpA por $48.500.000 CLP (Convenios Salud). "
                "2) Factura FAC-99450 de CloudSec Latam Ltda. por $19.200.000 CLP (Auditoría TI)."
            ),
            department="finanzas",
            classification=DataClassification.ESTRICTO_SALUD_FINANZAS.value,
            allowed_roles=[AppRole.ANALISTA_DEPARTAMENTO.value, AppRole.ESPECIALISTA_AUTORIZADO.value],
            source_system="SAP S/4HANA ERP Financiero",
            titular_rut="",
            contains_pii=True,
            created_at="2026-10-20",
        ),
        # --- DEPARTAMENTO: RECURSOS HUMANOS (Remuneraciones y Fichas de Personal) ---
        DocumentChunk(
            chunk_id="CHK-RRHH-001",
            document_id="DOC-BUK-REMUN-2026",
            title="Nómina Ejecutiva, Bandas Salariales y Bonos de Desempeño 2026",
            content=(
                "Confidencial Gerencia de Personas (Buk HCM): Estructura de remuneraciones y bonos ejecutivos 2026. "
                "1) Cargo Subgerente de Área: Banda salarial entre $5.800.000 y $7.200.000 CLP brutos mensuales. "
                "2) Ficha individual auditada - Colaborador: Patricio Morales Soto, RUT 14.221.334-K, "
                "correo p.morales@aseguradora-isa.cl: Sueldo base mensual $6.850.000 CLP, bono de desempeño anual "
                "aprobado del 24% ($19.728.000 CLP) y provisión de finiquito acumulada de $41.100.000 CLP."
            ),
            department="rrhh",
            classification=DataClassification.ESTRICTO_SALUD_FINANZAS.value,
            allowed_roles=[AppRole.ANALISTA_DEPARTAMENTO.value, AppRole.ESPECIALISTA_AUTORIZADO.value, AppRole.GESTOR_DOCUMENTAL.value],
            source_system="Buk / Workday HCM (Recursos Humanos)",
            titular_rut="14.221.334-K",
            contains_pii=True,
            created_at="2026-10-12",
        ),
        # --- DEPARTAMENTO: LEGAL Y CUMPLIMIENTO (Ley 21.719 y Ley 21.663) ---
        DocumentChunk(
            chunk_id="CHK-LEGAL-001",
            document_id="DOC-GRC-LEY21719",
            title="Matriz de Cumplimiento Ley 21.719 (Protección de Datos Personales) y Ley 21.663 (Ciberseguridad)",
            content=(
                "Directriz Oficial de Cumplimiento Normativo (Chile): "
                "1) Ley 21.719 de Protección de Datos Personales: Crea la Agencia de Protección de Datos Personales "
                "y establece multas de hasta 20.000 UTM por vulneración de datos sensibles (Art. 16: datos de salud, "
                "diagnósticos CIE-10 y biométricos). Su entrada en vigencia original está fijada para el 1 de diciembre "
                "de 2026 (con proyecto de ley ingresado al Senado en agosto buscando prorrogarla al 1 de diciembre de 2027). "
                "Exige privacidad desde el diseño, anonimización antes de transferencias a terceros, registro de auditoría "
                "y garantía de derechos ARCO (Acceso, Rectificación, Cancelación/Supresión y Oposición). "
                "2) Ley 21.663 Marco de Ciberseguridad (ANCI): Califica a aseguradoras y entidades financieras como "
                "Servicios Esenciales / OIV, obligando a reportar incidentes significativos al CSIRT Nacional en un plazo "
                "máximo de 3 horas desde su detección."
            ),
            department="legal_cumplimiento",
            classification=DataClassification.CONFIDENCIAL.value,
            allowed_roles=[AppRole.AUDITOR_CUMPLIMIENTO.value, AppRole.ANALISTA_DEPARTAMENTO.value],
            source_system="SharePoint Legal & GRC",
            titular_rut="",
            contains_pii=False,
            created_at="2026-10-22",
        ),
        # --- DEPARTAMENTO: TI Y CIBERSEGURIDAD ---
        DocumentChunk(
            chunk_id="CHK-TI-001",
            document_id="DOC-ARQ-RAG-SEGURIDAD",
            title="Estándar de Arquitectura Segura para IA Generativa y RAG Corporativo",
            content=(
                "Arquitectura de Seguridad TI para AegisRAG: "
                "1) Identidad SSO con Microsoft Entra ID (OIDC/MSAL) o Active Directory on-premise (LDAPS/ldap3) "
                "heredando MFA y desactivación inmediata en offboarding. "
                "2) Permission-Aware Retrieval: El control de acceso RBAC se ejecuta en la consulta vectorial de ChromaDB "
                "mediante el filtro `where` inyectado desde el token JWT validado en servidor, nunca en el prompt. "
                "3) Embeddings 100% locales (bge-m3 / nomic-embed-text) para evitar exfiltración de documentos al vectorizar. "
                "4) Caché particionado por hash de permisos (evita fuga cruzada entre roles). "
                "5) Router Híbrido: Datos sensibles van a vLLM/Ollama local; datos confidenciales a Azure OpenAI / Bedrock "
                "con contrato Zero-Data-Retention por Private Link; consultas generales a API tras anonimización con Presidio."
            ),
            department="ti_operaciones",
            classification=DataClassification.CONFIDENCIAL.value,
            allowed_roles=[AppRole.ANALISTA_DEPARTAMENTO.value],
            source_system="Confluence Arquitectura & Ciberseguridad TI",
            titular_rut="",
            contains_pii=False,
            created_at="2026-10-24",
        ),
        # --- DEPARTAMENTO: PÚBLICO CORPORATIVO (Accesible para todos los colaboradores autenticados) ---
        DocumentChunk(
            chunk_id="CHK-CORP-001",
            document_id="DOC-CORP-POLITICAS-2026",
            title="Manual General del Colaborador: Teletrabajo, Vacaciones y Cumplimiento Ético",
            content=(
                "Política General Corporativa (Accesible para todos los departamentos): "
                "1) Modalidad Híbrida: 3 días presenciales y 2 días de teletrabajo previa coordinación con jefatura. "
                "2) Vacaciones legales: 15 días hábiles anuales más 2 días administrativos adicionales. "
                "3) Seguridad de la Información y Ley 21.719: Todo colaborador debe proteger los datos personales de "
                "asegurados y clientes, utilizar autenticación multifactor (MFA) corporativa y reportar cualquier "
                "incidente o solicitud ARCO a través del conector de Mesa de Cumplimiento ServiceNow GRC."
            ),
            department="publico_corporativo",
            classification=DataClassification.PUBLICO.value,
            allowed_roles=[AppRole.LECTOR_GENERAL.value],
            source_system="Intranet Corporativa SharePoint",
            titular_rut="",
            contains_pii=False,
            created_at="2026-10-01",
        ),
    ]
