"""Enterprise Knowledge Sync Connectors with Active Directory ACL Inheritance."""
from __future__ import annotations

import uuid
from typing import Any

from app.domain.models import AppRole, DataClassification, DocumentChunk, UserIdentity
from app.domain.ports import PrivacyGuardPort, VectorStorePort

# Simulated external enterprise repositories with native Active Directory Group ACLs
EXTERNAL_PLATFORM_SOURCES: dict[str, dict[str, Any]] = {
    "sharepoint_salud": {
        "connector_id": "sharepoint_salud",
        "platform_name": "Microsoft SharePoint Online (Graph API) — Sitio Comité Médico",
        "source_ad_group": "GRP_AD_SALUD_LIQUIDADORES",
        "mapped_department": "salud_siniestros",
        "mapped_classification": DataClassification.ESTRICTO_SALUD_FINANZAS.value,
        "documents": [
            {
                "title": "Protocolo Auditoría Médica GES y Cobertura Oncológica 2026 (Siniestro SIN-2026-95301)",
                "content": (
                    "Acta Comité Oncológico - Siniestro SIN-2026-95301 (Póliza POL-2026-77410). "
                    "Paciente: Rodrigo Ignacio Valenzuela, RUT 12.345.678-5, correo r.valenzuela@cliente-seguros.cl. "
                    "Diagnóstico: carcinoma ductal infiltrante e inmunoterapia dirigida (CIE-10 C50.9). "
                    "Se autoriza cobertura catastrófica del 85% por un tope de 320 UF previa validación del liquidador senior."
                ),
                "titular_rut": "12.345.678-5",
            }
        ],
    },
    "sap_dms_finanzas": {
        "connector_id": "sap_dms_finanzas",
        "platform_name": "SAP S/4HANA Document Management (DMS) — Tesorería y Contraloría",
        "source_ad_group": "GRP_AD_FINANZAS_ANALISTAS",
        "mapped_department": "finanzas",
        "mapped_classification": DataClassification.ESTRICTO_SALUD_FINANZAS.value,
        "documents": [
            {
                "title": "Política de Retención de Pagos a Proveedores Críticos y Solvencia CMF 2026",
                "content": (
                    "Directriz de Contraloría Financiera (SAP DMS): Toda factura de proveedores médicos o tecnológicos "
                    "que supere los $15.000.000 CLP (incluyendo FAC-99201 y FAC-99450) requiere validación contra cuenta "
                    "corporativa CTA-00984123901 y puede ser retenida preventivamente mediante el conector SAP ERP."
                ),
                "titular_rut": "",
            }
        ],
    },
    "buk_hcm_rrhh": {
        "connector_id": "buk_hcm_rrhh",
        "platform_name": "Buk HCM Cloud — Repositorio Confidencial de Compensaciones",
        "source_ad_group": "GRP_AD_RRHH_GESTION",
        "mapped_department": "rrhh",
        "mapped_classification": DataClassification.ESTRICTO_SALUD_FINANZAS.value,
        "documents": [
            {
                "title": " Convenio de Retención de Talento Clave y Bonos por Desempeño 2026",
                "content": (
                    "Anexo Confidencial Buk HCM: Colaborador: Carolina Andrea Soto, RUT 15.432.876-9, "
                    "cargo Arquitecta Líder de Ciberseguridad. Sueldo base mensual pactado: $5.400.000 CLP más "
                    "bono de retención semestral del 20% sujeto a cumplimiento de objetivos ISO 27001 y Ley 21.663."
                ),
                "titular_rut": "15.432.876-9",
            }
        ],
    },
    "servicenow_grc_legal": {
        "connector_id": "servicenow_grc_legal",
        "platform_name": "ServiceNow GRC — Base de Conocimiento Normativo Ley 21.719 y ANCI",
        "source_ad_group": "GRP_AD_LEGAL_CUMPLIMIENTO",
        "mapped_department": "legal_cumplimiento",
        "mapped_classification": DataClassification.CONFIDENCIAL.value,
        "documents": [
            {
                "title": "Procedimiento Operativo de Respuesta a Solicitudes ARCO en 10 Días Hábiles (Ley 21.719)",
                "content": (
                    "Protocolo Oficial DPO (Ley 21.719): Ante una solicitud de Cancelación/Supresión de un titular "
                    "identificado con su RUT, el Oficial de Cumplimiento debe ejecutar el borrado físico y vectorial "
                    "en todas las colecciones de ChromaDB, invalidar las particiones de caché semántico y emitir el "
                    "comprobante criptográfico SHA-256 desde el registro de auditoría."
                ),
                "titular_rut": "",
            }
        ],
    },
}


class EnterpriseKnowledgeSyncConnector:
    """
    Synchronizes documents from integrable enterprise platforms (SharePoint, SAP DMS, Buk HCM, ServiceNow)
    while automatically inheriting Active Directory group ACLs into ChromaDB chunk metadata.
    """

    def __init__(self, vector_store: VectorStorePort, privacy_guard: PrivacyGuardPort) -> None:
        self.vector_store = vector_store
        self.privacy_guard = privacy_guard
        self._synced_history: list[dict[str, Any]] = []

    def list_sync_sources(self) -> list[dict[str, Any]]:
        return [
            {
                "connector_id": src["connector_id"],
                "platform_name": src["platform_name"],
                "source_ad_group": src["source_ad_group"],
                "mapped_department": src["mapped_department"],
                "mapped_classification": src["mapped_classification"],
                "available_documents_count": len(src["documents"]),
            }
            for src in EXTERNAL_PLATFORM_SOURCES.values()
        ]

    def sync_platform_source(self, connector_id: str, user: UserIdentity) -> dict[str, Any]:
        source = EXTERNAL_PLATFORM_SOURCES.get(connector_id)
        if not source:
            raise ValueError(f"Conector de sincronización '{connector_id}' no registrado.")

        target_dept = source["mapped_department"]
        if target_dept not in user.allowed_departments:
            raise PermissionError(
                f"RBAC Denegado en Conector de Ingesta: El usuario '{user.username}' ({user.primary_department}) "
                f"no posee el grupo AD '{source['source_ad_group']}' requerido para sincronizar '{source['platform_name']}'."
            )

        chunks_to_index: list[DocumentChunk] = []
        total_pii_found = 0
        for doc in source["documents"]:
            pii_scan = self.privacy_guard.anonymize(doc["content"])
            total_pii_found += len(pii_scan.entities)
            chunk_id = f"SYNC-{target_dept[:4].upper()}-{uuid.uuid4().hex[:5].upper()}"
            chunks_to_index.append(
                DocumentChunk(
                    chunk_id=chunk_id,
                    document_id=f"DOC-SYNC-{uuid.uuid4().hex[:6].upper()}",
                    title=doc["title"],
                    content=doc["content"],
                    department=target_dept,
                    classification=source["mapped_classification"],
                    allowed_roles=[
                        AppRole.ANALISTA_DEPARTAMENTO.value,
                        AppRole.ESPECIALISTA_AUTORIZADO.value,
                        AppRole.AUDITOR_CUMPLIMIENTO.value,
                    ],
                    source_system=source["platform_name"],
                    titular_rut=doc.get("titular_rut", ""),
                    contains_pii=len(pii_scan.entities) > 0,
                    created_at="2026-10-29",
                )
            )

        indexed_count = self.vector_store.upsert_chunks(chunks_to_index)
        sync_summary = {
            "connector_id": connector_id,
            "platform_name": source["platform_name"],
            "inherited_ad_group": source["source_ad_group"],
            "mapped_department": target_dept,
            "mapped_classification": source["mapped_classification"],
            "chunks_indexed": indexed_count,
            "chunk_ids": [c.chunk_id for c in chunks_to_index],
            "pii_entities_cataloged_locally": total_pii_found,
            "synced_by": user.email,
        }
        self._synced_history.append(sync_summary)
        return sync_summary
