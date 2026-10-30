"""Enterprise Structure-Aware Semantic Chunker & Automatic Ley 21.719 Sensitivity Classifier."""
from __future__ import annotations

import re
import uuid
from typing import Any

from app.domain.models import AppRole, DataClassification, DocumentChunk
from app.domain.ports import PrivacyGuardPort


class EnterpriseDocumentProcessor:
    """
    Splits multi-section corporate documents into semantic chunks and enforces
    Automatic Sensitivity Upgrading (Ley 21.719 Art. 16 Safety Net):
    If a user uploads a document labeled 'publico' or 'interno', but a chunk contains
    CIE-10 health diagnoses, bank accounts, or executive salaries, the classifier
    automatically upgrades the chunk's classification to `estricto_salud_finanzas`.
    """

    def __init__(self, privacy_guard: PrivacyGuardPort, max_chunk_chars: int = 480, overlap_chars: int = 60) -> None:
        self.privacy_guard = privacy_guard
        self.max_chunk_chars = max_chunk_chars
        self.overlap_chars = overlap_chars

    def split_into_semantic_sections(self, text: str) -> list[str]:
        """Split text by paragraphs/headers first, then apply sliding window if a section exceeds max_chunk_chars."""
        cleaned = text.strip()
        if not cleaned:
            return []

        raw_blocks = [b.strip() for b in re.split(r"\n\s*\n|(?=\n#{1,3}\s)", cleaned) if b.strip()]
        chunks: list[str] = []
        current_buf = ""

        for block in raw_blocks:
            if len(current_buf) + len(block) + 2 <= self.max_chunk_chars:
                current_buf = f"{current_buf}\n\n{block}".strip() if current_buf else block
            else:
                if current_buf:
                    chunks.append(current_buf)
                if len(block) <= self.max_chunk_chars:
                    current_buf = block
                else:
                    # Sliding window by sentence boundaries
                    sentences = re.split(r"(?<=[.!?])\s+", block)
                    window = ""
                    for sent in sentences:
                        if len(window) + len(sent) + 1 <= self.max_chunk_chars:
                            window = f"{window} {sent}".strip() if window else sent
                        else:
                            if window:
                                chunks.append(window)
                                overlap = window[-self.overlap_chars :] if len(window) > self.overlap_chars else window
                                window = f"{overlap} {sent}".strip()
                            else:
                                chunks.append(sent[: self.max_chunk_chars])
                                window = sent[self.max_chunk_chars :]
                    current_buf = window

        if current_buf:
            chunks.append(current_buf)
        return chunks

    def inspect_and_auto_classify(
        self,
        chunk_text: str,
        requested_classification: str,
    ) -> dict[str, Any]:
        """
        Inspect chunk content for Ley 21.719 sensitive health/financial indicators.
        Prevents human error when indexing documents with understated security labels.
        """
        pii_res = self.privacy_guard.anonymize(chunk_text)
        lower_text = chunk_text.lower()

        has_clinical_or_financial_keywords = any(
            kw in lower_text
            for kw in [
                "cie-10",
                "carcinoma",
                "quimioterapia",
                "psiquiátr",
                "biopsia",
                "ebitda",
                "sueldo base",
                "remuneración",
                "finiquito",
                "reserva técnica",
            ]
        )

        effective_classification = requested_classification
        auto_upgraded = False
        upgrade_reason = "Clasificación original mantenida."

        if pii_res.has_sensitive_health_or_finance or has_clinical_or_financial_keywords:
            if DataClassification.rank(requested_classification) < DataClassification.rank(
                DataClassification.ESTRICTO_SALUD_FINANZAS.value
            ):
                effective_classification = DataClassification.ESTRICTO_SALUD_FINANZAS.value
                auto_upgraded = True
                upgrade_reason = (
                    f"Upgrade automático de '{requested_classification}' a '{effective_classification}' "
                    "por detección de Datos Sensibles Art. 16 Ley 21.719 (Salud / Finanzas)."
                )
        elif len(pii_res.entities) > 0:
            if DataClassification.rank(requested_classification) < DataClassification.rank(
                DataClassification.CONFIDENCIAL.value
            ):
                effective_classification = DataClassification.CONFIDENCIAL.value
                auto_upgraded = True
                upgrade_reason = (
                    f"Upgrade automático de '{requested_classification}' a '{effective_classification}' "
                    f"por presencia de {len(pii_res.entities)} entidad(es) PII."
                )

        # Extract primary RUT if present in chunk
        detected_rut = ""
        for ent in pii_res.entities:
            if ent.entity_type == "RUT_CHILENO":
                detected_rut = ent.original_value
                break

        return {
            "effective_classification": effective_classification,
            "requested_classification": requested_classification,
            "auto_upgraded": auto_upgraded,
            "upgrade_reason": upgrade_reason,
            "pii_count": len(pii_res.entities),
            "detected_rut": detected_rut,
        }

    def process_document_into_chunks(
        self,
        title: str,
        content: str,
        department: str,
        requested_classification: str,
        source_system: str = "Ingesta Inteligente DLP / SharePoint",
        explicit_titular_rut: str = "",
    ) -> tuple[list[DocumentChunk], dict[str, Any]]:
        sections = self.split_into_semantic_sections(content)
        doc_id = f"DOC-{uuid.uuid4().hex[:6].upper()}"
        created_chunks: list[DocumentChunk] = []
        upgrades_applied = 0
        total_pii = 0

        for idx, sec_text in enumerate(sections, start=1):
            inspection = self.inspect_and_auto_classify(sec_text, requested_classification)
            if inspection["auto_upgraded"]:
                upgrades_applied += 1
            total_pii += inspection["pii_count"]

            chunk_id = f"CHK-{department[:4].upper()}-{uuid.uuid4().hex[:4].upper()}-{idx:02d}"
            chunk_title = title if len(sections) == 1 else f"{title} (Sección {idx}/{len(sections)})"
            titular_rut = explicit_titular_rut or inspection["detected_rut"]

            created_chunks.append(
                DocumentChunk(
                    chunk_id=chunk_id,
                    document_id=doc_id,
                    title=chunk_title,
                    content=sec_text,
                    department=department,
                    classification=inspection["effective_classification"],
                    allowed_roles=[
                        AppRole.ANALISTA_DEPARTAMENTO.value,
                        AppRole.ESPECIALISTA_AUTORIZADO.value,
                        AppRole.GESTOR_DOCUMENTAL.value,
                        AppRole.AUDITOR_CUMPLIMIENTO.value,
                    ]
                    if inspection["effective_classification"] != DataClassification.PUBLICO.value
                    else [AppRole.LECTOR_GENERAL.value],
                    source_system=source_system,
                    titular_rut=titular_rut,
                    contains_pii=inspection["pii_count"] > 0,
                    created_at="2026-10-30",
                )
            )

        summary = {
            "document_id": doc_id,
            "title": title,
            "total_chunks_created": len(created_chunks),
            "chunk_ids": [c.chunk_id for c in created_chunks],
            "requested_classification": requested_classification,
            "final_classifications": list({c.classification for c in created_chunks}),
            "dlp_auto_upgrades_count": upgrades_applied,
            "total_pii_entities_detected": total_pii,
        }
        return created_chunks, summary
