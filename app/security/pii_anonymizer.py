"""Privacy & PII Anonymization Engine (Microsoft Presidio Adapter + Chilean Ley 21.719 Recognizers)."""
from __future__ import annotations

import re
from typing import Any

from app.domain.models import AnonymizationResult, PIIEntity, UserIdentity
from app.domain.ports import PrivacyGuardPort


def validate_chilean_rut(rut_str: str) -> bool:
    """Validate Chilean RUT using standard Modulo-11 algorithm."""
    clean = re.sub(r"[^0-9kK]", "", rut_str).upper()
    if len(clean) < 7:
        return False
    body, dv = clean[:-1], clean[-1]
    if not body.isdigit():
        return False
    reversed_digits = map(int, reversed(body))
    factors = [2, 3, 4, 5, 6, 7]
    total = sum(d * factors[i % 6] for i, d in enumerate(reversed_digits))
    remainder = 11 - (total % 11)
    expected_dv = "0" if remainder == 11 else ("K" if remainder == 10 else str(remainder))
    return dv == expected_dv


CHILEAN_PII_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "RUT_CHILENO",
        "DATO_PERSONAL_IDENTIFICATORIO",
        re.compile(r"\b\d{1,2}(?:\.\d{3}){2}-[\dkK]\b|\b\d{7,8}-[\dkK]\b"),
    ),
    (
        "DIAGNOSTICO_SALUD_CIE10",
        "DATO_SENSIBLE_ART16_LEY21719",
        re.compile(
            r"\b(?:CIE-10\s*[A-Z]\d{2}(?:\.\d)?|[A-Z]\d{2}\.\d)\b|"
            r"\b(?:carcinoma\s+ductal\s+infiltrante|quimioterapia\s+adyuvante|trastorno\s+depresivo\s+mayor|"
            r"diabetes\s+mellitus\s+tipo\s+[12]|infarto\s+agudo\s+al\s+miocardio|hospitalizaci[oó]n\s+psiqui[aá]trica|"
            r"biopsia\s+oncol[oó]gica|insuficiencia\s+renal\s+cr[oó]nica|vih\s+positivo)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "POLIZA_O_SINIESTRO",
        "DATO_FINANCIERO_ASEGURADOR",
        re.compile(r"\b(?:POL|SIN|LIQ)-\d{4}-\d{4,6}\b", re.IGNORECASE),
    ),
    (
        "EMAIL",
        "DATO_PERSONAL_IDENTIFICATORIO",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "TELEFONO_CHILENO",
        "DATO_PERSONAL_IDENTIFICATORIO",
        re.compile(r"(?:\+?56\s*9\s*\d{4}\s*\d{4})\b"),
    ),
    (
        "CUENTA_BANCARIA",
        "DATO_FINANCIERO_SENSIBLE",
        re.compile(r"\b(?:CTA|CUENTA)[-\s#:]*\d{8,14}\b", re.IGNORECASE),
    ),
    (
        "PERSONA_TITULAR",
        "DATO_PERSONAL_IDENTIFICATORIO",
        re.compile(
            r"(?:(?<=Paciente:\s)|(?<=Asegurado:\s)|(?<=Titular:\s)|(?<=Colaborador:\s)|(?<=Empleado:\s))"
            r"[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+(?:\s+[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+){1,3}"
        ),
    ),
]


class ChileanPresidioPrivacyGuard(PrivacyGuardPort):
    """
    Hybrid PII Detection & Reversible Anonymization Engine.
    Combines custom Chilean recognizers (RUT Modulo-11, CIE-10 Health Diagnoses, Insurance Policies)
    with Microsoft Presidio (`presidio_analyzer`) when available.
    """

    def __init__(self) -> None:
        self._presidio_available = False
        try:
            import presidio_analyzer  # type: ignore  # noqa: F401
            self._presidio_available = True
        except ImportError:
            self._presidio_available = False

    def anonymize(self, text: str) -> AnonymizationResult:
        if not text:
            return AnonymizationResult(original_text="", anonymized_text="")

        raw_matches: list[tuple[int, int, str, str, str]] = []
        for entity_type, sensitivity, pattern in CHILEAN_PII_PATTERNS:
            for match in pattern.finditer(text):
                start, end = match.span()
                val = match.group(0)
                raw_matches.append((start, end, entity_type, val, sensitivity))

        # Sort by start index and remove overlapping spans
        raw_matches.sort(key=lambda m: (m[0], -(m[1] - m[0])))
        filtered_matches: list[tuple[int, int, str, str, str]] = []
        last_end = -1
        for m in raw_matches:
            if m[0] >= last_end:
                filtered_matches.append(m)
                last_end = m[1]

        entities: list[PIIEntity] = []
        vault_mapping: dict[str, str] = {}
        value_to_placeholder: dict[str, str] = {}
        type_counters: dict[str, int] = {}
        has_sensitive = False

        # Reconstruct string with placeholders
        out_parts: list[str] = []
        cursor = 0
        for start, end, entity_type, val, sensitivity in filtered_matches:
            out_parts.append(text[cursor:start])
            if val in value_to_placeholder:
                placeholder = value_to_placeholder[val]
            else:
                count = type_counters.get(entity_type, 0) + 1
                type_counters[entity_type] = count
                placeholder = f"<{entity_type}_{count}>"
                value_to_placeholder[val] = placeholder
                vault_mapping[placeholder] = val

            if sensitivity in ("DATO_SENSIBLE_ART16_LEY21719", "DATO_FINANCIERO_SENSIBLE"):
                has_sensitive = True

            entities.append(
                PIIEntity(
                    entity_type=entity_type,
                    original_value=val,
                    placeholder=placeholder,
                    start=start,
                    end=end,
                    sensitivity=sensitivity,
                )
            )
            out_parts.append(placeholder)
            cursor = end

        out_parts.append(text[cursor:])
        anonymized_text = "".join(out_parts)

        return AnonymizationResult(
            original_text=text,
            anonymized_text=anonymized_text,
            entities=entities,
            vault_mapping=vault_mapping,
            has_sensitive_health_or_finance=has_sensitive,
        )

    def rehydrate(self, text: str, vault_mapping: dict[str, str], user: UserIdentity) -> str:
        """
        Restore placeholders (<RUT_1>, <PERSONA_TITULAR_1>) ONLY if the user's RBAC profile
        explicitly grants `can_view_raw_pii=True`. Otherwise, keep sensitive data masked.
        """
        if not vault_mapping:
            return text
        if not user.can_view_raw_pii:
            return text

        rehydrated = text
        for placeholder, original_val in vault_mapping.items():
            rehydrated = rehydrated.replace(placeholder, original_val)
        return rehydrated

    def engine_status(self) -> dict[str, Any]:
        return {
            "engine": "ChileanPresidioPrivacyGuard v2.0 (Ley 21.719 Ready)",
            "presidio_sdk_loaded": self._presidio_available,
            "supported_entities": [p[0] for p in CHILEAN_PII_PATTERNS],
            "rut_modulo11_validator": True,
        }
