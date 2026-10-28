"""Role-Based Access Control (RBAC) Engine & Pre-Retrieval Policy Enforcer."""
from __future__ import annotations

import re
from typing import Any

from app.domain.models import AppRole, DataClassification, DocumentChunk, UserIdentity

# Mapping from Active Directory Security Groups to Application Permissions (Least Privilege)
AD_GROUP_POLICY_MAP: dict[str, dict[str, Any]] = {
    "GRP_AD_EMPLEADOS_TODOS": {
        "departments": ["publico_corporativo"],
        "roles": [AppRole.LECTOR_GENERAL.value],
        "max_classification": DataClassification.INTERNO.value,
        "can_view_raw_pii": False,
        "can_execute_write_actions": False,
    },
    "GRP_AD_SALUD_LIQUIDADORES": {
        "departments": ["salud_siniestros", "publico_corporativo"],
        "roles": [AppRole.ANALISTA_DEPARTAMENTO.value, AppRole.ESPECIALISTA_AUTORIZADO.value],
        "max_classification": DataClassification.ESTRICTO_SALUD_FINANZAS.value,
        "can_view_raw_pii": True,  # Authorized under Ley 21.719 for claims settlement
        "can_execute_write_actions": True,
    },
    "GRP_AD_FINANZAS_ANALISTAS": {
        "departments": ["finanzas", "publico_corporativo"],
        "roles": [AppRole.ANALISTA_DEPARTAMENTO.value, AppRole.ESPECIALISTA_AUTORIZADO.value],
        "max_classification": DataClassification.ESTRICTO_SALUD_FINANZAS.value,
        "can_view_raw_pii": False,  # Can see financial figures, but personal RUT/health stays masked on external calls
        "can_execute_write_actions": True,
    },
    "GRP_AD_RRHH_GESTION": {
        "departments": ["rrhh", "publico_corporativo"],
        "roles": [AppRole.ANALISTA_DEPARTAMENTO.value, AppRole.ESPECIALISTA_AUTORIZADO.value, AppRole.GESTOR_DOCUMENTAL.value],
        "max_classification": DataClassification.ESTRICTO_SALUD_FINANZAS.value,
        "can_view_raw_pii": True,  # Authorized to view employee records inside HR scope
        "can_execute_write_actions": True,
    },
    "GRP_AD_LEGAL_CUMPLIMIENTO": {
        "departments": ["legal_cumplimiento", "publico_corporativo"],
        "roles": [AppRole.AUDITOR_CUMPLIMIENTO.value, AppRole.ANALISTA_DEPARTAMENTO.value],
        "max_classification": DataClassification.CONFIDENCIAL.value,
        "can_view_raw_pii": False,  # Auditors verify logs and policies without exposing raw medical diagnoses
        "can_execute_write_actions": False,
    },
    "GRP_AD_TI_OPERACIONES": {
        "departments": ["ti_operaciones", "publico_corporativo"],
        "roles": [AppRole.ANALISTA_DEPARTAMENTO.value],
        "max_classification": DataClassification.CONFIDENCIAL.value,
        "can_view_raw_pii": False,  # IT admins manage infra but cannot read HR salaries or Health claims!
        "can_execute_write_actions": True,
    },
}

PROMPT_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "OVERRIDE_SYSTEM_INSTRUCTIONS",
        re.compile(
            r"(ignora|olvida|salta|omite|desactiva)\s+(todas\s+)?(las\s+|tus\s+)?(instrucciones|reglas|restricciones|permisos|filtros)",
            re.IGNORECASE,
        ),
    ),
    (
        "ROLE_ESCALATION_ATTEMPT",
        re.compile(
            r"(act[uú]a\s+como|eres\s+ahora|asume\s+el\s+rol\s+de|modo\s+dios|sudo|admin_override|developer\s+mode|jailbreak)",
            re.IGNORECASE,
        ),
    ),
    (
        "PROMPT_LEAK_ATTEMPT",
        re.compile(
            r"(mu[eé]strame\s+tu\s+system\s+prompt|revela\s+tus\s+instrucciones|imprime\s+todo\s+el\s+contexto\s+sin\s+filtrar)",
            re.IGNORECASE,
        ),
    ),
]


class RBACEngine:
    """Resolves AD Groups into least-privilege RBAC claims and builds vector DB pre-filters."""

    @staticmethod
    def resolve_permissions_from_ad_groups(ad_groups: list[str]) -> dict[str, Any]:
        allowed_depts: set[str] = {"publico_corporativo"}
        roles: set[str] = {AppRole.LECTOR_GENERAL.value}
        max_rank = DataClassification.rank(DataClassification.PUBLICO.value)
        max_class = DataClassification.PUBLICO.value
        can_view_raw_pii = False
        can_execute_write_actions = False

        for group in ad_groups:
            policy = AD_GROUP_POLICY_MAP.get(group)
            if not policy:
                continue
            allowed_depts.update(policy["departments"])
            roles.update(policy["roles"])
            group_class = policy["max_classification"]
            if DataClassification.rank(group_class) > max_rank:
                max_rank = DataClassification.rank(group_class)
                max_class = group_class
            if policy.get("can_view_raw_pii"):
                can_view_raw_pii = True
            if policy.get("can_execute_write_actions"):
                can_execute_write_actions = True

        return {
            "allowed_departments": sorted(allowed_depts),
            "roles": sorted(roles),
            "max_classification": max_class,
            "can_view_raw_pii": can_view_raw_pii,
            "can_execute_write_actions": can_execute_write_actions,
        }

    @staticmethod
    def get_allowed_classifications(max_classification: str) -> list[str]:
        max_rank = DataClassification.rank(max_classification)
        return [
            c.value
            for c in DataClassification
            if DataClassification.rank(c.value) <= max_rank
        ]

    @classmethod
    def build_chromadb_where_filter(cls, user: UserIdentity) -> dict[str, Any]:
        """
        Build the mandatory ChromaDB `where` filter injected BEFORE vector similarity search.
        Crucial security principle: Access control is enforced at retrieval, NEVER in the prompt.
        """
        allowed_classifications = cls.get_allowed_classifications(user.max_classification)
        return {
            "$and": [
                {"department": {"$in": list(user.allowed_departments)}},
                {"classification": {"$in": allowed_classifications}},
            ]
        }

    @classmethod
    def is_chunk_authorized(cls, chunk: DocumentChunk, user: UserIdentity) -> bool:
        """Deterministic server-side verification that a chunk satisfies the user's RBAC profile."""
        if chunk.department not in user.allowed_departments:
            return False
        allowed_classifications = cls.get_allowed_classifications(user.max_classification)
        if chunk.classification not in allowed_classifications:
            return False
        if chunk.allowed_roles:
            if not set(chunk.allowed_roles).intersection(set(user.roles)):
                return False
        return True

    @staticmethod
    def detect_security_threats(query: str, user: UserIdentity) -> dict[str, Any]:
        """
        Inspect user query for Prompt Injection attempts or explicit cross-department probing.
        Note: Even if a user bypasses regex detection, the Vector DB `where` filter prevents
        unauthorized documents from ever entering the context window.
        """
        triggered_rules: list[str] = []
        for rule_name, pattern in PROMPT_INJECTION_PATTERNS:
            if pattern.search(query):
                triggered_rules.append(rule_name)

        # Detect explicit probing of departments outside user's AD groups
        q_lower = query.lower()
        department_keywords = {
            "salud_siniestros": ["diagnóstico", "diagnostico", "oncolog", "psiquiátr", "siniestro", "reembolso médico", "isapre", "biopsia", "cie-10"],
            "finanzas": ["ebitda", "flujo de caja", "presupuesto reservado", "auditoría financiera", "margen financiero", "cuenta bancaria corporativa"],
            "rrhh": ["sueldo", "salario", "remuneración", "finiquito", "despido", "evaluación de desempeño", "bono ejecutivo"],
            "legal_cumplimiento": ["sumario interno", "investigación antifraude", "sanción cmf", "litigio reservado"],
            "ti_operaciones": ["credenciales", "firewall", "arquitectura de red", "llaves criptográficas", " Active Directory "],
        }
        probed_unauthorized_depts: list[str] = []
        for dept, keywords in department_keywords.items():
            if dept not in user.allowed_departments:
                if any(kw in q_lower for kw in keywords):
                    probed_unauthorized_depts.append(dept)

        return {
            "prompt_injection_detected": len(triggered_rules) > 0,
            "triggered_injection_rules": triggered_rules,
            "probed_unauthorized_departments": probed_unauthorized_depts,
            "risk_level": (
                "ALTO"
                if triggered_rules
                else ("MEDIO" if probed_unauthorized_depts else "BAJO")
            ),
        }
