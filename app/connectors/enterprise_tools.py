"""Actionable Enterprise Connectors (Core Seguros, SAP ERP Finanzas, Buk/Workday RRHH, ServiceNow/Compliance)."""
from __future__ import annotations

import re
import time
import uuid
from typing import Any

from app.domain.models import ToolInvocation, UserIdentity


class EnterpriseConnectorRegistry:
    """
    Registry and RBAC-gated executor for integrable enterprise platforms.
    Every connector enforces:
    1. Department isolation (`required_department in user.allowed_departments`).
    2. Write-privilege verification (`user.can_execute_write_actions`) for state-mutating actions.
    3. Human-in-the-Loop (`confirm_write=True`) option for critical financial/clinical operations.
    """

    def __init__(self) -> None:
        # Simulated live transactional state for connected enterprise platforms
        self._claims_state: dict[str, dict[str, Any]] = {
            "SIN-2026-88410": {
                "siniestro_id": "SIN-2026-88410",
                "poliza": "POL-2026-55120",
                "titular_rut": "15.432.876-5",
                "paciente": "Marcela Paz Fuenzalida",
                "prestacion": "Cirugía Oncológica y Quimioterapia Adyuvante (CIE-10 C50.9)",
                "monto_reclamado_uf": 185.0,
                "cobertura_plan_pct": 80,
                "monto_reembolsable_uf": 148.0,
                "estado": "EN_EVALUACION_MEDICA",
                "liquidador_asignado": "camila.soto@aseguradora-isa.cl",
            },
            "SIN-2026-90112": {
                "siniestro_id": "SIN-2026-90112",
                "poliza": "POL-2026-61209",
                "titular_rut": "12.987.654-3",
                "paciente": "Carlos Andrés Tapia",
                "prestacion": "Hospitalización Psiquiátrica Trastorno Depresivo Mayor (CIE-10 F32.2)",
                "monto_reclamado_uf": 62.5,
                "cobertura_plan_pct": 70,
                "monto_reembolsable_uf": 43.75,
                "estado": "PENDIENTE_PRELIQUIDACION",
                "liquidador_asignado": "camila.soto@aseguradora-isa.cl",
            },
        }
        self._erp_invoices: dict[str, dict[str, Any]] = {
            "FAC-99201": {
                "factura_id": "FAC-99201",
                "proveedor": "Clínica Metropolitana SpA",
                "monto_clp": 48500000,
                "centro_costo": "CC-SALUD-CONVENIOS",
                "estado_pago": "PROGRAMADO_TESORERIA",
            },
            "FAC-99450": {
                "factura_id": "FAC-99450",
                "proveedor": "CloudSec Latam Ltda.",
                "monto_clp": 19200000,
                "centro_costo": "CC-TI-CIBERSEGURIDAD",
                "estado_pago": "PENDIENTE_APROBACION_FINANZAS",
            },
        }
        self._tickets_created: list[dict[str, Any]] = []
        self._pending_hitl_actions: dict[str, dict[str, Any]] = {}

    def list_available_connectors(self) -> list[dict[str, Any]]:
        return [
            {
                "tool_name": "core_seguros_preliquidar_siniestro",
                "connector_system": "Core Seguros & Salud (API Siniestros)",
                "required_department": "salud_siniestros",
                "action_type": "WRITE",
                "description": "Calcula cobertura y emite orden de pre-liquidación de reembolso médico para un siniestro (ej. SIN-2026-88410).",
            },
            {
                "tool_name": "erp_finanzas_retener_factura",
                "connector_system": "SAP S/4HANA ERP Financiero",
                "required_department": "finanzas",
                "action_type": "WRITE",
                "description": "Aplica bloqueo preventivo de pago en tesorería a una factura de proveedor (ej. FAC-99201).",
            },
            {
                "tool_name": "buk_rrhh_emitir_certificado_compensacion",
                "connector_system": "Buk / Workday HCM (Recursos Humanos)",
                "required_department": "rrhh",
                "action_type": "READ_WRITE",
                "description": "Genera constancia interna de banda salarial, vacaciones y estructura de bonos de un colaborador.",
            },
            {
                "tool_name": "servicenow_crear_ticket_cumplimiento",
                "connector_system": "ServiceNow GRC & Mesa de Cumplimiento Ley 21.719 / 21.663",
                "required_department": "publico_corporativo",
                "action_type": "WRITE",
                "description": "Abre un ticket auditable de cumplimiento normativo, incidente CSIRT o requerimiento ARCO.",
            },
        ]

    def detect_and_execute_tools(
        self,
        query: str,
        user: UserIdentity,
        explicit_tool: str | None = None,
        explicit_params: dict[str, Any] | None = None,
        require_hitl: bool = False,
    ) -> list[ToolInvocation]:
        """
        Inspect query or explicit tool request, enforce RBAC, and execute integrated platform actions.
        When `require_hitl=True`, write operations generate a pending Human-in-the-Loop proposal.
        """
        invocations: list[ToolInvocation] = []
        q_lower = query.lower()

        # 1. Check if user is asking to pre-settle / approve a health insurance claim
        wants_claim_action = (
            explicit_tool == "core_seguros_preliquidar_siniestro"
            or any(
                kw in q_lower
                for kw in [
                    "preliquidar",
                    "pre-liquidar",
                    "aprobar reembolso",
                    "liquidar siniestro",
                    "emitir preliquidación",
                    "accionar reembolso",
                ]
            )
        )
        if wants_claim_action:
            sin_match = re.search(r"SIN-\d{4}-\d{4,6}", query, re.IGNORECASE)
            sin_id = (
                (explicit_params or {}).get("siniestro_id")
                or (sin_match.group(0).upper() if sin_match else "SIN-2026-88410")
            )
            invocations.append(self._exec_preliquidar_siniestro(user, str(sin_id), require_hitl=require_hitl))

        # 2. Check if user is asking to block/hold a financial invoice in ERP
        wants_erp_action = (
            explicit_tool == "erp_finanzas_retener_factura"
            or any(
                kw in q_lower
                for kw in [
                    "bloquear pago",
                    "retener factura",
                    "bloquear factura",
                    "congelar pago",
                    "suspender pago",
                ]
            )
        )
        if wants_erp_action:
            fac_match = re.search(r"FAC-\d{4,6}", query, re.IGNORECASE)
            fac_id = (
                (explicit_params or {}).get("factura_id")
                or (fac_match.group(0).upper() if fac_match else "FAC-99201")
            )
            invocations.append(self._exec_retener_factura(user, str(fac_id), require_hitl=require_hitl))

        # 3. Check if user wants an HR compensation action
        wants_hr_action = (
            explicit_tool == "buk_rrhh_emitir_certificado_compensacion"
            or any(
                kw in q_lower
                for kw in [
                    "emitir certificado salarial",
                    "generar constancia de sueldo",
                    "aprobar bono en buk",
                    "accionar ficha rrhh",
                ]
            )
        )
        if wants_hr_action:
            invocations.append(self._exec_rrhh_action(user, explicit_params or {}, require_hitl=require_hitl))

        # 4. Check if user wants to create a compliance/security ticket in ServiceNow
        wants_ticket = (
            explicit_tool == "servicenow_crear_ticket_cumplimiento"
            or any(
                kw in q_lower
                for kw in [
                    "crear ticket",
                    "abrir ticket",
                    "reportar incidente",
                    "levantar ticket",
                    "registrar solicitud arco",
                ]
            )
        )
        if wants_ticket:
            invocations.append(self._exec_create_compliance_ticket(user, query))

        return invocations

    def _create_hitl_proposal(
        self,
        tool_name: str,
        connector_system: str,
        required_department: str,
        parameters: dict[str, Any],
        user: UserIdentity,
        impact_description: str,
    ) -> ToolInvocation:
        action_id = f"HITL-{uuid.uuid4().hex[:8].upper()}"
        proposal = {
            "action_id": action_id,
            "tool_name": tool_name,
            "connector_system": connector_system,
            "required_department": required_department,
            "parameters": parameters,
            "requested_by": user.username,
            "requested_by_email": user.email,
            "impact_description": impact_description,
            "status": "PENDING_HUMAN_APPROVAL",
            "created_at_epoch": int(time.time()),
        }
        self._pending_hitl_actions[action_id] = proposal
        return ToolInvocation(
            tool_name=tool_name,
            connector_system=connector_system,
            action_type="WRITE",
            status="HITL_CONFIRMATION_REQUIRED",
            required_department=required_department,
            parameters=parameters,
            result_summary=(
                f"CONFIRMACIÓN HUMANA REQUERIDA ({action_id}): {impact_description}. "
                f"Esperando aprobación explícita de {user.full_name} antes de mutar el sistema."
            ),
            raw_output=proposal,
        )

    def confirm_pending_action(
        self,
        action_id: str,
        user: UserIdentity,
        decision: str = "APPROVE",
    ) -> ToolInvocation:
        proposal = self._pending_hitl_actions.get(action_id)
        if not proposal:
            raise ValueError(f"La propuesta HITL '{action_id}' no existe o ya fue procesada.")

        req_dept = proposal["required_department"]
        if req_dept not in user.allowed_departments or not user.can_execute_write_actions:
            raise PermissionError(
                f"RBAC Denegado en Confirmación HITL: El usuario '{user.username}' no tiene privilegios "
                f"de escritura en '{req_dept}' para aprobar la acción '{action_id}'."
            )

        del self._pending_hitl_actions[action_id]
        if decision.upper() != "APPROVE":
            return ToolInvocation(
                tool_name=proposal["tool_name"],
                connector_system=proposal["connector_system"],
                action_type="WRITE",
                status="REJECTED_BY_HUMAN",
                required_department=req_dept,
                parameters=proposal["parameters"],
                result_summary=f"Acción {action_id} cancelada manualmente por {user.full_name} (Human-in-the-Loop).",
                raw_output={"action_id": action_id, "decision": "REJECTED"},
            )

        tool_name = proposal["tool_name"]
        params = proposal["parameters"]
        if tool_name == "core_seguros_preliquidar_siniestro":
            return self._exec_preliquidar_siniestro(user, str(params.get("siniestro_id", "SIN-2026-88410")), require_hitl=False)
        if tool_name == "erp_finanzas_retener_factura":
            return self._exec_retener_factura(user, str(params.get("factura_id", "FAC-99201")), require_hitl=False)
        return self._exec_rrhh_action(user, params, require_hitl=False)

    def _exec_preliquidar_siniestro(self, user: UserIdentity, siniestro_id: str, require_hitl: bool = False) -> ToolInvocation:
        req_dept = "salud_siniestros"
        if req_dept not in user.allowed_departments or not user.can_execute_write_actions:
            return ToolInvocation(
                tool_name="core_seguros_preliquidar_siniestro",
                connector_system="Core Seguros & Salud (API Siniestros)",
                action_type="WRITE",
                status="RBAC_DENIED",
                required_department=req_dept,
                parameters={"siniestro_id": siniestro_id},
                result_summary=(
                    f"ACCESO DENEGADO AL CONECTOR: El usuario '{user.username}' ({user.primary_department}) "
                    f"no posee el grupo AD 'GRP_AD_SALUD_LIQUIDADORES' para accionar siniestros de salud."
                ),
            )

        claim = self._claims_state.get(siniestro_id)
        if not claim:
            return ToolInvocation(
                tool_name="core_seguros_preliquidar_siniestro",
                connector_system="Core Seguros & Salud (API Siniestros)",
                action_type="WRITE",
                status="EXECUTED",
                required_department=req_dept,
                parameters={"siniestro_id": siniestro_id},
                result_summary=f"El siniestro {siniestro_id} no fue encontrado en el Core de Seguros.",
            )

        if require_hitl:
            return self._create_hitl_proposal(
                tool_name="core_seguros_preliquidar_siniestro",
                connector_system="Core Seguros & Salud (API Siniestros)",
                required_department=req_dept,
                parameters={"siniestro_id": siniestro_id, "cobertura_pct": claim["cobertura_plan_pct"]},
                user=user,
                impact_description=(
                    f"Pre-liquidar siniestro {siniestro_id} (Póliza {claim['poliza']}) con desembolso de "
                    f"{claim['monto_reembolsable_uf']} UF"
                ),
            )

        claim["estado"] = "PRELIQUIDADO_APROBADO_PAGO"
        orden_id = f"ORD-LIQ-{int(time.time()) % 100000}"
        return ToolInvocation(
            tool_name="core_seguros_preliquidar_siniestro",
            connector_system="Core Seguros & Salud (API Siniestros)",
            action_type="WRITE",
            status="EXECUTED",
            required_department=req_dept,
            parameters={"siniestro_id": siniestro_id, "cobertura_pct": claim["cobertura_plan_pct"]},
            result_summary=(
                f"Acción ejecutada en Core Seguros: Siniestro {siniestro_id} (Póliza {claim['poliza']}) "
                f"actualizado a 'PRELIQUIDADO_APROBADO_PAGO' por {claim['monto_reembolsable_uf']} UF "
                f"(Orden {orden_id})."
            ),
            raw_output={"orden_liquidacion": orden_id, "claim": claim},
        )

    def _exec_retener_factura(self, user: UserIdentity, factura_id: str, require_hitl: bool = False) -> ToolInvocation:
        req_dept = "finanzas"
        if req_dept not in user.allowed_departments or not user.can_execute_write_actions:
            return ToolInvocation(
                tool_name="erp_finanzas_retener_factura",
                connector_system="SAP S/4HANA ERP Financiero",
                action_type="WRITE",
                status="RBAC_DENIED",
                required_department=req_dept,
                parameters={"factura_id": factura_id},
                result_summary=(
                    f"ACCESO DENEGADO AL ERP: El usuario '{user.username}' ({user.primary_department}) "
                    f"no pertenece a 'GRP_AD_FINANZAS_ANALISTAS' para retener pagos en SAP."
                ),
            )

        invoice = self._erp_invoices.get(factura_id)
        if not invoice:
            return ToolInvocation(
                tool_name="erp_finanzas_retener_factura",
                connector_system="SAP S/4HANA ERP Financiero",
                action_type="WRITE",
                status="EXECUTED",
                required_department=req_dept,
                parameters={"factura_id": factura_id},
                result_summary=f"Factura {factura_id} no existe en el libro mayor de SAP.",
            )

        if require_hitl:
            return self._create_hitl_proposal(
                tool_name="erp_finanzas_retener_factura",
                connector_system="SAP S/4HANA ERP Financiero",
                required_department=req_dept,
                parameters={"factura_id": factura_id},
                user=user,
                impact_description=(
                    f"Retener pago en SAP de factura {factura_id} ({invoice['proveedor']}) por "
                    f"${invoice['monto_clp']:,} CLP"
                ),
            )

        invoice["estado_pago"] = "RETENIDO_AUDITORIA_FINANZAS"
        return ToolInvocation(
            tool_name="erp_finanzas_retener_factura",
            connector_system="SAP S/4HANA ERP Financiero",
            action_type="WRITE",
            status="EXECUTED",
            required_department=req_dept,
            parameters={"factura_id": factura_id},
            result_summary=(
                f"Acción ejecutada en SAP ERP: Factura {factura_id} ({invoice['proveedor']} por "
                f"${invoice['monto_clp']:,} CLP) cambiada a estado 'RETENIDO_AUDITORIA_FINANZAS'."
            ),
            raw_output={"invoice": invoice},
        )

    def _exec_rrhh_action(self, user: UserIdentity, params: dict[str, Any], require_hitl: bool = False) -> ToolInvocation:
        req_dept = "rrhh"
        if req_dept not in user.allowed_departments or not user.can_execute_write_actions:
            return ToolInvocation(
                tool_name="buk_rrhh_emitir_certificado_compensacion",
                connector_system="Buk / Workday HCM (Recursos Humanos)",
                action_type="WRITE",
                status="RBAC_DENIED",
                required_department=req_dept,
                parameters=params,
                result_summary=(
                    f"ACCESO DENEGADO A BUK RR.HH.: El usuario '{user.username}' ({user.primary_department}) "
                    "no tiene permisos sobre remuneraciones ni fichas de personal."
                ),
            )

        if require_hitl:
            return self._create_hitl_proposal(
                tool_name="buk_rrhh_emitir_certificado_compensacion",
                connector_system="Buk / Workday HCM (Recursos Humanos)",
                required_department=req_dept,
                parameters=params,
                user=user,
                impact_description="Emitir certificado oficial de compensación y banda salarial en Buk HCM",
            )

        cert_id = f"CERT-BUK-{uuid.uuid4().hex[:6].upper()}"
        return ToolInvocation(
            tool_name="buk_rrhh_emitir_certificado_compensacion",
            connector_system="Buk / Workday HCM (Recursos Humanos)",
            action_type="WRITE",
            status="EXECUTED",
            required_department=req_dept,
            parameters=params,
            result_summary=(
                f"Acción ejecutada en Buk RR.HH.: Certificado confidencial de compensación y banda salarial "
                f"generado exitosamente ({cert_id}) por {user.full_name}."
            ),
            raw_output={"certificado_id": cert_id},
        )

    def _exec_create_compliance_ticket(self, user: UserIdentity, query: str) -> ToolInvocation:
        ticket_id = f"INC-GRC-{1000 + len(self._tickets_created) + 1}"
        ticket = {
            "ticket_id": ticket_id,
            "created_by": user.email,
            "department": user.primary_department,
            "summary": query[:140],
            "status": "ABIERTO_EN_COLA_CUMPLIMIENTO",
        }
        self._tickets_created.append(ticket)
        return ToolInvocation(
            tool_name="servicenow_crear_ticket_cumplimiento",
            connector_system="ServiceNow GRC & Mesa de Cumplimiento",
            action_type="WRITE",
            status="EXECUTED",
            required_department="publico_corporativo",
            parameters={"summary": query[:120]},
            result_summary=(
                f"Ticket {ticket_id} creado en ServiceNow GRC asignado al Oficial de Cumplimiento "
                f"(solicitante: {user.email})."
            ),
            raw_output=ticket,
        )
