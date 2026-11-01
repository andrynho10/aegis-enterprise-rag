"""
Enterprise Model Context Protocol (MCP) JSON-RPC 2.0 Server Adapter.

Exposes AegisRAG Enterprise's RBAC-governed knowledge base (`resources/*`) and
transactional enterprise connectors (`tools/*`) over the standard Model Context
Protocol (MCP) JSON-RPC 2.0 specification while strictly enforcing:
1. Active Directory / Entra ID OIDC JWT authentication on every RPC call.
2. Pre-retrieval RBAC filtering on `resources/list` and `resources/read` (zero cross-department visibility).
3. Ley 21.719 PII masking on resource contents when `user.can_view_raw_pii=False`.
4. RBAC & HITL governance + SHA-256 hash-chained audit logging on `tools/call`.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from app.security.rbac_engine import RBACEngine

if TYPE_CHECKING:
    from app.rag.orchestrator import EnterpriseRAGOrchestrator


class EnterpriseMCPServerAdapter:
    """
    Standard JSON-RPC 2.0 Model Context Protocol (MCP) Server Adapter with Zero-Trust RBAC.
    """

    PROTOCOL_VERSION = "2024-11-05"
    SERVER_NAME = "aegisrag-enterprise-mcp-server"
    SERVER_VERSION = "3.2.0"

    def __init__(self, orchestrator: EnterpriseRAGOrchestrator) -> None:
        self.orchestrator = orchestrator

    def handle_jsonrpc(self, token: str, rpc_request: dict[str, Any]) -> dict[str, Any]:
        """Process a JSON-RPC 2.0 MCP request authenticated with an Active Directory JWT."""
        rpc_id = rpc_request.get("id", 1)
        jsonrpc_ver = str(rpc_request.get("jsonrpc", "2.0"))
        method = str(rpc_request.get("method", "")).strip()
        params = rpc_request.get("params") or {}

        # 1. Verify OIDC / Active Directory Identity
        try:
            user = self.orchestrator.idp.verify_token_and_resolve_user(token)
        except PermissionError as exc:
            return {
                "jsonrpc": jsonrpc_ver,
                "id": rpc_id,
                "error": {
                    "code": -32001,
                    "message": f"MCP Auth Error (Active Directory JWT): {exc}",
                },
            }

        # 2. Dispatch standard MCP methods
        if method == "initialize":
            return {
                "jsonrpc": jsonrpc_ver,
                "id": rpc_id,
                "result": {
                    "protocolVersion": self.PROTOCOL_VERSION,
                    "serverInfo": {
                        "name": self.SERVER_NAME,
                        "version": self.SERVER_VERSION,
                    },
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {"subscribe": False, "listChanged": True},
                    },
                    "rbacSessionContext": {
                        "username": user.username,
                        "primary_department": user.primary_department,
                        "allowed_departments": user.allowed_departments,
                        "max_classification": user.max_classification,
                        "can_view_raw_pii": user.can_view_raw_pii,
                    },
                },
            }

        if method == "tools/list":
            connectors = self.orchestrator.connectors.list_available_connectors()
            mcp_tools: list[dict[str, Any]] = []
            for conn in connectors:
                req_dept = conn["required_department"]
                authorized = req_dept in user.allowed_departments
                mcp_tools.append(
                    {
                        "name": conn["tool_name"],
                        "description": (
                            f"[{conn['connector_system']}] {conn['description']} "
                            f"(Requiere grupo AD mapeado al depto '{req_dept}')"
                        ),
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "query": {
                                    "type": "string",
                                    "description": "Instrucción o identificador de negocio (ej. SIN-2026-88410 o FAC-99201).",
                                },
                                "require_hitl": {
                                    "type": "boolean",
                                    "description": "Si es true, exige confirmación Human-in-the-Loop para escritura.",
                                },
                            },
                            "required": ["query"],
                        },
                        "annotations": {
                            "connector_system": conn["connector_system"],
                            "action_type": conn["action_type"],
                            "required_department": req_dept,
                            "authorized_for_current_user": authorized,
                        },
                    }
                )
            return {
                "jsonrpc": jsonrpc_ver,
                "id": rpc_id,
                "result": {"tools": mcp_tools},
            }

        if method == "tools/call":
            tool_name = str(params.get("name", "")).strip()
            arguments = params.get("arguments") or {}
            query_text = str(arguments.get("query", f"Invocación MCP sobre {tool_name}"))
            require_hitl = bool(arguments.get("require_hitl", False))

            invocations = self.orchestrator.connectors.detect_and_execute_tools(
                query=query_text,
                user=user,
                explicit_tool=tool_name,
                explicit_params=arguments,
                require_hitl=require_hitl,
            )
            if not invocations:
                return {
                    "jsonrpc": jsonrpc_ver,
                    "id": rpc_id,
                    "error": {
                        "code": -32602,
                        "message": f"Herramienta MCP '{tool_name}' no encontrada en el registro empresarial.",
                    },
                }

            inv = invocations[0]
            is_error = inv.status == "RBAC_DENIED"

            audit_receipt = self.orchestrator.audit_logger.log_interaction(
                event_type="MCP_JSONRPC_TOOL_CALL_DENIED" if is_error else "MCP_JSONRPC_TOOL_CALL",
                username=user.username,
                user_department=user.primary_department,
                ad_groups=user.ad_groups,
                query_masked=f"MCP tools/call '{tool_name}' (action_type={inv.action_type})",
                where_filter={"required_department": inv.required_department},
                allowed_chunk_ids=[],
                blocked_chunks_count=1 if is_error else 0,
                pii_masked_count=0,
                routing_target="MCP_SERVER_JSONRPC_GATEWAY",
                tool_invocations=[inv.to_dict()],
                security_risk_level="MEDIO" if is_error else "BAJO",
                cache_status="MCP_DIRECT_EXECUTION",
            )

            return {
                "jsonrpc": jsonrpc_ver,
                "id": rpc_id,
                "result": {
                    "isError": is_error,
                    "content": [
                        {
                            "type": "text",
                            "text": inv.result_summary,
                        }
                    ],
                    "structuredOutput": inv.to_dict(),
                    "auditReceipt": audit_receipt,
                },
            }

        if method == "resources/list":
            # Strictly filter resources by the user's Active Directory RBAC scope!
            authorized_resources: list[dict[str, Any]] = []
            for dept in user.allowed_departments:
                col_name = self.orchestrator.vector_store._collection_name(dept)
                dept_chunks = self.orchestrator.vector_store._collections.get(col_name, {})
                for ch in dept_chunks.values():
                    if RBACEngine.is_chunk_authorized(ch, user):
                        authorized_resources.append(
                            {
                                "uri": f"aegis://department/{ch.department}/{ch.chunk_id}",
                                "name": ch.title,
                                "description": (
                                    f"Fuente: {ch.source_system} | Depto: {ch.department} | "
                                    f"Clasificación: {ch.classification}"
                                ),
                                "mimeType": "text/plain",
                                "annotations": {
                                    "chunk_id": ch.chunk_id,
                                    "department": ch.department,
                                    "classification": ch.classification,
                                    "source_system": ch.source_system,
                                },
                            }
                        )
            return {
                "jsonrpc": jsonrpc_ver,
                "id": rpc_id,
                "result": {
                    "resources": authorized_resources,
                    "rbacFilterApplied": RBACEngine.build_chromadb_where_filter(user),
                },
            }

        if method == "resources/read":
            uri = str(params.get("uri", "")).strip()
            target_chunk = None
            for dept_chunks in self.orchestrator.vector_store._collections.values():
                for ch in dept_chunks.values():
                    candidate_uri = f"aegis://department/{ch.department}/{ch.chunk_id}"
                    if candidate_uri == uri or ch.chunk_id == uri:
                        target_chunk = ch
                        break
                if target_chunk:
                    break

            if target_chunk is None:
                return {
                    "jsonrpc": jsonrpc_ver,
                    "id": rpc_id,
                    "error": {
                        "code": -32002,
                        "message": f"Recurso MCP '{uri}' no encontrado.",
                    },
                }

            # Enforce Permission-Aware Access Control on resource read
            if not RBACEngine.is_chunk_authorized(target_chunk, user):
                self.orchestrator.audit_logger.log_interaction(
                    event_type="MCP_RESOURCE_READ_DENIED_RBAC",
                    username=user.username,
                    user_department=user.primary_department,
                    ad_groups=user.ad_groups,
                    query_masked=f"Intento bloqueado MCP resources/read sobre {uri}",
                    where_filter={
                        "target_department": target_chunk.department,
                        "target_classification": target_chunk.classification,
                    },
                    allowed_chunk_ids=[],
                    blocked_chunks_count=1,
                    pii_masked_count=0,
                    routing_target="MCP_SERVER_JSONRPC_GATEWAY",
                    tool_invocations=[],
                    security_risk_level="ALTO",
                    cache_status="RBAC_DENIED",
                )
                return {
                    "jsonrpc": jsonrpc_ver,
                    "id": rpc_id,
                    "error": {
                        "code": -32003,
                        "message": (
                            f"RBAC Denegado en MCP resources/read: El usuario '{user.username}' "
                            f"({user.primary_department}) no tiene permisos para acceder al recurso "
                            f"del departamento '{target_chunk.department}' ({target_chunk.classification})."
                        ),
                    },
                }

            # Apply Ley 21.719 PII anonymization if user is not authorized for raw PII
            pii_res = self.orchestrator.privacy_guard.anonymize(target_chunk.content)
            displayed_text = target_chunk.content if user.can_view_raw_pii else pii_res.anonymized_text

            return {
                "jsonrpc": jsonrpc_ver,
                "id": rpc_id,
                "result": {
                    "contents": [
                        {
                            "uri": f"aegis://department/{target_chunk.department}/{target_chunk.chunk_id}",
                            "mimeType": "text/plain",
                            "text": displayed_text,
                            "piiMaskedByLey21719": not user.can_view_raw_pii,
                            "piiEntitiesDetected": len(pii_res.entities),
                        }
                    ]
                },
            }

        return {
            "jsonrpc": jsonrpc_ver,
            "id": rpc_id,
            "error": {
                "code": -32601,
                "message": (
                    f"Método MCP '{method}' no soportado. Métodos válidos: "
                    "initialize, tools/list, tools/call, resources/list, resources/read."
                ),
            },
        }
