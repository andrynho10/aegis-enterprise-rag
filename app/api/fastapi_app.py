"""FastAPI Production Entrypoint with OpenAPI Documentation & JWT Bearer Security."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from app.api.controllers import EnterpriseAPIController

WEB_DIR = Path(__file__).resolve().parent.parent / "web"


def create_fastapi_app(controller: EnterpriseAPIController | None = None) -> Any:
    """Create FastAPI instance when `fastapi` is installed in the environment."""
    from fastapi import Depends, FastAPI, Header, HTTPException
    from fastapi.responses import HTMLResponse

    ctrl = controller or EnterpriseAPIController()
    app = FastAPI(
        title="AegisRAG Enterprise - Plataforma Agentic RAG",
        version="2.0.0",
        description=(
            "Sistema RAG Empresarial con SSO (Entra ID / Active Directory), "
            "Permission-Aware Retrieval (ChromaDB RBAC), Anonimización PII (Ley 21.719), "
            "Router Híbrido (Local Ollama/vLLM vs Nube Privada ZDR vs API) y Auditoría Inmutable."
        ),
    )

    def extract_bearer_token(authorization: str = Header(default="")) -> str:
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Falta encabezado Authorization: Bearer <JWT>")
        return authorization.removeprefix("Bearer ").strip()

    @app.get("/", response_class=HTMLResponse)
    def serve_dashboard() -> str:
        return (WEB_DIR / "index.html").read_text(encoding="utf-8")

    @app.get("/api/v1/health")
    def health() -> dict[str, Any]:
        return ctrl.get_system_health()

    @app.get("/api/v1/auth/users")
    def list_users() -> dict[str, Any]:
        return ctrl.list_directory_users()

    @app.post("/api/v1/auth/login")
    def login(body: dict[str, Any]) -> dict[str, Any]:
        try:
            return ctrl.login_sso(str(body.get("username", "")))
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    @app.post("/api/v1/rag/query")
    def rag_query(body: dict[str, Any], token: str = Depends(extract_bearer_token)) -> dict[str, Any]:
        try:
            return ctrl.execute_rag_query(token=token, body=body)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/v1/rag/ingest")
    def rag_ingest(body: dict[str, Any], token: str = Depends(extract_bearer_token)) -> dict[str, Any]:
        try:
            return ctrl.ingest_document(token=token, body=body)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    @app.post("/api/v1/compliance/arco-delete")
    def arco_delete(body: dict[str, Any], token: str = Depends(extract_bearer_token)) -> dict[str, Any]:
        try:
            return ctrl.execute_arco_erasure(token=token, body=body)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/v1/compliance/reset-corpus")
    def reset_corpus() -> dict[str, Any]:
        return ctrl.reset_seed_corpus()

    @app.post("/api/v1/rag/actions/confirm")
    def confirm_hitl(body: dict[str, Any], token: str = Depends(extract_bearer_token)) -> dict[str, Any]:
        try:
            return ctrl.confirm_hitl_action(token=token, body=body)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/v1/connectors/sync")
    def sync_connector(body: dict[str, Any], token: str = Depends(extract_bearer_token)) -> dict[str, Any]:
        try:
            return ctrl.sync_external_repository(token=token, body=body)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/v1/compliance/redteam")
    def run_redteam() -> dict[str, Any]:
        return ctrl.run_redteam_benchmark()

    @app.get("/api/v1/compliance/audit-logs")
    def audit_logs() -> dict[str, Any]:
        return ctrl.get_compliance_dashboard()

    return app
