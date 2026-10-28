"""Unified Launcher for AegisRAG Enterprise (FastAPI/Uvicorn or Zero-Dependency ThreadingHTTPServer)."""
from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.api.controllers import EnterpriseAPIController
from app.config.settings import settings

WEB_INDEX = Path(__file__).resolve().parent / "app" / "web" / "index.html"
CONTROLLER = EnterpriseAPIController()


class EnterpriseHTTPRequestHandler(BaseHTTPRequestHandler):
    """Production-grade JSON & HTML HTTP Handler routing directly to EnterpriseAPIController."""

    def log_message(self, format: str, *args: Any) -> None:
        # Clean structured console logging
        sys.stdout.write(f"[AegisRAG HTTP] {self.address_string()} - {format % args}\n")

    def _send_json(self, status_code: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _send_html(self, html_text: str) -> None:
        raw = html_text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        return json.loads(raw) if raw else {}

    def _extract_bearer_token(self) -> str:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise PermissionError("Falta encabezado Authorization: Bearer <JWT>")
        return auth.removeprefix("Bearer ").strip()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            self._send_html(WEB_INDEX.read_text(encoding="utf-8"))
            return
        if path == "/api/v1/health":
            self._send_json(200, CONTROLLER.get_system_health())
            return
        if path == "/api/v1/auth/users":
            self._send_json(200, CONTROLLER.list_directory_users())
            return
        if path == "/api/v1/compliance/audit-logs":
            self._send_json(200, CONTROLLER.get_compliance_dashboard())
            return

        self._send_json(404, {"detail": f"Ruta '{path}' no encontrada."})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        try:
            body = self._read_json_body()
            if path == "/api/v1/auth/login":
                res = CONTROLLER.login_sso(str(body.get("username", "")))
                self._send_json(200, res)
                return

            if path == "/api/v1/compliance/reset-corpus":
                res = CONTROLLER.reset_seed_corpus()
                self._send_json(200, res)
                return

            if path == "/api/v1/rag/query":
                token = self._extract_bearer_token()
                res = CONTROLLER.execute_rag_query(token=token, body=body)
                self._send_json(200, res)
                return

            if path == "/api/v1/rag/ingest":
                token = self._extract_bearer_token()
                res = CONTROLLER.ingest_document(token=token, body=body)
                self._send_json(200, res)
                return

            if path == "/api/v1/compliance/arco-delete":
                token = self._extract_bearer_token()
                res = CONTROLLER.execute_arco_erasure(token=token, body=body)
                self._send_json(200, res)
                return

            self._send_json(404, {"detail": f"Endpoint POST '{path}' no encontrado."})
        except PermissionError as exc:
            self._send_json(403, {"detail": str(exc)})
        except ValueError as exc:
            self._send_json(400, {"detail": str(exc)})
        except Exception as exc:
            self._send_json(500, {"detail": f"Error interno del servidor: {exc}"})


def main() -> None:
    host = settings.host
    port = settings.port
    use_fastapi = "--fastapi" in sys.argv

    if use_fastapi:
        try:
            import uvicorn  # type: ignore
            from app.api.fastapi_app import create_fastapi_app

            print(f"[*] Iniciando AegisRAG Enterprise (FastAPI + Uvicorn) en http://{host}:{port}")
            uvicorn.run(create_fastapi_app(CONTROLLER), host=host, port=port)
            return
        except ImportError:
            print("[!] FastAPI/Uvicorn no detectados en el entorno actual; activando servidor nativo de alta velocidad.")

    server = ThreadingHTTPServer((host, port), EnterpriseHTTPRequestHandler)
    print("=" * 78)
    print(f"  {settings.app_name}")
    print(f"  Dashboard Interactivo y API activa en: http://{host}:{port}")
    print("  SSO Active Directory • ChromaDB RBAC • Presidio PII • Router Híbrido • ARCO")
    print("=" * 78)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Servidor detenido correctamente.")
        server.server_close()


if __name__ == "__main__":
    main()
