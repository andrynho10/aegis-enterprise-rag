"""Standards-compliant OIDC / JWT Token Manager (RFC 7519)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from typing import Any

from app.config.settings import settings


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


class JWTManager:
    """Issues and validates OIDC/Entra-compatible JWT tokens with AD group claims."""

    def __init__(
        self,
        secret: str = settings.jwt_secret,
        issuer: str = settings.jwt_issuer,
        audience: str = settings.jwt_audience,
        ttl_seconds: int = settings.jwt_ttl_seconds,
    ) -> None:
        self.secret = secret.encode("utf-8")
        self.issuer = issuer
        self.audience = audience
        self.ttl_seconds = ttl_seconds

    def create_oidc_token(
        self,
        user_id: str,
        username: str,
        full_name: str,
        email: str,
        job_title: str,
        ad_groups: list[str],
        mfa_verified: bool = True,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        now = int(time.time())
        header = {"alg": "HS256", "typ": "JWT", "kid": "entra-key-2026-01"}
        payload: dict[str, Any] = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": user_id,
            "oid": user_id,
            "tid": "72f988bf-86f1-41af-91ab-2d7cd011db47",  # Corporate Tenant ID
            "preferred_username": username,
            "upn": email,
            "name": full_name,
            "job_title": job_title,
            "groups": ad_groups,  # Active Directory Security Group memberships
            "amr": ["pwd", "mfa"] if mfa_verified else ["pwd"],
            "iat": now,
            "nbf": now,
            "exp": now + self.ttl_seconds,
            "jti": str(uuid.uuid4()),
        }
        if extra_claims:
            payload.update(extra_claims)

        header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        signature = hmac.new(self.secret, signing_input, hashlib.sha256).digest()
        sig_b64 = _b64url_encode(signature)
        return f"{header_b64}.{payload_b64}.{sig_b64}"

    def verify_and_decode(self, token: str) -> dict[str, Any]:
        parts = token.strip().split(".")
        if len(parts) != 3:
            raise ValueError("Formato de token JWT inválido.")

        header_b64, payload_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected_sig = hmac.new(self.secret, signing_input, hashlib.sha256).digest()
        actual_sig = _b64url_decode(sig_b64)

        if not hmac.compare_digest(expected_sig, actual_sig):
            raise PermissionError("Firma criptográfica del token JWT inválida (posible adulteración).")

        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        now = int(time.time())
        if payload.get("exp", 0) < now:
            raise PermissionError("El token corporativo SSO ha expirado.")
        if payload.get("aud") != self.audience:
            raise PermissionError("Audiencia (aud) del token inválida.")

        return payload
