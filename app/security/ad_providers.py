"""Active Directory & Microsoft Entra ID Identity Providers (Mock + MSAL + LDAP3)."""
from __future__ import annotations

from typing import Any

from app.config.settings import settings
from app.domain.models import UserIdentity
from app.domain.ports import IdentityProviderPort
from app.security.jwt_manager import JWTManager
from app.security.rbac_engine import RBACEngine


CORPORATE_DIRECTORY_USERS: dict[str, dict[str, Any]] = {
    "camila.soto": {
        "user_id": "ad-oid-1001-salud",
        "username": "camila.soto",
        "full_name": "Camila Soto Valdés",
        "email": "camila.soto@aseguradora-isa.cl",
        "job_title": "Liquidadora Senior de Siniestros de Salud",
        "primary_department": "salud_siniestros",
        "ad_groups": ["GRP_AD_EMPLEADOS_TODOS", "GRP_AD_SALUD_LIQUIDADORES"],
        "account_enabled": True,
        "mfa_verified": True,
    },
    "roberto.mendez": {
        "user_id": "ad-oid-1002-finanzas",
        "username": "roberto.mendez",
        "full_name": "Roberto Méndez Lagos",
        "email": "roberto.mendez@aseguradora-isa.cl",
        "job_title": "Analista de Control Financiero y Presupuesto",
        "primary_department": "finanzas",
        "ad_groups": ["GRP_AD_EMPLEADOS_TODOS", "GRP_AD_FINANZAS_ANALISTAS"],
        "account_enabled": True,
        "mfa_verified": True,
    },
    "valentina.rojas": {
        "user_id": "ad-oid-1003-rrhh",
        "username": "valentina.rojas",
        "full_name": "Valentina Rojas Pizarro",
        "email": "valentina.rojas@aseguradora-isa.cl",
        "job_title": "Subgerenta de Personas y Remuneraciones (RR.HH.)",
        "primary_department": "rrhh",
        "ad_groups": ["GRP_AD_EMPLEADOS_TODOS", "GRP_AD_RRHH_GESTION"],
        "account_enabled": True,
        "mfa_verified": True,
    },
    "diego.vargas": {
        "user_id": "ad-oid-1004-auditor",
        "username": "diego.vargas",
        "full_name": "Diego Vargas Araya",
        "email": "diego.vargas@aseguradora-isa.cl",
        "job_title": "Oficial de Cumplimiento y Privacidad (DPO Ley 21.719)",
        "primary_department": "legal_cumplimiento",
        "ad_groups": ["GRP_AD_EMPLEADOS_TODOS", "GRP_AD_LEGAL_CUMPLIMIENTO"],
        "account_enabled": True,
        "mfa_verified": True,
    },
    "matias.silva": {
        "user_id": "ad-oid-1005-ti",
        "username": "matias.silva",
        "full_name": "Matías Silva Contreras",
        "email": "matias.silva@aseguradora-isa.cl",
        "job_title": "Ingeniero de Plataforma TI y Ciberseguridad",
        "primary_department": "ti_operaciones",
        "ad_groups": ["GRP_AD_EMPLEADOS_TODOS", "GRP_AD_TI_OPERACIONES"],
        "account_enabled": True,
        "mfa_verified": True,
    },
    "ex.empleado": {
        "user_id": "ad-oid-9999-revoked",
        "username": "ex.empleado",
        "full_name": "Jorge Ramírez (Cuenta Desvinculada AD)",
        "email": "jorge.ramirez@aseguradora-isa.cl",
        "job_title": "Ex-Ejecutivo Comercial (Cuenta Desactivada en Entra ID)",
        "primary_department": "comercial",
        "ad_groups": ["GRP_AD_EMPLEADOS_TODOS"],
        "account_enabled": False,  # Demonstrates automatic SSO revocation when offboarded
        "mfa_verified": False,
    },
}


class MockActiveDirectoryProvider(IdentityProviderPort):
    """
    Local Active Directory / Microsoft Entra ID Simulator.
    Issues real cryptographically signed OIDC JWT tokens containing AD group claims.
    """

    def __init__(self, jwt_manager: JWTManager | None = None) -> None:
        self.jwt_manager = jwt_manager or JWTManager()

    def _build_user_identity(self, raw_entry: dict[str, Any], idp_label: str = "Microsoft Entra ID (OIDC/SSO Simulator)") -> UserIdentity:
        perms = RBACEngine.resolve_permissions_from_ad_groups(raw_entry["ad_groups"])
        return UserIdentity(
            user_id=raw_entry["user_id"],
            username=raw_entry["username"],
            full_name=raw_entry["full_name"],
            email=raw_entry["email"],
            job_title=raw_entry["job_title"],
            primary_department=raw_entry["primary_department"],
            allowed_departments=perms["allowed_departments"],
            ad_groups=list(raw_entry["ad_groups"]),
            roles=perms["roles"],
            max_classification=perms["max_classification"],
            can_view_raw_pii=perms["can_view_raw_pii"],
            can_execute_write_actions=perms["can_execute_write_actions"],
            mfa_verified=raw_entry.get("mfa_verified", True),
            idp_source=idp_label,
        )

    def authenticate_and_issue_token(self, username: str) -> tuple[str, UserIdentity]:
        entry = CORPORATE_DIRECTORY_USERS.get(username)
        if not entry:
            raise PermissionError(f"Usuario '{username}' no existe en el Directorio Activo.")

        if not entry.get("account_enabled", True):
            raise PermissionError(
                f"ACCESO REVOCADO POR SSO: La cuenta corporativa de '{entry['full_name']}' "
                "fue desactivada en Active Directory / Entra ID (offboarding automático)."
            )

        identity = self._build_user_identity(entry)
        token = self.jwt_manager.create_oidc_token(
            user_id=identity.user_id,
            username=identity.username,
            full_name=identity.full_name,
            email=identity.email,
            job_title=identity.job_title,
            ad_groups=identity.ad_groups,
            mfa_verified=identity.mfa_verified,
            extra_claims={
                "primary_department": identity.primary_department,
                "account_enabled": True,
            },
        )
        return token, identity

    def verify_token_and_resolve_user(self, token: str) -> UserIdentity:
        payload = self.jwt_manager.verify_and_decode(token)
        username = payload.get("preferred_username", "")
        # Verify real-time revocation status in directory
        directory_entry = CORPORATE_DIRECTORY_USERS.get(username)
        if directory_entry and not directory_entry.get("account_enabled", True):
            raise PermissionError(
                "ACCESO REVOCADO: La cuenta fue deshabilitada en Active Directory después de la emisión del token."
            )

        ad_groups = payload.get("groups", [])
        perms = RBACEngine.resolve_permissions_from_ad_groups(ad_groups)
        return UserIdentity(
            user_id=payload.get("sub", "unknown"),
            username=username,
            full_name=payload.get("name", username),
            email=payload.get("upn", ""),
            job_title=payload.get("job_title", ""),
            primary_department=payload.get("primary_department", "publico_corporativo"),
            allowed_departments=perms["allowed_departments"],
            ad_groups=ad_groups,
            roles=perms["roles"],
            max_classification=perms["max_classification"],
            can_view_raw_pii=perms["can_view_raw_pii"],
            can_execute_write_actions=perms["can_execute_write_actions"],
            mfa_verified="mfa" in payload.get("amr", []),
            idp_source="Microsoft Entra ID (OIDC/JWT Verified)",
        )

    def list_directory_users(self) -> list[UserIdentity]:
        users: list[UserIdentity] = []
        for entry in CORPORATE_DIRECTORY_USERS.values():
            label = (
                "Microsoft Entra ID (Activa + MFA)"
                if entry.get("account_enabled", True)
                else "Microsoft Entra ID (CUENTA REVOCADA / DESVINCULADA)"
            )
            users.append(self._build_user_identity(entry, idp_label=label))
        return users


class EntraIDMSALProvider(IdentityProviderPort):
    """
    Production Adapter for Microsoft Entra ID (formerly Azure AD) using MSAL & OIDC.
    Requires `pip install msal PyJWT[crypto]` and ENTRA_TENANT_ID / ENTRA_CLIENT_ID configured.
    """

    def __init__(self) -> None:
        self.tenant_id = settings.entra_tenant_id
        self.client_id = settings.entra_client_id
        self.client_secret = settings.entra_client_secret
        self.authority = f"https://login.microsoftonline.com/{self.tenant_id}"

    def authenticate_and_issue_token(self, username: str) -> tuple[str, UserIdentity]:
        try:
            import msal  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "Para usar EntraIDMSALProvider en producción, instala `pip install msal`."
            ) from exc

        app = msal.ConfidentialClientApplication(
            self.client_id,
            authority=self.authority,
            client_credential=self.client_secret,
        )
        # In production OAuth2 Authorization Code Flow with PKCE, the frontend exchanges `code` via `acquire_token_by_authorization_code`
        raise NotImplementedError(
            f"Configurado para Entra ID authority={self.authority} con MSAL ({app.authority.instance}). "
            "Use el flujo OIDC Authorization Code en producción."
        )

    def verify_token_and_resolve_user(self, token: str) -> UserIdentity:
        raise NotImplementedError("Validación contra JWKS de Microsoft Entra ID lista para configurar tenant.")

    def list_directory_users(self) -> list[UserIdentity]:
        return []


class ActiveDirectoryLDAPProvider(IdentityProviderPort):
    """
    Production Adapter for On-Premise Windows Server Active Directory via LDAP/LDAPS (`ldap3`).
    Resolves `memberOf` security groups directly from Domain Controller.
    """

    def __init__(self) -> None:
        self.server_uri = settings.ldap_server_uri
        self.base_dn = settings.ldap_base_dn

    def authenticate_and_issue_token(self, username: str) -> tuple[str, UserIdentity]:
        try:
            import ldap3  # type: ignore  # noqa: F401
        except ImportError as exc:
            raise RuntimeError(
                "Para conectar a un Active Directory on-premise vía LDAPS, instala `pip install ldap3`."
            ) from exc
        raise NotImplementedError(
            f"Conector LDAPS configurado para {self.server_uri} ({self.base_dn})."
        )

    def verify_token_and_resolve_user(self, token: str) -> UserIdentity:
        raise NotImplementedError("Verificación delegada a JWTManager tras bind LDAPS.")

    def list_directory_users(self) -> list[UserIdentity]:
        return []
