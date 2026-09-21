import asyncio
import base64
import binascii
import json
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any
from uuid import UUID

import httpx
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import OKPKey
from joserfc.jwt import JWTClaimsRegistry

ALLOWED_ALGORITHMS = frozenset({"Ed25519"})
API_KEY_SCOPES = frozenset({"api:execute", "api:assets", "api:sessions", "api:read", "admin:org"})
MAX_TOKEN_LENGTH = 32_768
MAX_TOKEN_LIFETIME_SECONDS = 10 * 60
CLOCK_SKEW_LEEWAY_SECONDS = 30
JWKS_FAILURE_BACKOFF_SECONDS = 5
UNKNOWN_KID_REFRESH_INTERVAL_SECONDS = 5


@dataclass(frozen=True, slots=True)
class VerifiedPrincipal:
    principal_id: str
    grants: Mapping[str, frozenset[str]]
    kind: str
    organization_id: UUID | None
    account_id: UUID
    api_key_id: UUID | None
    api_key_scopes: frozenset[str] | None
    jti: UUID
    expires_at: int


class TokenVerifier:
    def __init__(
        self,
        *,
        jwks_url: str,
        issuer: str,
        audience: str,
        client: httpx.AsyncClient | None = None,
        cache_ttl_seconds: int = 300,
    ) -> None:
        if cache_ttl_seconds <= 0:
            raise ValueError("JWKS cache lifetime must be positive")
        self._jwks_url = jwks_url
        self._issuer = issuer
        self._audience = audience
        self._client = client
        self._cache_ttl_seconds = cache_ttl_seconds
        self._keys: dict[str, OKPKey] = {}
        self._cache_expires_at = 0.0
        self._refresh_retry_at = 0.0
        self._next_unknown_kid_refresh_at = 0.0
        self._refresh_lock = asyncio.Lock()

    async def verify(self, token: str) -> VerifiedPrincipal | None:
        header = self._protected_header(token)
        if header is None:
            return None
        kid = header["kid"]
        key = await self._verification_key(kid)
        if key is None:
            return None

        now = int(time.time())
        try:
            decoded = jwt.decode(token, key, algorithms=ALLOWED_ALGORITHMS)
            claims = decoded.claims
            JWTClaimsRegistry(
                now=now,
                leeway=CLOCK_SKEW_LEEWAY_SECONDS,
                iss={"essential": True, "value": self._issuer},
                aud={"essential": True, "value": self._audience},
                sub={"essential": True},
                kind={"essential": True},
                grants={"essential": True},
                acct={"essential": True},
                exp={"essential": True},
                iat={"essential": True},
                jti={"essential": True},
            ).validate(claims)
            if not self._valid_times(claims, now):
                return None
            return self._principal(claims)
        except (JoseError, KeyError, TypeError, ValueError):
            return None

    def _protected_header(self, token: str) -> dict[str, str] | None:
        if not token or len(token) > MAX_TOKEN_LENGTH:
            return None
        parts = token.split(".")
        if len(parts) != 3:
            return None
        try:
            encoded = parts[0].encode("ascii")
            padding = b"=" * (-len(encoded) % 4)
            raw_header = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
            header = json.loads(raw_header)
        except (UnicodeEncodeError, UnicodeDecodeError, binascii.Error, json.JSONDecodeError):
            return None
        if not isinstance(header, dict):
            return None
        alg = header.get("alg")
        kid = header.get("kid")
        typ = header.get("typ")
        if (
            not isinstance(alg, str)
            or alg not in ALLOWED_ALGORITHMS
            or not isinstance(kid, str)
            or not kid
        ):
            return None
        if typ is not None and typ != "JWT":
            return None
        return {"alg": alg, "kid": kid}

    async def _verification_key(self, kid: str) -> OKPKey | None:
        now = time.monotonic()
        cached = self._keys.get(kid)
        if cached is not None and now < self._cache_expires_at:
            return cached
        if now < self._refresh_retry_at:
            return cached
        if self._keys and now < self._cache_expires_at and now < self._next_unknown_kid_refresh_at:
            return None

        async with self._refresh_lock:
            now = time.monotonic()
            cached = self._keys.get(kid)
            if cached is not None and now < self._cache_expires_at:
                return cached
            if now < self._refresh_retry_at:
                return cached
            if self._keys and now < self._cache_expires_at:
                if now < self._next_unknown_kid_refresh_at:
                    return None
                self._next_unknown_kid_refresh_at = now + UNKNOWN_KID_REFRESH_INTERVAL_SECONDS
            try:
                keys, ttl = await self._fetch_jwks()
            except (httpx.HTTPError, KeyError, TypeError, ValueError):
                self._refresh_retry_at = time.monotonic() + JWKS_FAILURE_BACKOFF_SECONDS
                return cached
            self._keys = keys
            self._cache_expires_at = time.monotonic() + ttl
            self._refresh_retry_at = 0.0
            key = keys.get(kid)
            if key is None:
                self._next_unknown_kid_refresh_at = (
                    time.monotonic() + UNKNOWN_KID_REFRESH_INTERVAL_SECONDS
                )
            return key

    async def _fetch_jwks(self) -> tuple[dict[str, OKPKey], int]:
        if self._client is None:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(self._jwks_url)
        else:
            response = await self._client.get(self._jwks_url)
        response.raise_for_status()
        payload: Any = response.json()
        if not isinstance(payload, dict) or not isinstance(payload.get("keys"), list):
            raise ValueError("JWKS response is malformed")

        keys: dict[str, OKPKey] = {}
        for raw_key in payload["keys"]:
            if not isinstance(raw_key, dict):
                raise ValueError("JWKS key is malformed")
            if (
                raw_key.get("alg") != "Ed25519"
                or raw_key.get("kty") != "OKP"
                or raw_key.get("crv") != "Ed25519"
                or raw_key.get("use") not in (None, "sig")
                or "d" in raw_key
            ):
                raise ValueError("JWKS contains an unsupported key")
            kid = raw_key.get("kid")
            if not isinstance(kid, str) or not kid or kid in keys:
                raise ValueError("JWKS key identifier is invalid")
            keys[kid] = OKPKey.import_key(raw_key)
        if not keys:
            raise ValueError("JWKS contains no verification keys")

        ttl = self._cache_ttl_seconds
        cache_control = response.headers.get("cache-control", "")
        max_age = re.search(r"(?:^|,)\s*max-age=(\d+)\s*(?:,|$)", cache_control)
        if max_age is not None:
            ttl = max(1, min(ttl, int(max_age.group(1))))
        return keys, ttl

    @staticmethod
    def _valid_times(claims: dict[str, Any], now: int) -> bool:
        issued_at = claims.get("iat")
        expires_at = claims.get("exp")
        return (
            isinstance(issued_at, int)
            and not isinstance(issued_at, bool)
            and issued_at <= now + CLOCK_SKEW_LEEWAY_SECONDS
            and isinstance(expires_at, int)
            and not isinstance(expires_at, bool)
            and expires_at >= now - CLOCK_SKEW_LEEWAY_SECONDS
            and 0 < expires_at - issued_at <= MAX_TOKEN_LIFETIME_SECONDS
        )

    @staticmethod
    def _principal(claims: dict[str, Any]) -> VerifiedPrincipal:
        principal_id = claims["sub"]
        kind = claims["kind"]
        raw_grants = claims["grants"]
        if not isinstance(principal_id, str) or not isinstance(kind, str):
            raise ValueError("Principal claims are invalid")
        if kind not in {"human", "agent"} or not isinstance(raw_grants, dict):
            raise ValueError("Principal claims are invalid")

        prefix, separator, raw_id = principal_id.partition("_")
        if separator != "_" or prefix not in {"u", "k"} or str(UUID(raw_id)) != raw_id:
            raise ValueError("Principal identifier is invalid")
        if prefix == "u" and kind != "human":
            raise ValueError("User principals must be human")

        organization_id = TokenVerifier._optional_uuid_claim(claims["org"])
        account_id = TokenVerifier._uuid_claim(claims["acct"])
        api_key_id = TokenVerifier._optional_uuid_claim(claims["key"])
        jti = TokenVerifier._uuid_claim(claims["jti"])

        raw_api_key_scopes = claims.get("key_scopes")
        if prefix == "u":
            if api_key_id is not None or raw_api_key_scopes is not None:
                raise ValueError("User principal API key claims are invalid")
            api_key_scopes = None
        else:
            if api_key_id != UUID(raw_id) or not isinstance(raw_api_key_scopes, list):
                raise ValueError("API key principal claims are invalid")
            if (
                not raw_api_key_scopes
                or len(raw_api_key_scopes) > len(API_KEY_SCOPES)
                or not all(isinstance(scope, str) and scope for scope in raw_api_key_scopes)
            ):
                raise ValueError("API key scopes claim is invalid")
            api_key_scopes = frozenset(raw_api_key_scopes)
            if (
                len(api_key_scopes) != len(raw_api_key_scopes)
                or not api_key_scopes <= API_KEY_SCOPES
            ):
                raise ValueError("API key scopes claim is invalid")

        grants: dict[str, frozenset[str]] = {}
        for scope, capabilities in raw_grants.items():
            if not isinstance(scope, str) or not scope or not isinstance(capabilities, list):
                raise ValueError("Grants claim is invalid")
            resource_kind, separator, resource_id = scope.partition(":")
            if separator != ":" or resource_kind not in {"org", "project"}:
                raise ValueError("Grant scope is invalid")
            scope_id = TokenVerifier._uuid_claim(resource_id)
            if resource_kind == "org" and scope_id != organization_id:
                raise ValueError("Organization grant does not match token context")
            if not all(isinstance(capability, str) and capability for capability in capabilities):
                raise ValueError("Grants claim is invalid")
            grants[scope] = frozenset(capabilities)
        return VerifiedPrincipal(
            principal_id=principal_id,
            grants=MappingProxyType(grants),
            kind=kind,
            organization_id=organization_id,
            account_id=account_id,
            api_key_id=api_key_id,
            api_key_scopes=api_key_scopes,
            jti=jti,
            expires_at=claims["exp"],
        )

    @staticmethod
    def _uuid_claim(value: Any) -> UUID:
        if not isinstance(value, str):
            raise ValueError("Identifier claim is invalid")
        parsed = UUID(value)
        if str(parsed) != value:
            raise ValueError("Identifier claim is invalid")
        return parsed

    @staticmethod
    def _optional_uuid_claim(value: Any) -> UUID | None:
        return None if value is None else TokenVerifier._uuid_claim(value)
