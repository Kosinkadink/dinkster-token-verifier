import ast
import time
from pathlib import Path
from uuid import UUID

import httpx
import pytest
from joserfc import jwt
from joserfc.jwk import OKPKey

import dinkster_token_verifier
from dinkster_token_verifier import TokenVerifier


def claims(**changes: object) -> dict[str, object]:
    now = int(time.time())
    organization_id = UUID(int=3)
    values: dict[str, object] = {
        "sub": f"u_{UUID(int=1)}",
        "kind": "human",
        "aud": "dinkster-session",
        "iss": "https://identity.example",
        "org": str(organization_id),
        "acct": str(organization_id),
        "key": None,
        "key_scopes": None,
        "grants": {f"org:{organization_id}": ["project:read"]},
        "iat": now,
        "exp": now + 600,
        "jti": str(UUID(int=2)),
    }
    values.update(changes)
    return values


def public_jwk(key: OKPKey, kid: str) -> dict[str, str]:
    return {
        **key.as_dict(private=False),
        "alg": "Ed25519",
        "kid": kid,
        "use": "sig",
    }


def token(key: OKPKey, kid: str, payload: dict[str, object]) -> str:
    return jwt.encode(
        {"alg": "Ed25519", "kid": kid, "typ": "JWT"},
        payload,
        key,
        algorithms=["Ed25519"],
    )


@pytest.mark.asyncio
async def test_verifies_a_trusted_token_and_caches_the_jwks() -> None:
    key = OKPKey.generate_key("Ed25519")
    access_token = token(key, "key-1", claims())
    requests = 0

    def jwks(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(
            200,
            json={"keys": [public_jwk(key, "key-1")]},
            headers={"cache-control": "public, max-age=60"},
            request=request,
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(jwks)) as client:
        verifier = TokenVerifier(
            jwks_url="https://identity.example/.well-known/jwks.json",
            issuer="https://identity.example",
            audience="dinkster-session",
            client=client,
        )
        first = await verifier.verify(access_token)
        second = await verifier.verify(access_token)

    assert first is not None
    assert second == first
    assert first.principal_id == f"u_{UUID(int=1)}"
    assert first.grants == {f"org:{UUID(int=3)}": frozenset({"project:read"})}
    assert requests == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changes",
    [
        {"aud": "other"},
        {"iss": "https://other.example"},
        {"exp": int(time.time()) - 31},
        {"exp": int(time.time()) + 3600},
        {"grants": {f"org:{UUID(int=4)}": ["project:read"]}},
    ],
)
async def test_rejects_invalid_signed_claims(changes: dict[str, object]) -> None:
    key = OKPKey.generate_key("Ed25519")

    def jwks(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"keys": [public_jwk(key, "key-1")]},
            request=request,
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(jwks)) as client:
        verifier = TokenVerifier(
            jwks_url="https://identity.example/.well-known/jwks.json",
            issuer="https://identity.example",
            audience="dinkster-session",
            client=client,
        )
        assert await verifier.verify(token(key, "key-1", claims(**changes))) is None


@pytest.mark.asyncio
async def test_verifies_an_api_key_agent_with_allowed_scopes() -> None:
    key = OKPKey.generate_key("Ed25519")
    api_key_id = UUID(int=4)

    def jwks(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"keys": [public_jwk(key, "key-1")]},
            request=request,
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(jwks)) as client:
        verifier = TokenVerifier(
            jwks_url="https://identity.example/.well-known/jwks.json",
            issuer="https://identity.example",
            audience="dinkster-session",
            client=client,
        )
        principal = await verifier.verify(
            token(
                key,
                "key-1",
                claims(
                    sub=f"k_{api_key_id}",
                    kind="agent",
                    key=str(api_key_id),
                    key_scopes=["api:execute", "api:assets"],
                ),
            )
        )

    assert principal is not None
    assert principal.principal_id == f"k_{api_key_id}"
    assert principal.kind == "agent"
    assert principal.api_key_id == api_key_id
    assert principal.api_key_scopes == frozenset({"api:execute", "api:assets"})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("key_claim", "scopes"),
    [
        (str(UUID(int=5)), ["api:execute"]),
        (str(UUID(int=4)), []),
        (str(UUID(int=4)), ["api:execute", "api:execute"]),
        (str(UUID(int=4)), ["api:unknown"]),
    ],
)
async def test_rejects_invalid_api_key_agent_claims(key_claim: str, scopes: list[str]) -> None:
    key = OKPKey.generate_key("Ed25519")
    api_key_id = UUID(int=4)

    def jwks(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"keys": [public_jwk(key, "key-1")]},
            request=request,
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(jwks)) as client:
        verifier = TokenVerifier(
            jwks_url="https://identity.example/.well-known/jwks.json",
            issuer="https://identity.example",
            audience="dinkster-session",
            client=client,
        )
        assert (
            await verifier.verify(
                token(
                    key,
                    "key-1",
                    claims(
                        sub=f"k_{api_key_id}",
                        kind="agent",
                        key=key_claim,
                        key_scopes=scopes,
                    ),
                )
            )
            is None
        )


def test_package_has_no_identity_service_imports() -> None:
    package_root = Path(dinkster_token_verifier.__file__).parent
    for path in package_root.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(alias.name.split(".")[0] != "dinkster_identity" for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] != "dinkster_identity"
