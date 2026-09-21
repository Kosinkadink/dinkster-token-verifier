"""Offline signature, freshness, scope, and composition verification."""

from typing import Any
from uuid import UUID

from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.jws import JWSRegistry

from dinkster_token_verifier.policy import EffectivePolicy, Layer

SNAPSHOT_TYPE = "dinkster-policy+jwt"
SNAPSHOT_TTL = 600
SNAPSHOT_INTERVAL = 300
MAX_SNAPSHOT_LENGTH = 16_000_000
SNAPSHOT_REGISTRY = JWSRegistry(algorithms=["Ed25519"])
SNAPSHOT_REGISTRY.max_payload_length = MAX_SNAPSHOT_LENGTH


def verify_snapshot(
    token: str,
    jwks: dict[str, Any],
    *,
    issuer: str,
    now: int,
) -> dict[str, Any]:
    """Raise on any invalid input; callers must not evaluate an unverified payload."""
    if len(token) > MAX_SNAPSHOT_LENGTH:
        raise ValueError("Snapshot exceeds size limit")
    decoded = jwt.decode(
        token,
        KeySet.import_key_set({"keys": jwks["keys"]}),
        registry=SNAPSHOT_REGISTRY,
    )
    if decoded.header.get("typ") != SNAPSHOT_TYPE or decoded.header.get("alg") != "Ed25519":
        raise ValueError("Not a policy snapshot")
    claims = decoded.claims
    if claims.get("iss") != issuer or claims.get("format") != 1:
        raise ValueError("Wrong snapshot issuer or format")
    iat, exp = claims.get("iat"), claims.get("exp")
    if (
        type(iat) is not int
        or type(exp) is not int
        or not iat <= now < exp
        or exp - iat != SNAPSHOT_TTL
    ):
        raise ValueError("Expired or invalid snapshot lifetime")
    return claims


def verify_layer_snapshot(
    token: str,
    jwks: dict[str, Any],
    *,
    issuer: str,
    now: int,
    scope_kind: str,
    scope_id: UUID,
) -> Layer:
    claims = verify_snapshot(token, jwks, issuer=issuer, now=now)
    if claims.get("kind") != "layer":
        raise ValueError("Expected a layer snapshot")
    layer = Layer.model_validate(claims["policy"])
    if layer.scope_kind != scope_kind or layer.scope_id != scope_id:
        raise ValueError("Snapshot scope mismatch")
    return layer


def verify_effective_snapshot(
    token: str,
    jwks: dict[str, Any],
    *,
    issuer: str,
    now: int,
    project_id: UUID,
) -> EffectivePolicy:
    claims = verify_snapshot(token, jwks, issuer=issuer, now=now)
    if claims.get("kind") != "effective":
        raise ValueError("Expected an effective snapshot")
    policy = EffectivePolicy.model_validate(claims["policy"])
    if policy.project_id != project_id:
        raise ValueError("Snapshot project mismatch")
    project = verify_layer_snapshot(
        claims["inputs"]["project"],
        jwks,
        issuer=issuer,
        now=now,
        scope_kind="project",
        scope_id=project_id,
    )
    org = None
    if policy.org is not None:
        org = verify_layer_snapshot(
            claims["inputs"]["org"],
            jwks,
            issuer=issuer,
            now=now,
            scope_kind="org",
            scope_id=policy.org.scope_id,
        )
    elif claims["inputs"]["org"] is not None:
        raise ValueError("Unexpected organization input")
    composed = EffectivePolicy(project_id=project_id, org=org, project=project)
    if composed != policy:
        raise ValueError("Signed inputs do not match composed policy")
    return composed
