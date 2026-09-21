from uuid import UUID

import pytest
from joserfc import jwt
from joserfc.jwk import OKPKey

from dinkster_token_verifier.policy import EffectivePolicy, Layer
from dinkster_token_verifier.policy_snapshots import (
    SNAPSHOT_TTL,
    SNAPSHOT_TYPE,
    verify_effective_snapshot,
    verify_snapshot,
)


def snapshot_token(
    key: OKPKey,
    kid: str,
    *,
    now: int,
    claims: dict[str, object],
) -> str:
    return jwt.encode(
        {"alg": "Ed25519", "kid": kid, "typ": SNAPSHOT_TYPE},
        {
            "iss": "https://identity.example",
            "iat": now,
            "exp": now + SNAPSHOT_TTL,
            "format": 1,
            **claims,
        },
        key,
        algorithms=["Ed25519"],
    )


def public_jwks(key: OKPKey, kid: str) -> dict[str, object]:
    return {
        "keys": [
            {
                **key.as_dict(private=False),
                "alg": "Ed25519",
                "kid": kid,
                "use": "sig",
            }
        ]
    }


def test_verifies_signed_inputs_before_returning_an_effective_policy() -> None:
    key = OKPKey.generate_key("Ed25519")
    kid = "policy-key"
    now = 1_800_000_000
    project_id = UUID(int=2)
    project = Layer(scope_kind="project", scope_id=project_id, version=4)
    project_token = snapshot_token(
        key,
        kid,
        now=now,
        claims={"kind": "layer", "policy": project.model_dump(mode="json")},
    )
    policy = EffectivePolicy(project_id=project_id, org=None, project=project)
    effective_token = snapshot_token(
        key,
        kid,
        now=now,
        claims={
            "kind": "effective",
            "policy": policy.model_dump(mode="json"),
            "inputs": {"org": None, "project": project_token},
        },
    )

    assert (
        verify_effective_snapshot(
            effective_token,
            public_jwks(key, kid),
            issuer="https://identity.example",
            now=now,
            project_id=project_id,
        )
        == policy
    )


def test_rejects_a_snapshot_with_the_wrong_lifetime() -> None:
    key = OKPKey.generate_key("Ed25519")
    kid = "policy-key"
    now = 1_800_000_000
    invalid = jwt.encode(
        {"alg": "Ed25519", "kid": kid, "typ": SNAPSHOT_TYPE},
        {
            "iss": "https://identity.example",
            "iat": now,
            "exp": now + SNAPSHOT_TTL + 1,
            "format": 1,
        },
        key,
        algorithms=["Ed25519"],
    )

    with pytest.raises(ValueError, match="lifetime"):
        verify_snapshot(
            invalid,
            public_jwks(key, kid),
            issuer="https://identity.example",
            now=now,
        )
