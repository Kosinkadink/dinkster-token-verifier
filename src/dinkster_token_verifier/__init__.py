"""Offline verification for Dinkster identity access tokens."""

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from dinkster_token_verifier.verifier import API_KEY_SCOPES, TokenVerifier, VerifiedPrincipal

__all__ = ["API_KEY_SCOPES", "TokenVerifier", "VerifiedPrincipal"]


def __getattr__(name: str) -> Any:
    # Pure policy consumers do not load the HTTP-backed token verifier.
    if name in __all__:
        from dinkster_token_verifier import verifier

        return getattr(verifier, name)
    raise AttributeError(name)
