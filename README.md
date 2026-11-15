# dinkster-token-verifier

`dinkster-token-verifier` verifies Dinkster access tokens and signed policy
snapshots without calling the identity service for each request. It contains
verification and policy code only. It does not sign or mint tokens, store
accounts, access a database, or run a service.

## Install

Consumers pin `dinkster-token-verifier==0.1.2` in package metadata and record
the resolved PyPI wheel hashes in their lockfile. Before its first PyPI
publication, build a local wheel with `python -m build`.

## Releases

Stable releases use the matching `vX.Y.Z` tag and build a wheel and sdist.
Main pushes publish a wheel-only development release using the next patch
and the total reachable commit count, such as `0.1.3.dev42`. Other branches
and pull requests build development wheels without publishing. Both paths
use `.github/workflows/release.yml` and PyPI trusted publishing.

Release wheels record the exact source commit in package metadata and
`dinkster_token_verifier/_release.json`. Main publication records the same
version and commit in an immutable annotated `main-VERSION` tag. Stable tags
are annotated by the authorized publisher at the validated landed commit.
Consumers update their exact requirement and lock together after publication.

The repository owner must register the PyPI project `dinkster-token-verifier`
with a trusted publisher for owner `Kosinkadink`, repository
`dinkster-token-verifier`, workflow `release.yml`, environment `pypi`.
The GitHub environment must permit Main and version tags under the owner's
publication policy. No stored PyPI API token is used.

## Access token contract

`TokenVerifier` accepts a compact JWS with three base64url segments and an
Ed25519 protected header. `typ` may be omitted; when present it must be `JWT`:

```json
{"alg":"Ed25519","kid":"<key id>","typ":"JWT"}
```

The signed payload must contain these claims:

- `iss` and `aud`: exactly the configured issuer and audience.
- `sub`: `u_<uuid>` for a human or `k_<uuid>` for an API-key agent.
- `kind`: `human` or `agent`, consistent with `sub`.
- `org`: a canonical organization UUID or `null`.
- `acct`: the canonical account UUID.
- `key`: the canonical API key UUID for an agent, otherwise `null`.
- `key_scopes`: a nonempty, unique subset of the supported API key scopes for
  an agent, otherwise `null`.
- `grants`: a map from `org:<uuid>` or `project:<uuid>` to capability strings.
- `iat` and `exp`: integer Unix timestamps no more than 10 minutes apart.
- `jti`: a canonical UUID.

The verifier allows 30 seconds of clock skew and returns `None` for an invalid,
expired, malformed, unsupported, or unverifiable token. It returns an immutable
`VerifiedPrincipal` after all signature, claim, scope, and context checks pass.

```python
from dinkster_token_verifier import TokenVerifier

verifier = TokenVerifier(
    jwks_url="https://identity.example/.well-known/jwks.json",
    issuer="https://identity.example",
    audience="dinkster-session",
)
principal = await verifier.verify(access_token)
```

## JWKS discovery and rotation contract

The caller supplies the HTTPS JWKS URL advertised by its trusted identity
service. Dinkster identity publishes it at `/.well-known/jwks.json`. The
response must be a JSON object whose `keys` array contains one or more public
OKP Ed25519 signing keys. Every key must have a unique nonempty `kid`,
`kty: "OKP"`, `crv: "Ed25519"`, `alg: "Ed25519"`, optional `use: "sig"`, and
no private `d` value.

Keys are cached for at most 300 seconds by default. A smaller HTTP
`Cache-Control: max-age=<seconds>` shortens that lifetime. An unknown `kid`
causes one refresh so newly rotated keys become usable before the cache
expires; repeated unknown key IDs are throttled for 5 seconds. A failed
refresh retains a previously cached matching key and backs off another fetch
for 5 seconds. Identity services must therefore publish retired public keys
until every access token signed by them has expired.

## Signed policy snapshots

`dinkster_token_verifier.policy_snapshots` verifies Ed25519 JWT policy
snapshots against caller-supplied trusted JWKS. Snapshots use type
`dinkster-policy+jwt`, format 1, an exact 10-minute lifetime, and signed inputs
whose recomposition must equal the signed effective policy. The pure policy
models and narrowing-only evaluator live in `dinkster_token_verifier.policy`.
