import ast
import itertools
import subprocess
import sys
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from dinkster_token_verifier import policy as module
from dinkster_token_verifier.policy import (
    EffectivePolicy,
    Layer,
    Rule,
    RuleInput,
    Subject,
    canonical_json,
    evaluate,
    evaluate_layer,
)

DIGEST = "blake3:" + "a" * 64
MODEL = Subject(kind="model", identifier=DIGEST, license="flux-1-dev-non-commercial-license")
ORG_ID, PROJECT_ID = UUID(int=1), UUID(int=2)


def rule(kind="model_digest", matcher=DIGEST, effect="deny", number=1):
    return Rule(id=UUID(int=number), subject_kind=kind, matcher=matcher, effect=effect)


def layer(kind="org", effect="allow", rules=(), inherited=False):
    return Layer(
        scope_kind=kind,
        scope_id=ORG_ID if kind == "org" else PROJECT_ID,
        version=1,
        default_model_effect=effect,
        default_pack_effect=effect,
        default_remote_node_effect=effect,
        rules=rules,
        inherited=inherited,
    )


@pytest.mark.parametrize(
    "org_effect,project_effect", itertools.product(["allow", "deny"], repeat=2)
)
@pytest.mark.parametrize(
    "subject",
    [
        MODEL,
        Subject(kind="node_pack", identifier="example-pack", version="1.0"),
        Subject(kind="remote_node", identifier="provider/image"),
    ],
)
def test_defaults_at_both_layers(org_effect, project_effect, subject):
    policy = EffectivePolicy(
        project_id=PROJECT_ID,
        org=layer(effect=org_effect),
        project=layer("project", project_effect),
    )
    decision = evaluate(policy, subject)
    assert decision.effect == ("allow" if org_effect == project_effect == "allow" else "deny")
    assert decision.layer == ("org" if org_effect == "deny" else "project")
    assert decision.rule is None


def test_specificity_and_deterministic_equal_specificity_denial():
    license_deny = rule("model_license", MODEL.license, number=1)
    digest_allow = rule(effect="allow", number=2)
    digest_deny = rule(number=3)
    second_deny = rule(number=4)
    for scope in ("org", "project"):
        assert evaluate_layer(layer(scope, rules=(license_deny,)), MODEL).rule == license_deny
        assert (
            evaluate_layer(layer(scope, rules=(license_deny, digest_allow)), MODEL).rule
            == digest_allow
        )
        for rules in itertools.permutations((license_deny, digest_allow, digest_deny, second_deny)):
            result = evaluate_layer(layer(scope, rules=rules), MODEL)
            assert result.effect == "deny" and result.rule == digest_deny


def test_project_only_narrows_and_missing_project_inherits():
    allow, deny = rule(effect="allow"), rule(effect="deny")
    for org_rule, project_rule, expected_layer in [(allow, deny, "project"), (deny, allow, "org")]:
        policy = EffectivePolicy(
            project_id=PROJECT_ID,
            org=layer(rules=(org_rule,)),
            project=layer("project", rules=(project_rule,)),
        )
        result = evaluate(policy, MODEL)
        assert result.effect == "deny" and result.layer == expected_layer
    for effect in ("allow", "deny"):
        org = layer(rules=(rule(effect=effect),))
        policy = EffectivePolicy(
            project_id=PROJECT_ID,
            org=org,
            project=layer("project", inherited=True),
        )
        assert evaluate(policy, MODEL) == evaluate_layer(org, MODEL)
        personal = EffectivePolicy(
            project_id=PROJECT_ID, org=None, project=layer("project", effect)
        )
        assert evaluate(personal, MODEL).effect == effect


@pytest.mark.parametrize(
    "version,expected",
    [
        ("0.9", "allow"),
        ("1.0", "deny"),
        ("1.5", "deny"),
        ("1.5rc1", "deny"),
        ("2.0", "allow"),
    ],
)
def test_pack_version_ranges(version, expected):
    pack = rule("node_pack", "example-pack@>=1,<2")
    assert pack.matcher == "example-pack@<2,>=1"
    result = evaluate_layer(
        layer(rules=(pack,)),
        Subject(
            kind="node_pack",
            identifier="example-pack",
            version=version,
        ),
    )
    assert result.effect == expected
    assert (
        evaluate_layer(
            layer(rules=(pack,)),
            Subject(
                kind="node_pack",
                identifier="other-pack",
                version="1.5",
            ),
        ).effect
        == "allow"
    )


def test_pack_wildcards_unversioned_and_remote_exact():
    pack = rule("node_pack", "example-pack@==1.*,!=1.5")
    for version, expected in [("1.4", "deny"), ("1.5", "allow"), ("2.0", "allow")]:
        assert (
            evaluate_layer(
                layer(rules=(pack,)),
                Subject(
                    kind="node_pack",
                    identifier="example-pack",
                    version=version,
                ),
            ).effect
            == expected
        )
    assert (
        evaluate_layer(
            layer(rules=(rule("node_pack", "example-pack"),)),
            Subject(
                kind="node_pack",
                identifier="example-pack",
                version="999.0rc1",
            ),
        ).effect
        == "deny"
    )
    remote = rule("remote_node", "provider/image")
    for identifier, expected in [("provider/image", "deny"), ("provider/image-v2", "allow")]:
        assert (
            evaluate_layer(
                layer(rules=(remote,)),
                Subject(
                    kind="remote_node",
                    identifier=identifier,
                ),
            ).effect
            == expected
        )


@pytest.mark.parametrize(
    "kind,matcher",
    [
        ("model_digest", "blake3:abc"),
        ("model_digest", "sha256:" + "a" * 64),
        ("model_digest", "blake3:" + "A" * 64),
        ("model_license", ""),
        ("model_license", "MIT OR Apache-2.0"),
        ("remote_node", "two words"),
        ("node_pack", "Example_Pack"),
        ("node_pack", "example-pack@"),
        ("node_pack", "example-pack@latest"),
        ("node_pack", "a" * 65),
    ],
)
def test_invalid_matchers(kind, matcher):
    with pytest.raises(ValueError):
        RuleInput(subject_kind=kind, matcher=matcher, effect="allow")


def test_invalid_subjects_and_inherited_layers():
    for changes in [
        {"version": None},
        {"version": "latest"},
        {"version": "1.0+private"},
        {"identifier": "example-pack@>=1"},
        {"license": "MIT"},
    ]:
        with pytest.raises(ValueError):
            Subject.model_validate(
                {
                    "kind": "node_pack",
                    "identifier": "example-pack",
                    "version": "1.0",
                    **changes,
                }
            )
    with pytest.raises(ValueError):
        layer("project", "deny", inherited=True)
    with pytest.raises(ValueError):
        layer(rules=(rule(), rule()))
    with pytest.raises(ValueError):
        EffectivePolicy(project_id=uuid4(), org=None, project=layer("project"))


def test_canonical_bytes_ignore_rule_insertion_order():
    rules = (rule(number=1), rule("model_license", "MIT", number=2), rule(number=3))
    expected = canonical_json(layer(rules=rules))
    for permutation in itertools.permutations(rules):
        assert canonical_json(layer(rules=permutation)) == expected


def test_evaluation_imports_only_pure_dependencies():
    tree = ast.parse(Path(module.__file__).read_text())
    allowed = {"json", "re", "dataclasses", "typing", "uuid", "packaging", "pydantic"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name.split(".")[0] in allowed for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.module.split(".")[0] in allowed
    subprocess.run(
        [
            sys.executable,
            "-c",
            """
import sys
from dinkster_token_verifier.policy import Subject
from dinkster_token_verifier.policy_snapshots import verify_effective_snapshot
forbidden = {'dinkster_identity', 'sqlalchemy', 'asyncpg', 'httpx', 'httpcore', 'fastapi'}
for name in sys.modules:
    assert name.split('.')[0] not in forbidden
""",
        ],
        check=True,
    )
