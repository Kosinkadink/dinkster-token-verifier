"""Pure policy models, canonical serialization, and narrowing-only evaluation."""

import json
import re
from dataclasses import dataclass
from typing import Literal, Self
from uuid import UUID

from packaging.specifiers import SpecifierSet
from packaging.version import Version
from pydantic import BaseModel, ConfigDict, Field, model_validator

Effect = Literal["allow", "deny"]
ScopeKind = Literal["org", "project"]
SubjectKind = Literal["model_digest", "model_license", "node_pack", "remote_node"]
DIGEST_PATTERN = r"blake3:[0-9a-f]{64}"
PACK_PATTERN = r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*"


class PolicyModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Defaults(PolicyModel):
    default_model_effect: Effect = "allow"
    default_pack_effect: Effect = "allow"
    default_remote_node_effect: Effect = "allow"


class RuleInput(PolicyModel):
    subject_kind: SubjectKind
    matcher: str = Field(min_length=1, max_length=512)
    effect: Effect
    comment: str = Field(default="", max_length=2000)

    @model_validator(mode="after")
    def valid_matcher(self) -> Self:
        if self.subject_kind == "model_digest":
            if re.fullmatch(DIGEST_PATTERN, self.matcher) is None:
                raise ValueError("Expected a lowercase BLAKE3 digest")
        elif self.subject_kind == "node_pack":
            pack, separator, specifier = self.matcher.partition("@")
            if len(pack) > 64 or re.fullmatch(PACK_PATTERN, pack) is None:
                raise ValueError("Expected a canonical registry pack identifier")
            if separator:
                if not specifier.strip():
                    raise ValueError("Expected a PEP 440 specifier set after @")
                specifiers = SpecifierSet(specifier)
                for item in specifiers:
                    if item.operator == "===":
                        version = Version(item.version)
                        if str(version) != item.version or version.local is not None:
                            raise ValueError(
                                "Exact pack equality requires a public registry version"
                            )
                object.__setattr__(self, "matcher", f"{pack}@{specifiers}")
        elif re.fullmatch(r"[!-~]{1,255}", self.matcher) is None:
            raise ValueError("Expected a nonempty ASCII identifier without whitespace")
        return self


class Rule(RuleInput):
    id: UUID


class Layer(Defaults):
    scope_kind: ScopeKind
    scope_id: UUID
    version: int = Field(ge=0)
    inherited: bool = False
    rules: tuple[Rule, ...] = ()

    @model_validator(mode="after")
    def unique_rules(self) -> Self:
        if len({rule.id for rule in self.rules}) != len(self.rules):
            raise ValueError("Duplicate rule identifiers")
        if self.inherited and self.rules:
            raise ValueError("Inherited layers cannot contain rules")
        if (
            self.inherited
            and self.scope_kind == "project"
            and any(
                effect != "allow"
                for effect in (
                    self.default_model_effect,
                    self.default_pack_effect,
                    self.default_remote_node_effect,
                )
            )
        ):
            raise ValueError("Inherited project defaults must allow")
        return self


class EffectivePolicy(PolicyModel):
    project_id: UUID
    org: Layer | None
    project: Layer
    composition: Literal["all_layers_allow"] = "all_layers_allow"

    @model_validator(mode="after")
    def valid_scopes(self) -> Self:
        if self.project.scope_kind != "project" or self.project.scope_id != self.project_id:
            raise ValueError("Project layer does not match the effective policy")
        if self.org is not None and self.org.scope_kind != "org":
            raise ValueError("Expected an organization layer")
        return self


class Subject(PolicyModel):
    kind: Literal["model", "node_pack", "remote_node"]
    identifier: str
    license: str | None = None
    version: str | None = None

    @model_validator(mode="after")
    def valid_subject(self) -> Self:
        kind: SubjectKind = "model_digest" if self.kind == "model" else self.kind
        RuleInput(subject_kind=kind, matcher=self.identifier, effect="allow")
        if self.kind == "node_pack":
            if "@" in self.identifier or self.version is None:
                raise ValueError("Pack subjects require an identifier and version")
            version = Version(self.version)
            if str(version) != self.version or version.local is not None:
                raise ValueError("Expected a normalized public PEP 440 version")
        elif self.version is not None:
            raise ValueError("Only pack subjects have versions")
        if self.license is not None:
            if self.kind != "model":
                raise ValueError("Only model subjects have licenses")
            RuleInput(subject_kind="model_license", matcher=self.license, effect="allow")
        return self


@dataclass(frozen=True)
class Decision:
    effect: Effect
    layer: ScopeKind
    scope_id: UUID
    rule: Rule | None


def canonical_json(value: PolicyModel) -> bytes:
    """Sort rules by stable identifiers, independent of storage/insertion order."""

    def ordered(item: object) -> object:
        if isinstance(item, dict):
            return {
                key: ordered(sorted(child, key=lambda rule: rule["id"]))
                if key == "rules" and isinstance(child, list)
                else ordered(child)
                for key, child in item.items()
            }
        if isinstance(item, list):
            return [ordered(child) for child in item]
        return item

    return json.dumps(
        ordered(value.model_dump(mode="json")),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def evaluate_layer(layer: Layer, subject: Subject) -> Decision:
    matches: list[tuple[int, Rule]] = []
    for rule in layer.rules:
        specificity = 0
        if subject.kind == "model":
            if rule.subject_kind == "model_digest" and rule.matcher == subject.identifier:
                specificity = 2
            elif rule.subject_kind == "model_license" and rule.matcher == subject.license:
                specificity = 1
        elif subject.kind == "node_pack" and rule.subject_kind == "node_pack":
            pack, separator, specifier = rule.matcher.partition("@")
            assert subject.version is not None
            if pack == subject.identifier and (
                not separator or SpecifierSet(specifier).contains(subject.version, prereleases=True)
            ):
                specificity = 2
        elif subject.kind == "remote_node" and rule.subject_kind == "remote_node":
            if rule.matcher == subject.identifier:
                specificity = 2
        if specificity:
            matches.append((specificity, rule))
    if matches:
        _, rule = min(
            matches, key=lambda item: (-item[0], item[1].effect != "deny", str(item[1].id))
        )
        return Decision(rule.effect, layer.scope_kind, layer.scope_id, rule)
    effect = {
        "model": layer.default_model_effect,
        "node_pack": layer.default_pack_effect,
        "remote_node": layer.default_remote_node_effect,
    }[subject.kind]
    return Decision(effect, layer.scope_kind, layer.scope_id, None)


def evaluate(policy: EffectivePolicy, subject: Subject) -> Decision:
    """An org denial is final; otherwise the project decides, including its default."""
    if policy.org is not None:
        org = evaluate_layer(policy.org, subject)
        if org.effect == "deny" or policy.project.inherited:
            return org
    return evaluate_layer(policy.project, subject)
