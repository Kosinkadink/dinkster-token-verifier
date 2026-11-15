"""Prepare public stable or development versions and their source identity."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tomllib
from pathlib import Path


def prepare(root: Path, tag: str | None = None) -> dict[str, str]:
    project = root / "pyproject.toml"
    text = project.read_text(encoding="utf-8")
    stable = tomllib.loads(text)["project"]["version"]
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", stable) is None:
        raise ValueError("project version must be X.Y.Z")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if tag is not None:
        if tag != f"v{stable}":
            raise ValueError("stable release tag must match the project version")
        version = stable
    else:
        major, minor, patch = map(int, stable.split("."))
        count = subprocess.check_output(
            ["git", "rev-list", "--count", "HEAD"], cwd=root, text=True
        ).strip()
        version = f"{major}.{minor}.{patch + 1}.dev{count}"
    identity = {"version": version, "sourceCommit": commit}
    text = re.sub(r'(?m)^version = "[^"]+"$', f'version = "{version}"', text, count=1)
    text += (
        "\n[project.urls]\n"
        f'Source = "https://github.com/Kosinkadink/dinkster-token-verifier/tree/{commit}"\n'
    )
    project.write_text(text, encoding="utf-8")
    (root / "src/dinkster_token_verifier/_release.json").write_text(
        json.dumps(identity, sort_keys=True) + "\n", encoding="ascii"
    )
    return identity


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag")
    args = parser.parse_args()
    print(json.dumps(prepare(Path(__file__).resolve().parents[1], args.tag), sort_keys=True))
