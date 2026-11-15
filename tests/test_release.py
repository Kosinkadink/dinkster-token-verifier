"""Release wheels retain public version and exact source identity."""

import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from packaging.version import Version

from scripts.prepare_release import prepare

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("tag", [None, "v0.1.2"])
def test_release_wheel_records_public_version_and_source(tmp_path: Path, tag: str | None) -> None:
    source = tmp_path / "source"
    subprocess.run(["git", "clone", "--shared", str(ROOT), str(source)], check=True)
    shutil.copyfile(ROOT / "pyproject.toml", source / "pyproject.toml")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    identity = prepare(source, tag)
    assert identity["sourceCommit"] == commit
    version = Version(identity["version"])
    assert version.local is None
    assert version.is_devrelease == (tag is None)
    if tag is not None:
        assert version == Version("0.1.2")
    arguments = ["--wheel"] if tag is None else []
    subprocess.run([sys.executable, "-m", "build", *arguments], cwd=source, check=True)
    assert len(list((source / "dist").glob("*.tar.gz"))) == (0 if tag is None else 1)
    [wheel] = (source / "dist").glob("*.whl")
    with zipfile.ZipFile(wheel) as archive:
        assert json.loads(archive.read("dinkster_token_verifier/_release.json")) == identity
        [metadata] = [name for name in archive.namelist() if name.endswith("/METADATA")]
        text = archive.read(metadata).decode()
        assert f"Version: {version}\n" in text
        assert (
            f"Project-URL: Source, https://github.com/Kosinkadink/dinkster-token-verifier/tree/{commit}\n"
            in text
        )
    if tag is None:
        subprocess.run(["git", "restore", "--", "pyproject.toml"], cwd=source, check=True)
        subprocess.run(["git", "checkout", "HEAD~1"], cwd=source, check=True)
        shutil.copyfile(ROOT / "pyproject.toml", source / "pyproject.toml")
        earlier = prepare(source)
        assert Version(earlier["version"]) < version
        assert earlier["sourceCommit"] != commit
