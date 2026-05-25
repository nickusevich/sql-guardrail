from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402,I001

from sqlguard.server import app  # noqa: E402


def test_missing_policy_env_fails_to_boot(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SQLGUARD_POLICY_PATH", raising=False)
    with (
        pytest.raises(RuntimeError, match="SQLGUARD_POLICY_PATH"),
        TestClient(app),
    ):
        pass


def test_nonexistent_policy_path_fails_to_boot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SQLGUARD_POLICY_PATH", str(tmp_path / "no-such-file.yml"))
    with pytest.raises(RuntimeError, match="does not exist"), TestClient(app):
        pass


def test_invalid_policy_yaml_fails_to_boot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    bad = tmp_path / "bad.yml"
    bad.write_text("tables:\n  - this is not a valid table policy\n")
    monkeypatch.setenv("SQLGUARD_POLICY_PATH", str(bad))
    # Pydantic surfaces malformed table entries as ValidationError; the
    # lifespan re-raises it on startup so the server never serves traffic.
    with pytest.raises(ValidationError), TestClient(app):
        pass
