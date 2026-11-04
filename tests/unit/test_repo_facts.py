"""リポジトリの事実の収集 (#303, #304, #620, #621, #622)."""

from __future__ import annotations

from pathlib import Path

from security_checker.context import facts
from security_checker.context.facts import collect_repo_facts


def write(root: Path, relative: str, body: str = "x\n") -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def test_a_repository_under_a_build_directory_still_has_facts(tmp_path):
    root = tmp_path / "build" / "repo"
    write(root, "app.py")
    assert collect_repo_facts(root).languages == ["Python"]


def test_target_exclude_is_respected(tmp_path):
    write(tmp_path, "app.py")
    write(tmp_path, "generated/main.go")
    assert collect_repo_facts(tmp_path, ["generated/**"]).languages == ["Python"]


def test_auth_layer_is_not_inferred_from_file_names(tmp_path):
    write(tmp_path, "AUTHORS")
    write(tmp_path, "docs/oauth.md")
    assert collect_repo_facts(tmp_path).has_auth_layer is None


def test_auth_layer_is_inferred_from_dependencies(tmp_path):
    write(tmp_path, "requirements.txt", "flask\nflask-login==0.6\n")
    assert collect_repo_facts(tmp_path).has_auth_layer is True


def test_truncation_is_deterministic_and_recorded(tmp_path, monkeypatch):
    monkeypatch.setattr(facts, "MAX_FILES", 2)
    for name in ("c.go", "a.py", "b.py"):
        write(tmp_path, name)
    result = collect_repo_facts(tmp_path)
    assert result.truncated
    assert result.languages == ["Python"]  # 名前順に a.py, b.py まで
