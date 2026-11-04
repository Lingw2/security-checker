"""評価用データセットの読み込み (設計書 §26.1).

壊れたケースを黙って飛ばさないこと (P9) と、同梱データセットが実際に読めることを固定する。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from security_checker.errors import ConfigError
from security_checker.eval.dataset import load_dataset
from security_checker.models.enums import Category, Severity

BUNDLED = Path(__file__).resolve().parents[2] / "benchmarks" / "datasets" / "handmade-v1"

CASE = """
candidate:
  scanner: semgrep
  rule_id: r
  path: app.py
  start_line: 3
code: |
  print("hi")
ground_truth:
  vulnerable: true
  severity: high
  rationale: テスト用
"""


def write_case(root: Path, name: str, body: str) -> None:
    cases = root / "cases"
    cases.mkdir(parents=True, exist_ok=True)
    (cases / name).write_text(body, encoding="utf-8")


def test_loads_a_case_and_derives_the_id_from_the_filename(tmp_path):
    write_case(tmp_path, "0001.yaml", CASE)
    dataset = load_dataset(tmp_path)
    assert [case.id for case in dataset.cases] == ["0001"]
    assert dataset.positives == 1
    assert dataset.negatives == 0


def test_case_converts_to_the_same_candidate_type_used_at_runtime(tmp_path):
    write_case(tmp_path, "0001.yaml", CASE)
    candidate = load_dataset(tmp_path).cases[0].to_candidate()
    assert candidate.category is Category.SAST
    assert candidate.location is not None
    assert candidate.location.start_line == 3
    # end_line を省いたら start_line と同じにする (範囲が壊れないこと)
    assert candidate.location.end_line == 3


def test_missing_directory_is_a_config_error(tmp_path):
    with pytest.raises(ConfigError, match="評価ケース"):
        load_dataset(tmp_path)


def test_empty_directory_is_a_config_error(tmp_path):
    (tmp_path / "cases").mkdir()
    with pytest.raises(ConfigError):
        load_dataset(tmp_path)


def test_a_broken_case_is_not_skipped_silently(tmp_path):
    write_case(tmp_path, "0001.yaml", CASE)
    write_case(tmp_path, "0002.yaml", "candidate: {}\n")
    with pytest.raises(ConfigError, match="0002"):
        load_dataset(tmp_path)


def test_unknown_keys_are_rejected(tmp_path):
    """ラベルの綴り間違いが黙って無視されると、評価が静かに壊れる."""
    write_case(tmp_path, "0001.yaml", CASE + "\nvunerable: true\n")
    with pytest.raises(ConfigError):
        load_dataset(tmp_path)


def test_duplicate_ids_are_rejected(tmp_path):
    body = "id: same\n" + CASE
    write_case(tmp_path, "0001.yaml", body)
    write_case(tmp_path, "0002.yaml", body)
    with pytest.raises(ConfigError, match="重複"):
        load_dataset(tmp_path)


def test_the_bundled_dataset_loads():
    """同梱データセットが壊れていないこと."""
    dataset = load_dataset(BUNDLED)
    assert dataset.name == "handmade-v1"
    assert len(dataset.cases) >= 4
    # 実運用の分布は FP が支配的なので、陰性ケースを必ず含める (§26.2)
    assert dataset.negatives >= 1
    assert dataset.positives >= 1
    for case in dataset.cases:
        assert case.code.strip(), f"{case.id}: コードが空"
        assert case.ground_truth.rationale.strip(), f"{case.id}: 正解の根拠が書かれていない"
        if case.ground_truth.vulnerable:
            assert case.ground_truth.severity is not Severity.NONE


# --- ワークスペースの外に書き出させない (#624) ------------------------------------


@pytest.mark.parametrize(
    "path",
    ["../../../.bashrc", "src/../../x.py", "..\\..\\x.py", "/etc/passwd", "C:\\x.py", ""],
)
def test_a_case_path_that_escapes_the_workspace_is_rejected(tmp_path, path):
    write_case(tmp_path, "0001.yaml", CASE.replace("path: app.py", f"path: {path!r}"))
    with pytest.raises(ConfigError, match="不正"):
        load_dataset(tmp_path)


@pytest.mark.parametrize("case_id", ["../evil", "a/b", "..", "a\\b"])
def test_a_case_id_that_is_not_a_plain_name_is_rejected(tmp_path, case_id):
    write_case(tmp_path, "0001.yaml", f"id: {case_id!r}\n" + CASE)
    with pytest.raises(ConfigError, match="不正"):
        load_dataset(tmp_path)


def test_a_nested_relative_path_is_still_accepted(tmp_path):
    write_case(tmp_path, "0001.yaml", CASE.replace("path: app.py", "path: src/pkg/app.py"))
    assert load_dataset(tmp_path).cases[0].candidate.path == "src/pkg/app.py"


@pytest.mark.parametrize("rationale", [None, '""', '"   "'])
def test_rationale_is_required(tmp_path, rationale):
    """rationale は必須. 省略・空・空白だけを黙って読み込まない (#235)."""
    body = CASE.replace("  rationale: テスト用\n", "")
    if rationale is not None:
        body += f"  rationale: {rationale}\n"
    write_case(tmp_path, "0001.yaml", body)
    with pytest.raises(ConfigError, match="rationale"):
        load_dataset(tmp_path)
