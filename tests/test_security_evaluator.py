import json
from pathlib import Path

import app.security_evaluator as security_evaluator


# -------------------------------------------------
# TEST CORPUS
# -------------------------------------------------


def write_corpus(
    tmp_path: Path,
    cases: list[dict],
) -> Path:

    path = (
        tmp_path
        / "security-eval.json"
    )

    path.write_text(
        json.dumps(
            cases
        ),
        encoding="utf-8",
    )

    return path


def make_case(
    *,
    expected_detection: bool,
    category: str | None,
) -> dict:

    return {
        "id": "TEST-001",
        "name": "Evaluator test case",
        "category": category,
        "field": "description",
        "payload": "Synthetic evaluation payload.",
        "expected_detection":
            expected_detection,
    }


# -------------------------------------------------
# FALSE NEGATIVE
# -------------------------------------------------


def test_security_evaluator_counts_false_negative(
    monkeypatch,
    tmp_path: Path,
) -> None:

    path = write_corpus(
        tmp_path,
        [
            make_case(
                expected_detection=True,
                category="risk_manipulation",
            )
        ],
    )

    monkeypatch.setattr(
        security_evaluator,
        "detect_prompt_injection",
        lambda payload: [],
    )

    result = (
        security_evaluator
        .run_security_evaluation(
            path
        )
    )

    assert result.total_cases == 1
    assert result.adversarial_cases == 1
    assert result.benign_cases == 0

    assert result.passed_cases == 0
    assert result.failed_cases == 1

    assert result.false_negatives == 1
    assert result.false_positives == 0
    assert result.category_mismatches == 0

    assert result.passed is False


# -------------------------------------------------
# FALSE POSITIVE
# -------------------------------------------------


def test_security_evaluator_counts_false_positive(
    monkeypatch,
    tmp_path: Path,
) -> None:

    path = write_corpus(
        tmp_path,
        [
            make_case(
                expected_detection=False,
                category=None,
            )
        ],
    )

    monkeypatch.setattr(
        security_evaluator,
        "detect_prompt_injection",
        lambda payload: [
            "instruction_override"
        ],
    )

    result = (
        security_evaluator
        .run_security_evaluation(
            path
        )
    )

    assert result.total_cases == 1
    assert result.adversarial_cases == 0
    assert result.benign_cases == 1

    assert result.passed_cases == 0
    assert result.failed_cases == 1

    assert result.false_negatives == 0
    assert result.false_positives == 1
    assert result.category_mismatches == 0

    assert result.passed is False


# -------------------------------------------------
# CATEGORY INTEGRITY
# -------------------------------------------------


def test_security_evaluator_rejects_wrong_detection_category(
    monkeypatch,
    tmp_path: Path,
) -> None:

    path = write_corpus(
        tmp_path,
        [
            make_case(
                expected_detection=True,
                category="risk_manipulation",
            )
        ],
    )

    monkeypatch.setattr(
        security_evaluator,
        "detect_prompt_injection",
        lambda payload: [
            "approval_bypass"
        ],
    )

    result = (
        security_evaluator
        .run_security_evaluation(
            path
        )
    )

    assert result.passed_cases == 0
    assert result.failed_cases == 1

    assert result.false_negatives == 0
    assert result.false_positives == 0
    assert result.category_mismatches == 1

    assert result.passed is False
