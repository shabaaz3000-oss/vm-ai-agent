import json
from pathlib import Path

import pytest

from app.input_security import detect_prompt_injection


# -------------------------------------------------
# EVALUATION CORPUS
# -------------------------------------------------


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)

EVAL_CORPUS_PATH = (
    PROJECT_ROOT
    / "evals"
    / "adversarial_cases.json"
)


def load_adversarial_cases() -> list[dict]:

    return json.loads(
        EVAL_CORPUS_PATH.read_text(
            encoding="utf-8"
        )
    )


ADVERSARIAL_CASES = (
    load_adversarial_cases()
)


# -------------------------------------------------
# CORPUS INTEGRITY
# -------------------------------------------------


def test_adversarial_corpus_metadata_is_valid() -> None:

    required_fields = {
        "id",
        "name",
        "category",
        "field",
        "payload",
        "expected_detection",
    }

    assert ADVERSARIAL_CASES

    ids = []

    for case in ADVERSARIAL_CASES:

        assert (
            required_fields
            <= case.keys()
        )

        assert isinstance(
            case["id"],
            str
        )

        assert case["id"].strip()

        assert isinstance(
            case["name"],
            str
        )

        assert case["name"].strip()

        assert isinstance(
            case["field"],
            str
        )

        assert case["field"].strip()

        assert isinstance(
            case["payload"],
            str
        )

        assert case["payload"].strip()

        assert isinstance(
            case["expected_detection"],
            bool
        )

        if case["expected_detection"]:

            assert isinstance(
                case["category"],
                str
            )

            assert (
                case["category"]
                .strip()
            )

        else:

            assert (
                case["category"]
                is None
            )

        ids.append(
            case["id"]
        )

    assert (
        len(ids)
        == len(set(ids))
    )


# -------------------------------------------------
# PROMPT-INJECTION EVALUATION
# -------------------------------------------------


@pytest.mark.parametrize(
    "case",
    ADVERSARIAL_CASES,
    ids=[
        case["id"]
        for case in ADVERSARIAL_CASES
    ],
)
def test_prompt_injection_evaluation_corpus(
    case,
) -> None:

    matches = detect_prompt_injection(
        case["payload"]
    )

    detected = bool(
        matches
    )

    assert (
        detected
        is case["expected_detection"]
    ), (
        f"{case['id']} ({case['name']}) "
        f"detection mismatch: "
        f"expected "
        f"{case['expected_detection']}, "
        f"got {detected}; "
        f"matches={matches}"
    )

    if case["expected_detection"]:

        assert (
            case["category"]
            in matches
        ), (
            f"{case['id']} ({case['name']}) "
            f"was detected, but expected "
            f"category "
            f"{case['category']!r} "
            f"was not returned; "
            f"matches={matches}"
        )

    else:

        assert matches == [], (
            f"{case['id']} ({case['name']}) "
            f"is benign but produced "
            f"matches={matches}"
        )
