from __future__ import annotations

import json

from dataclasses import dataclass
from pathlib import Path

from app.input_security import (
    detect_prompt_injection,
)


# -------------------------------------------------
# PROJECT PATHS
# -------------------------------------------------


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parent
    .parent
)

EVAL_CORPUS_PATH = (
    PROJECT_ROOT
    / "evals"
    / "adversarial_cases.json"
)


# -------------------------------------------------
# EVALUATION RESULT
# -------------------------------------------------


@dataclass(frozen=True)
class SecurityEvaluationResult:

    total_cases: int
    adversarial_cases: int
    benign_cases: int

    passed_cases: int
    failed_cases: int

    false_negatives: int
    false_positives: int
    category_mismatches: int

    passed: bool


# -------------------------------------------------
# CORPUS LOADING
# -------------------------------------------------


def load_security_evaluation_cases(
    path: Path = EVAL_CORPUS_PATH,
) -> list[dict]:

    raw_data = path.read_text(
        encoding="utf-8"
    )

    cases = json.loads(
        raw_data
    )

    if not isinstance(
        cases,
        list
    ):

        raise ValueError(
            "Security evaluation corpus "
            "must contain a JSON list."
        )

    return cases


# -------------------------------------------------
# SECURITY EVALUATION
# -------------------------------------------------


def run_security_evaluation(
    path: Path = EVAL_CORPUS_PATH,
) -> SecurityEvaluationResult:

    cases = (
        load_security_evaluation_cases(
            path
        )
    )

    total_cases = len(
        cases
    )

    adversarial_cases = 0
    benign_cases = 0

    passed_cases = 0
    failed_cases = 0

    false_negatives = 0
    false_positives = 0
    category_mismatches = 0

    for case in cases:

        payload = case[
            "payload"
        ]

        expected_detection = case[
            "expected_detection"
        ]

        expected_category = case[
            "category"
        ]

        if not isinstance(
            payload,
            str
        ):

            raise ValueError(
                "Security evaluation payload "
                "must be a string."
            )

        if not isinstance(
            expected_detection,
            bool
        ):

            raise ValueError(
                "expected_detection must "
                "be a boolean."
            )

        matches = (
            detect_prompt_injection(
                payload
            )
        )

        detected = bool(
            matches
        )

        if expected_detection:

            adversarial_cases += 1

        else:

            benign_cases += 1

        case_passed = False

        if expected_detection:

            if not detected:

                false_negatives += 1

            elif (
                expected_category
                not in matches
            ):

                category_mismatches += 1

            else:

                case_passed = True

        else:

            if detected:

                false_positives += 1

            else:

                case_passed = True

        if case_passed:

            passed_cases += 1

        else:

            failed_cases += 1

    passed = (
        failed_cases == 0
    )

    return SecurityEvaluationResult(
        total_cases=
            total_cases,

        adversarial_cases=
            adversarial_cases,

        benign_cases=
            benign_cases,

        passed_cases=
            passed_cases,

        failed_cases=
            failed_cases,

        false_negatives=
            false_negatives,

        false_positives=
            false_positives,

        category_mismatches=
            category_mismatches,

        passed=
            passed,
    )
