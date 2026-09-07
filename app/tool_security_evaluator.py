import json
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

from app.auth import Principal
from app.tools.dispatcher import (
    ToolExecutionContext,
    dispatch_llm_tool,
)


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)

TOOL_SECURITY_CORPUS_PATH = (
    PROJECT_ROOT
    / "evals"
    / "tool_security_cases.json"
)


@dataclass(frozen=True)
class ToolSecurityEvaluationResult:
    total_cases: int
    allowed_cases: int
    blocked_cases: int
    passed_cases: int
    failed_cases: int
    unexpected_allows: int
    unexpected_blocks: int
    error_mismatches: int
    passed: bool


def load_tool_security_cases(
    path: Path = TOOL_SECURITY_CORPUS_PATH,
) -> list[dict]:

    raw_data = path.read_text(
        encoding="utf-8"
    )

    cases = json.loads(
        raw_data
    )

    if not isinstance(
        cases,
        list,
    ):
        raise ValueError(
            "Tool security evaluation corpus "
            "must contain a JSON list."
        )

    return cases


def run_tool_security_evaluation(
    path: Path = TOOL_SECURITY_CORPUS_PATH,
) -> ToolSecurityEvaluationResult:

    cases = load_tool_security_cases(
        path
    )

    allowed_cases = 0
    blocked_cases = 0

    passed_cases = 0
    failed_cases = 0

    unexpected_allows = 0
    unexpected_blocks = 0
    error_mismatches = 0

    for case in cases:

        principal = Principal(
            username=(
                "tool-security-eval"
            ),
            role=case["principal_role"],
        )

        if case[
            "provide_search_context"
        ]:
            context = ToolExecutionContext(
                principal=principal,
                finding=object(),
                asset=object(),
                risk=object(),
                retriever=object(),
            )

        else:
            context = ToolExecutionContext(
                principal=principal,
            )

        expected_allowed = case[
            "expected_allowed"
        ]

        expected_error = case[
            "expected_error"
        ]

        observed_allowed = False
        observed_error = None

        sentinel = {
            "status": "evaluation-success"
        }

        try:

            with patch(
                "app.tools.dispatcher.get_finding",
                return_value=sentinel,
            ), patch(
                "app.tools.dispatcher.get_asset_details",
                return_value=sentinel,
            ), patch(
                "app.tools.dispatcher.get_threat_intel",
                return_value=sentinel,
            ), patch(
                "app.tools.dispatcher.search_knowledge",
                return_value=sentinel,
            ), patch(
                "app.tools.dispatcher.log_event",
            ):

                result = dispatch_llm_tool(
                    tool_name=
                        case["tool_name"],
                    context=
                        context,
                )

                observed_allowed = (
                    result
                    == sentinel
                )

        except Exception as error:

            observed_error = (
                type(error).__name__
            )

        case_passed = False

        if expected_allowed:

            allowed_cases += 1

            if observed_allowed:
                case_passed = True
            else:
                unexpected_blocks += 1

        else:

            blocked_cases += 1

            if observed_allowed:
                unexpected_allows += 1

            elif (
                observed_error
                != expected_error
            ):
                error_mismatches += 1

            else:
                case_passed = True

        if case_passed:
            passed_cases += 1
        else:
            failed_cases += 1

    return ToolSecurityEvaluationResult(
        total_cases=len(cases),
        allowed_cases=allowed_cases,
        blocked_cases=blocked_cases,
        passed_cases=passed_cases,
        failed_cases=failed_cases,
        unexpected_allows=unexpected_allows,
        unexpected_blocks=unexpected_blocks,
        error_mismatches=error_mismatches,
        passed=(failed_cases == 0),
    )