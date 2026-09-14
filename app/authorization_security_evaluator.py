import json
import os

from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from pydantic import ValidationError

from app.auth import (
    Principal,
    authenticate_token,
    require_approver,
)

from app.tools.authorization import (
    require_tool_permission,
)


# -------------------------------------------------
# PROJECT PATHS
# -------------------------------------------------


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)


AUTHORIZATION_SECURITY_CORPUS_PATH = (
    PROJECT_ROOT
    / "evals"
    / "authorization_security_cases.json"
)


# -------------------------------------------------
# SYNTHETIC EVALUATION TOKENS
# -------------------------------------------------


ANALYST_TOKEN = (
    "authorization-eval-analyst-token"
)

APPROVER_TOKEN = (
    "authorization-eval-approver-token"
)

INVALID_TOKEN = (
    "authorization-eval-invalid-token"
)


# -------------------------------------------------
# CASE RESULT
# -------------------------------------------------


@dataclass(frozen=True)
class AuthorizationCaseResult:

    case_id: str

    expected_allowed: bool
    observed_allowed: bool

    expected_status: int | None
    observed_status: int | None

    expected_role: str | None
    observed_role: str | None

    expected_exception: str | None
    observed_exception: str | None

    passed: bool


# -------------------------------------------------
# AGGREGATE RESULT
# -------------------------------------------------


@dataclass(frozen=True)
class AuthorizationSecurityEvaluationResult:

    total_cases: int

    allowed_cases: int
    blocked_cases: int

    passed_cases: int
    failed_cases: int

    unexpected_allows: int
    unexpected_blocks: int

    status_mismatches: int
    role_mismatches: int
    exception_mismatches: int

    passed: bool


# -------------------------------------------------
# LOAD CORPUS
# -------------------------------------------------


def load_authorization_security_cases(
    path: Path =
        AUTHORIZATION_SECURITY_CORPUS_PATH,
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
            "Authorization security corpus "
            "must contain a JSON list."
        )

    return cases


# -------------------------------------------------
# EVALUATE ONE CASE
# -------------------------------------------------


def evaluate_authorization_case(
    case: dict,
) -> AuthorizationCaseResult:

    operation = case[
        "operation"
    ]

    case_input = case[
        "input"
    ]

    expected = case[
        "expected"
    ]

    valid_operations = {
        "authenticate",
        "require_approver",
        "tool_permission",
        "construct_principal",
    }

    if operation not in valid_operations:

        raise ValueError(
            "Unsupported authorization "
            "evaluation operation."
        )

    expected_allowed = expected[
        "allowed"
    ]

    expected_status = expected[
        "status_code"
    ]

    expected_role = expected[
        "resolved_role"
    ]

    expected_exception = expected[
        "exception"
    ]

    observed_allowed = False
    observed_status = None
    observed_role = None
    observed_exception = None

    configured_tokens = {
        "VM_AI_ANALYST_TOKEN":
            ANALYST_TOKEN,

        "VM_AI_APPROVER_TOKEN":
            APPROVER_TOKEN,
    }

    try:

        with patch.dict(
            os.environ,
            configured_tokens,
            clear=False,
        ):

            # -------------------------------------------------
            # AUTHENTICATION
            # -------------------------------------------------

            if operation == "authenticate":

                token_kind = case_input[
                    "token_kind"
                ]

                token = {
                    "analyst":
                        ANALYST_TOKEN,

                    "approver":
                        APPROVER_TOKEN,

                    "invalid":
                        INVALID_TOKEN,
                }[
                    token_kind
                ]

                principal = authenticate_token(
                    token
                )

                observed_role = (
                    principal.role
                )

            # -------------------------------------------------
            # APPROVER ROLE GATE
            # -------------------------------------------------

            elif operation == "require_approver":

                principal = Principal(
                    username=(
                        "authorization-eval-user"
                    ),
                    role=case_input[
                        "role"
                    ],
                )

                resolved = require_approver(
                    principal
                )

                observed_role = (
                    resolved.role
                )

            # -------------------------------------------------
            # TOOL PERMISSION
            # -------------------------------------------------

            elif operation == "tool_permission":

                principal = Principal(
                    username=(
                        "authorization-eval-user"
                    ),
                    role=case_input[
                        "role"
                    ],
                )

                require_tool_permission(
                    principal=principal,
                    tool_name=case_input[
                        "tool_name"
                    ],
                )

                observed_role = (
                    principal.role
                )

            # -------------------------------------------------
            # ROLE MODEL VALIDATION
            # -------------------------------------------------

            elif operation == "construct_principal":

                principal = Principal(
                    username=(
                        "authorization-eval-user"
                    ),
                    role=case_input[
                        "role"
                    ],
                )

                observed_role = (
                    principal.role
                )

            observed_allowed = True

    except HTTPException as error:

        observed_exception = (
            type(error).__name__
        )

        observed_status = (
            error.status_code
        )

    except ValidationError as error:

        observed_exception = (
            type(error).__name__
        )

    # -------------------------------------------------
    # COMPARE EXPECTED / OBSERVED
    # -------------------------------------------------

    if expected_allowed:

        passed = (
            observed_allowed
            and observed_exception is None
            and (
                expected_role is None
                or observed_role
                == expected_role
            )
        )

    else:

        passed = (
            not observed_allowed
            and (
                expected_exception is None
                or observed_exception
                == expected_exception
            )
            and (
                expected_status is None
                or observed_status
                == expected_status
            )
        )

    return AuthorizationCaseResult(
        case_id=
            case["id"],

        expected_allowed=
            expected_allowed,

        observed_allowed=
            observed_allowed,

        expected_status=
            expected_status,

        observed_status=
            observed_status,

        expected_role=
            expected_role,

        observed_role=
            observed_role,

        expected_exception=
            expected_exception,

        observed_exception=
            observed_exception,

        passed=
            passed,
    )


# -------------------------------------------------
# RUN CORPUS
# -------------------------------------------------


def run_authorization_security_evaluation(
    path: Path =
        AUTHORIZATION_SECURITY_CORPUS_PATH,
) -> AuthorizationSecurityEvaluationResult:

    cases = (
        load_authorization_security_cases(
            path
        )
    )

    results = [
        evaluate_authorization_case(
            case
        )
        for case in cases
    ]

    allowed_cases = sum(
        1
        for result in results
        if result.expected_allowed
    )

    blocked_cases = (
        len(results)
        - allowed_cases
    )

    passed_cases = sum(
        1
        for result in results
        if result.passed
    )

    failed_cases = (
        len(results)
        - passed_cases
    )

    unexpected_allows = sum(
        1
        for result in results
        if (
            not result.expected_allowed
            and result.observed_allowed
        )
    )

    unexpected_blocks = sum(
        1
        for result in results
        if (
            result.expected_allowed
            and not result.observed_allowed
        )
    )

    status_mismatches = sum(
        1
        for result in results
        if (
            result.expected_status
            is not None
            and result.observed_status
            != result.expected_status
        )
    )

    role_mismatches = sum(
        1
        for result in results
        if (
            result.expected_role
            is not None
            and result.observed_role
            != result.expected_role
        )
    )

    exception_mismatches = sum(
        1
        for result in results
        if (
            result.expected_exception
            is not None
            and result.observed_exception
            != result.expected_exception
        )
    )

    return AuthorizationSecurityEvaluationResult(
        total_cases=
            len(results),

        allowed_cases=
            allowed_cases,

        blocked_cases=
            blocked_cases,

        passed_cases=
            passed_cases,

        failed_cases=
            failed_cases,

        unexpected_allows=
            unexpected_allows,

        unexpected_blocks=
            unexpected_blocks,

        status_mismatches=
            status_mismatches,

        role_mismatches=
            role_mismatches,

        exception_mismatches=
            exception_mismatches,

        passed=(
            failed_cases == 0
        ),
    )