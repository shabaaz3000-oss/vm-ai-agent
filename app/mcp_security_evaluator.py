import asyncio
import json

from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

from mcp import Client

from app.mcp_server import (
    LOCAL_MCP_PRINCIPAL,
    mcp,
)

from app.tools.dispatcher import (
    dispatch_llm_tool as real_dispatch_llm_tool,
)


# -------------------------------------------------
# PROJECT PATHS
# -------------------------------------------------


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)


MCP_SECURITY_CORPUS_PATH = (
    PROJECT_ROOT
    / "evals"
    / "mcp_security_cases.json"
)


# -------------------------------------------------
# CASE OBSERVATION
# -------------------------------------------------


@dataclass(frozen=True)
class MCPCaseObservation:

    allowed: bool
    dispatcher_called: bool
    principal_unchanged: bool | None


# -------------------------------------------------
# EVALUATION RESULT
# -------------------------------------------------


@dataclass(frozen=True)
class MCPSecurityEvaluationResult:

    total_cases: int

    allowed_cases: int
    blocked_cases: int
    authority_protection_cases: int

    passed_cases: int
    failed_cases: int

    unexpected_allows: int
    unexpected_blocks: int

    authority_failures: int
    dispatcher_bypasses: int

    spoof_attempts_blocked: int
    spoof_attempts_ignored: int

    passed: bool


# -------------------------------------------------
# LOAD CORPUS
# -------------------------------------------------


def load_mcp_security_cases(
    path: Path = MCP_SECURITY_CORPUS_PATH,
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
            "MCP security evaluation corpus "
            "must contain a JSON list."
        )

    return cases


# -------------------------------------------------
# PRINCIPAL VALIDATION
# -------------------------------------------------


def principal_matches_server_identity(
    context,
) -> bool:

    if context is None:
        return False

    principal = context.principal

    return (
        principal.username
        == LOCAL_MCP_PRINCIPAL.username

        and principal.role
        == LOCAL_MCP_PRINCIPAL.role

        and principal.retrieval_access
        == LOCAL_MCP_PRINCIPAL.retrieval_access
    )


# -------------------------------------------------
# OBSERVE ONE MCP CASE
# -------------------------------------------------


async def observe_mcp_security_case(
    client: Client,
    case: dict,
) -> MCPCaseObservation:

    with patch(
        "app.mcp_server.dispatch_llm_tool",
        wraps=real_dispatch_llm_tool,
    ) as mocked_dispatch:

        result = await client.call_tool(
            case["tool_name"],
            case["arguments"],
        )

        dispatcher_called = (
            mocked_dispatch.call_count > 0
        )

        context = None

        if dispatcher_called:

            call = mocked_dispatch.call_args

            if (
                call is not None
                and "context" in call.kwargs
            ):

                context = call.kwargs[
                    "context"
                ]

            elif (
                call is not None
                and len(call.args) >= 2
            ):

                context = call.args[1]

        principal_unchanged = None

        if dispatcher_called:

            principal_unchanged = (
                principal_matches_server_identity(
                    context
                )
            )

        return MCPCaseObservation(
            allowed=(
                result.is_error is False
            ),
            dispatcher_called=
                dispatcher_called,
            principal_unchanged=
                principal_unchanged,
        )


# -------------------------------------------------
# ASYNC MCP SECURITY EVALUATION
# -------------------------------------------------


async def run_mcp_security_evaluation_async(
    path: Path = MCP_SECURITY_CORPUS_PATH,
) -> MCPSecurityEvaluationResult:

    cases = load_mcp_security_cases(
        path
    )

    allowed_cases = 0
    blocked_cases = 0
    authority_protection_cases = 0

    passed_cases = 0
    failed_cases = 0

    unexpected_allows = 0
    unexpected_blocks = 0

    authority_failures = 0
    dispatcher_bypasses = 0

    spoof_attempts_blocked = 0
    spoof_attempts_ignored = 0

    async with Client(
        mcp,
        raise_exceptions=True,
    ) as client:

        for case in cases:

            observation = (
                await observe_mcp_security_case(
                    client,
                    case,
                )
            )

            expected_behavior = case[
                "expected_behavior"
            ]

            case_passed = False

            # -------------------------------------------------
            # LEGITIMATE ALLOW
            # -------------------------------------------------

            if expected_behavior == "allow":

                allowed_cases += 1

                if not observation.allowed:

                    unexpected_blocks += 1

                elif not observation.dispatcher_called:

                    dispatcher_bypasses += 1

                elif (
                    observation.principal_unchanged
                    is not True
                ):

                    authority_failures += 1

                else:

                    case_passed = True

            # -------------------------------------------------
            # HARD BLOCK
            # -------------------------------------------------

            elif expected_behavior == "block":

                blocked_cases += 1

                if observation.allowed:

                    unexpected_allows += 1

                elif observation.dispatcher_called:

                    dispatcher_bypasses += 1

                else:

                    case_passed = True

            # -------------------------------------------------
            # AUTHORITY PROTECTION
            # -------------------------------------------------

            elif (
                expected_behavior
                == "protect_authority"
            ):

                authority_protection_cases += 1

                # Best case:
                # MCP rejects the spoof before dispatcher.
                if (
                    not observation.allowed
                    and not observation.dispatcher_called
                ):

                    spoof_attempts_blocked += 1
                    case_passed = True

                # Also secure:
                # extra client fields are tolerated,
                # but server-controlled identity remains
                # authoritative.
                elif (
                    observation.dispatcher_called
                    and observation.principal_unchanged
                    is True
                ):

                    spoof_attempts_ignored += 1
                    case_passed = True

                else:

                    authority_failures += 1

            else:

                raise ValueError(
                    "Unknown MCP expected behavior: "
                    f"{expected_behavior}"
                )

            # -------------------------------------------------
            # CASE RESULT
            # -------------------------------------------------

            if case_passed:

                passed_cases += 1

            else:

                failed_cases += 1

    return MCPSecurityEvaluationResult(
        total_cases=
            len(cases),

        allowed_cases=
            allowed_cases,

        blocked_cases=
            blocked_cases,

        authority_protection_cases=
            authority_protection_cases,

        passed_cases=
            passed_cases,

        failed_cases=
            failed_cases,

        unexpected_allows=
            unexpected_allows,

        unexpected_blocks=
            unexpected_blocks,

        authority_failures=
            authority_failures,

        dispatcher_bypasses=
            dispatcher_bypasses,

        spoof_attempts_blocked=
            spoof_attempts_blocked,

        spoof_attempts_ignored=
            spoof_attempts_ignored,

        passed=(
            failed_cases == 0
        ),
    )


# -------------------------------------------------
# SYNCHRONOUS ENTRY POINT
# -------------------------------------------------


def run_mcp_security_evaluation(
    path: Path = MCP_SECURITY_CORPUS_PATH,
) -> MCPSecurityEvaluationResult:

    return asyncio.run(
        run_mcp_security_evaluation_async(
            path
        )
    )