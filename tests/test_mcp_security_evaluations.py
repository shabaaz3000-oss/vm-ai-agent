import json

from pathlib import Path

import pytest

from mcp import Client

from app.mcp_server import mcp

from app.mcp_security_evaluator import (
    observe_mcp_security_case,
    run_mcp_security_evaluation_async,
)


# -------------------------------------------------
# PATHS
# -------------------------------------------------


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)


CORPUS_PATH = (
    PROJECT_ROOT
    / "evals"
    / "mcp_security_cases.json"
)


# -------------------------------------------------
# LOAD CASES
# -------------------------------------------------


def load_cases() -> list[dict]:

    return json.loads(
        CORPUS_PATH.read_text(
            encoding="utf-8"
        )
    )


CASES = load_cases()


@pytest.fixture
def anyio_backend():

    return "asyncio"


# -------------------------------------------------
# CORPUS METADATA
# -------------------------------------------------


def test_mcp_security_corpus_metadata_is_valid():

    required_fields = {
        "id",
        "name",
        "category",
        "tool_name",
        "arguments",
        "expected_behavior",
        "severity",
    }

    valid_behaviors = {
        "allow",
        "block",
        "protect_authority",
    }

    assert CASES

    ids = []

    for case in CASES:

        assert (
            required_fields
            <= case.keys()
        )

        assert isinstance(
            case["id"],
            str,
        )

        assert case["id"].strip()

        assert isinstance(
            case["name"],
            str,
        )

        assert case["name"].strip()

        assert isinstance(
            case["category"],
            str,
        )

        assert case["category"].strip()

        assert isinstance(
            case["tool_name"],
            str,
        )

        assert case["tool_name"]

        assert isinstance(
            case["arguments"],
            dict,
        )

        assert (
            case["expected_behavior"]
            in valid_behaviors
        )

        assert case[
            "severity"
        ] in {
            "low",
            "medium",
            "high",
            "critical",
        }

        ids.append(
            case["id"]
        )

    assert (
        len(ids)
        == len(set(ids))
    )


# -------------------------------------------------
# CORPUS CASES
# -------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize(
    "case",
    CASES,
    ids=[
        case["id"]
        for case in CASES
    ],
)
async def test_mcp_security_corpus(
    case,
):

    async with Client(
        mcp,
        raise_exceptions=True,
    ) as client:

        observation = (
            await observe_mcp_security_case(
                client,
                case,
            )
        )

    expected_behavior = case[
        "expected_behavior"
    ]

    # -------------------------------------------------
    # LEGITIMATE READ
    # -------------------------------------------------

    if expected_behavior == "allow":

        assert observation.allowed is True
        assert observation.dispatcher_called is True

        assert (
            observation.principal_unchanged
            is True
        )

    # -------------------------------------------------
    # HIDDEN / UNKNOWN TOOL
    # -------------------------------------------------

    elif expected_behavior == "block":

        assert observation.allowed is False

        # A hard-blocked MCP tool should never
        # reach the internal dispatcher.
        assert (
            observation.dispatcher_called
            is False
        )

    # -------------------------------------------------
    # IDENTITY / AUTHORITY SPOOF
    # -------------------------------------------------

    elif (
        expected_behavior
        == "protect_authority"
    ):

        blocked_before_dispatch = (
            observation.allowed is False
            and observation.dispatcher_called
            is False
        )

        safely_ignored = (
            observation.dispatcher_called
            is True
            and observation.principal_unchanged
            is True
        )

        assert (
            blocked_before_dispatch
            or safely_ignored
        )


# -------------------------------------------------
# AGGREGATE EVALUATOR
# -------------------------------------------------


@pytest.mark.anyio
async def test_mcp_security_evaluator_passes():

    result = (
        await run_mcp_security_evaluation_async()
    )

    assert (
        result.total_cases
        == len(CASES)
    )

    assert result.allowed_cases == 3
    assert result.blocked_cases == 6

    assert (
        result.authority_protection_cases
        == 3
    )

    assert (
        result.passed_cases
        == len(CASES)
    )

    assert result.failed_cases == 0

    assert result.unexpected_allows == 0
    assert result.unexpected_blocks == 0

    assert result.authority_failures == 0
    assert result.dispatcher_bypasses == 0

    # An authority-spoofing attempt may safely
    # be rejected OR tolerated but ignored.
    assert (
        result.spoof_attempts_blocked
        + result.spoof_attempts_ignored
        == 3
    )

    assert result.passed is True