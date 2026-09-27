import json

from pathlib import Path

import pytest

from app.mcp_identity_security_evaluator import (
    load_mcp_identity_security_cases,
    run_mcp_identity_security_evaluation_async,
)


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)


CORPUS_PATH = (
    PROJECT_ROOT
    / "evals"
    / "mcp_identity_security_cases.json"
)


def test_mcp_identity_security_corpus_metadata():

    cases = json.loads(
        CORPUS_PATH.read_text(
            encoding="utf-8-sig"
        )
    )

    assert len(cases) == 8

    ids = [
        case["id"]
        for case in cases
    ]

    assert len(ids) == len(set(ids))

    required = {
        "id",
        "name",
        "category",
        "attack",
        "expected_behavior",
        "severity",
    }

    for case in cases:

        assert required <= case.keys()

        assert (
            case["expected_behavior"]
            in {
                "allow",
                "block",
                "protect_authority",
            }
        )

        assert (
            case["severity"]
            in {
                "low",
                "medium",
                "high",
                "critical",
            }
        )


def test_mcp_identity_security_loader():

    cases = (
        load_mcp_identity_security_cases()
    )

    assert len(cases) == 8


@pytest.mark.anyio
async def test_mcp_identity_security_evaluator_passes():

    result = (
        await
        run_mcp_identity_security_evaluation_async()
    )

    assert result.total_cases == 8

    assert result.allowed_cases == 1

    assert result.blocked_cases == 5

    assert (
        result.authority_protection_cases
        == 2
    )

    assert result.passed_cases == 8
    assert result.failed_cases == 0

    assert result.unexpected_allows == 0
    assert result.unexpected_blocks == 0

    assert result.passed is True
