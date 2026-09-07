import json
from pathlib import Path

import pytest

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

CORPUS_PATH = (
    PROJECT_ROOT
    / "evals"
    / "tool_security_cases.json"
)


def load_cases() -> list[dict]:

    return json.loads(
        CORPUS_PATH.read_text(
            encoding="utf-8"
        )
    )


CASES = load_cases()


def test_tool_security_corpus_metadata_is_valid():

    required_fields = {
        "id",
        "name",
        "category",
        "principal_role",
        "tool_name",
        "provide_search_context",
        "expected_allowed",
        "expected_error",
        "severity",
    }

    assert CASES

    ids = []

    for case in CASES:

        assert required_fields <= case.keys()

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

        assert case[
            "principal_role"
        ] in {
            "ANALYST",
            "APPROVER",
        }

        assert isinstance(
            case["tool_name"],
            str,
        )

        assert case["tool_name"].strip()

        assert isinstance(
            case["provide_search_context"],
            bool,
        )

        assert isinstance(
            case["expected_allowed"],
            bool,
        )

        if case["expected_allowed"]:
            assert (
                case["expected_error"]
                is None
            )
        else:
            assert isinstance(
                case["expected_error"],
                str,
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

    assert len(ids) == len(set(ids))


@pytest.mark.parametrize(
    "case",
    CASES,
    ids=[
        case["id"]
        for case in CASES
    ],
)
def test_tool_security_corpus(
    case,
    monkeypatch,
):

    sentinel = {
        "status": "evaluation-success"
    }

    monkeypatch.setattr(
        "app.tools.dispatcher.get_finding",
        lambda **kwargs: sentinel,
    )

    monkeypatch.setattr(
        "app.tools.dispatcher.get_asset_details",
        lambda **kwargs: sentinel,
    )

    monkeypatch.setattr(
        "app.tools.dispatcher.get_threat_intel",
        lambda **kwargs: sentinel,
    )

    monkeypatch.setattr(
        "app.tools.dispatcher.search_knowledge",
        lambda **kwargs: sentinel,
    )

    monkeypatch.setattr(
        "app.tools.dispatcher.log_event",
        lambda *args, **kwargs: None,
    )

    principal = Principal(
        username="tool-security-test",
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

    if case["expected_allowed"]:

        result = dispatch_llm_tool(
            tool_name=
                case["tool_name"],
            context=
                context,
        )

        assert result == sentinel

    else:

        expected_exception = {
            "PermissionError":
                PermissionError,
            "KeyError":
                KeyError,
            "ValueError":
                ValueError,
        }[
            case["expected_error"]
        ]

        with pytest.raises(
            expected_exception
        ):

            dispatch_llm_tool(
                tool_name=
                    case["tool_name"],
                context=
                    context,
            )