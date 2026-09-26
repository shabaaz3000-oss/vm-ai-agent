import json

from pathlib import Path

import pytest

from mcp import Client

from app.mcp_server import (
    LOCAL_MCP_PRINCIPAL,
    mcp,
)

from app.models import (
    AssetContext,
    ThreatIntel,
    VulnerabilityFinding,
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
    / "mcp_output_security_cases.json"
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
# TEST DATA BUILDERS
# -------------------------------------------------


def build_finding(
    target_field: str,
    payload: str,
) -> VulnerabilityFinding:

    data = {
        "finding_id": "finding-output-security",
        "asset_name": "host-01",
        "cve": "CVE-2099-9999",
        "title": "Test finding",
        "description": "Normal vulnerability description.",
        "cvss": 9.8,
        "patch_available": True,
    }

    data[target_field] = payload

    return VulnerabilityFinding(
        **data
    )


def build_asset(
    target_field: str,
    payload: str,
) -> AssetContext:

    data = {
        "asset_name": "host-01",
        "owner": "Security Team",
        "application": "Payments",
        "environment": "production",
        "business_criticality": "critical",
        "internet_exposed": True,
        "data_classification": "confidential",
        "current_controls": [
            "EDR",
            "MFA",
        ],
    }

    if target_field == "current_controls":

        data[target_field] = [
            payload
        ]

    else:

        data[target_field] = payload

    return AssetContext(
        **data
    )


def build_threat_intel(
    target_field: str,
    payload: str,
) -> ThreatIntel:

    data = {
        "cve": "CVE-2099-9999",
        "epss": 0.99,
        "kev": True,
        "data_source": "trusted-feed",
    }

    data[target_field] = payload

    return ThreatIntel(
        **data
    )


def build_tool_result(
    tool_name: str,
    target_field: str,
    payload: str,
):

    if tool_name == "get_finding":

        return build_finding(
            target_field,
            payload,
        )

    if tool_name == "get_asset_details":

        return build_asset(
            target_field,
            payload,
        )

    if tool_name == "get_threat_intel":

        return build_threat_intel(
            target_field,
            payload,
        )

    raise ValueError(
        f"Unsupported MCP output tool: "
        f"{tool_name}"
    )


# -------------------------------------------------
# METADATA
# -------------------------------------------------


def test_mcp_output_security_corpus_metadata_is_valid():

    required_fields = {
        "id",
        "name",
        "tool_name",
        "target_field",
        "payload",
        "category",
        "severity",
    }

    allowed_tools = {
        "get_finding",
        "get_asset_details",
        "get_threat_intel",
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

        assert (
            case["tool_name"]
            in allowed_tools
        )

        assert isinstance(
            case["target_field"],
            str,
        )

        assert case["target_field"].strip()

        assert isinstance(
            case["payload"],
            str,
        )

        assert case["payload"].strip()

        assert isinstance(
            case["category"],
            str,
        )

        assert case["category"].strip()

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
# ADVERSARIAL MCP OUTPUT CASES
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
async def test_mcp_tool_output_remains_data(
    case,
    monkeypatch,
):

    dispatch_calls = []

    expected_result = build_tool_result(
        case["tool_name"],
        case["target_field"],
        case["payload"],
    )

    def fake_dispatch_llm_tool(
        *,
        tool_name,
        context,
    ):

        dispatch_calls.append(
            (
                tool_name,
                context,
            )
        )

        return expected_result

    monkeypatch.setattr(
        "app.mcp_server.dispatch_llm_tool",
        fake_dispatch_llm_tool,
    )

    async with Client(
        mcp,
        raise_exceptions=True,
    ) as client:

        tools_before = (
            await client.list_tools()
        )

        result = await client.call_tool(
            case["tool_name"],
            {},
        )

        tools_after = (
            await client.list_tools()
        )

        hidden_action = await client.call_tool(
            "execute_ticket_workflow",
            {},
        )

    # -------------------------------------------------
    # ORIGINAL READ SUCCEEDS
    # -------------------------------------------------

    assert result.is_error is False

    assert (
        result.structured_content
        is not None
    )

    # -------------------------------------------------
    # PAYLOAD SURVIVES AS DATA
    # -------------------------------------------------

    returned_value = (
        result.structured_content[
            case["target_field"]
        ]
    )

    if (
        case["target_field"]
        == "current_controls"
    ):

        assert (
            case["payload"]
            in returned_value
        )

    else:

        assert (
            returned_value
            == case["payload"]
        )

    # -------------------------------------------------
    # NO CAPABILITY EXPANSION
    # -------------------------------------------------

    tool_names_before = [
        tool.name
        for tool in tools_before.tools
    ]

    tool_names_after = [
        tool.name
        for tool in tools_after.tools
    ]

    assert tool_names_before == [
        "get_finding",
        "get_asset_details",
        "get_threat_intel",
    ]

    assert (
        tool_names_after
        == tool_names_before
    )

    # -------------------------------------------------
    # HIDDEN ACTION STILL INACCESSIBLE
    # -------------------------------------------------

    assert (
        hidden_action.is_error
        is True
    )

    # -------------------------------------------------
    # ONLY ORIGINAL READ REACHED DISPATCHER
    # -------------------------------------------------

    assert len(dispatch_calls) == 1

    tool_name, context = (
        dispatch_calls[0]
    )

    assert (
        tool_name
        == case["tool_name"]
    )

    # -------------------------------------------------
    # SERVER AUTHORITY REMAINS UNCHANGED
    # -------------------------------------------------

    assert (
        context.principal.username
        == LOCAL_MCP_PRINCIPAL.username
    )

    assert (
        context.principal.role
        == LOCAL_MCP_PRINCIPAL.role
    )

    assert (
        context.principal.retrieval_access
        == LOCAL_MCP_PRINCIPAL.retrieval_access
    )

    assert (
        context.principal.role
        == "ANALYST"
    )