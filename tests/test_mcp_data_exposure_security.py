import json

import pytest

from mcp import Client

from app.auth import Principal

from app.mcp_server import mcp

from app.models import (
    AssetContext,
    ThreatIntel,
    VulnerabilityFinding,
)

from app.tools.dispatcher import (
    ToolExecutionContext,
)


# -------------------------------------------------
# PYTEST / ANYIO
# -------------------------------------------------


@pytest.fixture
def anyio_backend():

    return "asyncio"


# -------------------------------------------------
# SECRET MARKERS
# -------------------------------------------------


SECRET_USERNAME = (
    "internal-secret-user-7429"
)

SECRET_CONTEXT_VALUE = (
    "internal-context-secret-9841"
)


# -------------------------------------------------
# TEST CASES
# -------------------------------------------------


CASES = [
    {
        "tool_name": "get_finding",
        "result": VulnerabilityFinding(
            finding_id="finding-001",
            asset_name="host-01",
            cve="CVE-2099-0001",
            title="Test finding",
            description="Normal description",
            cvss=9.8,
            patch_available=True,
        ),
        "expected_keys": {
            "finding_id",
            "asset_name",
            "cve",
            "title",
            "description",
            "cvss",
            "patch_available",
        },
    },
    {
        "tool_name": "get_asset_details",
        "result": AssetContext(
            asset_name="host-01",
            owner="Security Team",
            application="Payments",
            environment="production",
            business_criticality="critical",
            internet_exposed=True,
            data_classification="confidential",
            current_controls=[
                "EDR",
                "MFA",
            ],
        ),
        "expected_keys": {
            "asset_name",
            "owner",
            "application",
            "environment",
            "business_criticality",
            "internet_exposed",
            "data_classification",
            "current_controls",
        },
    },
    {
        "tool_name": "get_threat_intel",
        "result": ThreatIntel(
            cve="CVE-2099-0001",
            epss=0.99,
            kev=True,
            data_source="trusted-feed",
        ),
        "expected_keys": {
            "cve",
            "epss",
            "kev",
            "data_source",
        },
    },
]


# -------------------------------------------------
# MCP DATA EXPOSURE
# -------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize(
    "case",
    CASES,
    ids=[
        case["tool_name"]
        for case in CASES
    ],
)
async def test_mcp_response_does_not_leak_execution_context(
    case,
    monkeypatch,
):

    secret_principal = Principal(
        username=SECRET_USERNAME,
        role="ANALYST",
        retrieval_access="standard",
    )

    secret_context = ToolExecutionContext(
        principal=secret_principal,
        finding=SECRET_CONTEXT_VALUE,
        asset=SECRET_CONTEXT_VALUE,
        risk=SECRET_CONTEXT_VALUE,
        retriever=SECRET_CONTEXT_VALUE,
    )

    observed_contexts = []

    def fake_build_context():

        return secret_context

    def fake_dispatch_llm_tool(
        *,
        tool_name,
        context,
    ):

        observed_contexts.append(
            context
        )

        assert (
            tool_name
            == case["tool_name"]
        )

        return case["result"]

    monkeypatch.setattr(
        "app.mcp_server.build_mcp_execution_context",
        fake_build_context,
    )

    monkeypatch.setattr(
        "app.mcp_server.dispatch_llm_tool",
        fake_dispatch_llm_tool,
    )

    async with Client(
        mcp,
        raise_exceptions=True,
    ) as client:

        result = await client.call_tool(
            case["tool_name"],
            {},
        )

    # -------------------------------------------------
    # NORMAL TOOL RESULT SUCCEEDS
    # -------------------------------------------------

    assert result.is_error is False

    assert (
        result.structured_content
        is not None
    )

    # -------------------------------------------------
    # RESPONSE MATCHES DECLARED CONTRACT
    # -------------------------------------------------

    assert (
        set(
            result.structured_content.keys()
        )
        == case["expected_keys"]
    )

    # -------------------------------------------------
    # INTERNAL EXECUTION CONTEXT WAS REAL
    # -------------------------------------------------

    assert len(
        observed_contexts
    ) == 1

    assert (
        observed_contexts[0]
        is secret_context
    )

    assert (
        observed_contexts[0]
        .principal
        .username
        == SECRET_USERNAME
    )

    # -------------------------------------------------
    # BUT INTERNAL DATA MUST NOT CROSS MCP BOUNDARY
    # -------------------------------------------------

    serialized_response = json.dumps(
        result.structured_content,
        sort_keys=True,
    )

    assert (
        SECRET_USERNAME
        not in serialized_response
    )

    assert (
        SECRET_CONTEXT_VALUE
        not in serialized_response
    )

    forbidden_names = {
        "principal",
        "username",
        "role",
        "retrieval_access",
        "finding",
        "asset",
        "risk",
        "retriever",
        "requires_human_approval",
        "llm_visible",
        "kind",
    }

    assert (
        forbidden_names
        .isdisjoint(
            result.structured_content.keys()
        )
    )