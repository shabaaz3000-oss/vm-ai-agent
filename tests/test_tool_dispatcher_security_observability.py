from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import app.tools.dispatcher as dispatcher


class StubContext:
    def __init__(
        self,
        *,
        telemetry_origin=None,
        tenant_id=None,
        binding_error=False,
    ):
        self.telemetry_origin = telemetry_origin

        self.security_context = (
            None
            if tenant_id is None
            else SimpleNamespace(
                tenant_id=tenant_id,
                session_correlation_id="session-ref-alpha",
            )
        )

        self.principal = object()

        self.binding_error = binding_error

    def validate_security_binding(
        self,
    ) -> None:

        if self.binding_error:
            raise ValueError(
                "simulated binding mismatch"
            )

    def audit_identity_fields(
        self,
    ) -> dict[str, str]:

        return {}


def _allow_get_finding(
    monkeypatch: pytest.MonkeyPatch,
):

    monkeypatch.setattr(
        dispatcher,
        "get_tool_spec",
        lambda _name: SimpleNamespace(
            llm_visible=True,
            kind="read",
        ),
    )

    monkeypatch.setattr(
        dispatcher,
        "get_finding",
        lambda *,
        principal: "finding-result",
    )

    monkeypatch.setattr(
        dispatcher,
        "log_event",
        lambda *_args, **_kwargs: None,
    )


def test_non_mcp_dispatch_emits_no_canonical_mcp_event(
    monkeypatch: pytest.MonkeyPatch,
):
    allowed = []
    denied = []

    _allow_get_finding(
        monkeypatch
    )

    monkeypatch.setattr(
        dispatcher,
        "emit_mcp_tool_invocation_allowed_security_event",
        lambda **kwargs: allowed.append(
            kwargs
        ),
    )

    monkeypatch.setattr(
        dispatcher,
        "emit_mcp_tool_invocation_denied_security_event",
        lambda **kwargs: denied.append(
            kwargs
        ),
    )

    context = StubContext()

    result = dispatcher.dispatch_llm_tool(
        "get_finding",
        context,
    )

    assert result == "finding-result"
    assert allowed == []
    assert denied == []


def test_string_mcp_marker_does_not_count_as_trusted_origin(
    monkeypatch: pytest.MonkeyPatch,
):
    allowed = []

    _allow_get_finding(
        monkeypatch
    )

    monkeypatch.setattr(
        dispatcher,
        "emit_mcp_tool_invocation_allowed_security_event",
        lambda **kwargs: allowed.append(
            kwargs
        ),
    )

    context = StubContext(
        telemetry_origin="mcp",
        tenant_id="tenant-alpha",
    )

    dispatcher.dispatch_llm_tool(
        "get_finding",
        context,
    )

    assert allowed == []


def test_trusted_mcp_dispatch_emits_allowed_event(
    monkeypatch: pytest.MonkeyPatch,
):
    allowed = []

    _allow_get_finding(
        monkeypatch
    )

    monkeypatch.setattr(
        dispatcher,
        "emit_mcp_tool_invocation_allowed_security_event",
        lambda **kwargs: allowed.append(
            kwargs
        ),
    )

    context = StubContext(
        telemetry_origin=(
            dispatcher
            .ToolInvocationTelemetryOrigin
            .MCP
        ),
        tenant_id="tenant-alpha",
    )

    result = dispatcher.dispatch_llm_tool(
        "get_finding",
        context,
    )

    assert result == "finding-result"

    assert allowed == [
        {
            "tenant_id":
                "tenant-alpha",

            "session_ref":
                "session-ref-alpha",
        }
    ]


@pytest.mark.parametrize(
    (
        "spec_factory",
        "expected_exception",
    ),
    [
        (
            lambda: (_ for _ in ()).throw(
                KeyError(
                    "unknown tool"
                )
            ),
            KeyError,
        ),
        (
            lambda: SimpleNamespace(
                llm_visible=False,
                kind="read",
            ),
            PermissionError,
        ),
        (
            lambda: SimpleNamespace(
                llm_visible=True,
                kind="action",
            ),
            PermissionError,
        ),
    ],
)
def test_trusted_mcp_policy_denials_emit_canonical_denial(
    monkeypatch: pytest.MonkeyPatch,
    spec_factory,
    expected_exception,
):
    denied = []

    def get_spec(
        _name,
    ):
        return spec_factory()

    monkeypatch.setattr(
        dispatcher,
        "get_tool_spec",
        get_spec,
    )

    monkeypatch.setattr(
        dispatcher,
        "log_event",
        lambda *_args, **_kwargs: None,
    )

    monkeypatch.setattr(
        dispatcher,
        "emit_mcp_tool_invocation_denied_security_event",
        lambda **kwargs: denied.append(
            kwargs
        ),
    )

    context = StubContext(
        telemetry_origin=(
            dispatcher
            .ToolInvocationTelemetryOrigin
            .MCP
        ),
        tenant_id="tenant-alpha",
    )

    with pytest.raises(
        expected_exception
    ):
        dispatcher.dispatch_llm_tool(
            "some-tool",
            context,
        )

    assert denied == [
        {
            "tenant_id":
                "tenant-alpha",

            "reason":
                "tool_not_authorized",

            "session_ref":
                "session-ref-alpha",
        }
    ]


def test_mcp_binding_mismatch_emits_denial_and_preserves_exception(
    monkeypatch: pytest.MonkeyPatch,
):
    denied = []

    monkeypatch.setattr(
        dispatcher,
        "emit_mcp_tool_invocation_denied_security_event",
        lambda **kwargs: denied.append(
            kwargs
        ),
    )

    context = StubContext(
        telemetry_origin=(
            dispatcher
            .ToolInvocationTelemetryOrigin
            .MCP
        ),
        tenant_id="tenant-alpha",
        binding_error=True,
    )

    with pytest.raises(
        ValueError,
        match="simulated binding mismatch",
    ):
        dispatcher.dispatch_llm_tool(
            "get_finding",
            context,
        )

    assert denied == [
        {
            "tenant_id":
                "tenant-alpha",

            "reason":
                "security_binding_mismatch",

            "session_ref":
                "session-ref-alpha",
        }
    ]


def test_mcp_origin_without_security_context_emits_nothing(
    monkeypatch: pytest.MonkeyPatch,
):
    allowed = []

    _allow_get_finding(
        monkeypatch
    )

    monkeypatch.setattr(
        dispatcher,
        "emit_mcp_tool_invocation_allowed_security_event",
        lambda **kwargs: allowed.append(
            kwargs
        ),
    )

    context = StubContext(
        telemetry_origin=(
            dispatcher
            .ToolInvocationTelemetryOrigin
            .MCP
        ),
        tenant_id=None,
    )

    dispatcher.dispatch_llm_tool(
        "get_finding",
        context,
    )

    assert allowed == []


def test_only_mcp_builders_set_telemetry_origin():
    agent = Path(
        "app/agent.py"
    ).read_text(
        encoding="utf-8-sig"
    )

    mcp_server = Path(
        "app/mcp_server.py"
    ).read_text(
        encoding="utf-8-sig"
    )

    mcp_rag = Path(
        "app/mcp_rag_context.py"
    ).read_text(
        encoding="utf-8-sig"
    )

    assert (
        "ToolInvocationTelemetryOrigin"
        not in agent
    )

    assert (
        mcp_server.count(
            "telemetry_origin="
        )
        == 1
    )

    assert (
        mcp_rag.count(
            "telemetry_origin="
        )
        == 1
    )

    assert (
        "ToolInvocationTelemetryOrigin.MCP"
        in mcp_server
    )

    assert (
        "ToolInvocationTelemetryOrigin.MCP"
        in mcp_rag
    )
