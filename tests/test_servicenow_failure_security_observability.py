from __future__ import annotations

import ast
from pathlib import Path

import pytest

import app.security_observability_integrations as integrations
from app.providers.servicenow_client import (
    ServiceNowLookupError,
    ServiceNowLookupFailureKind,
)
from app.providers.servicenow_correlation import (
    build_servicenow_correlation_id,
)
from app.ticket_execution_context import (
    TicketExecutionContext,
)


CLIENT_PATH = Path(
    "app/providers/servicenow_client.py"
)

RECONCILIATION_PATH = Path(
    "app/servicenow_reconciliation.py"
)


def _trusted_values():
    context = TicketExecutionContext(
        tenant_id="tenant-alpha",
        workflow_id="WF-12345678",
        execution_attempt_id="EXEC-12345678",
    )

    correlation = (
        build_servicenow_correlation_id(
            context
        )
    )

    return (
        context,
        correlation,
    )


def _capture_events(
    monkeypatch: pytest.MonkeyPatch,
):
    events = []

    def capture(event):
        events.append(
            event
        )
        return True

    monkeypatch.setattr(
        integrations,
        "_emit_best_effort",
        capture,
    )

    return events


def test_lookup_failure_kind_vocabulary_is_bounded():
    assert {
        item.value
        for item in ServiceNowLookupFailureKind
    } == {
        "transport",
        "http_status",
        "invalid_response",
        "correlation_mismatch",
    }


def test_lookup_error_preserves_message_and_typed_kind():
    error = ServiceNowLookupError(
        "stable message",
        failure_kind=(
            ServiceNowLookupFailureKind
            .INVALID_RESPONSE
        ),
    )

    assert (
        str(error)
        == "stable message"
    )

    assert (
        error.failure_kind
        is (
            ServiceNowLookupFailureKind
            .INVALID_RESPONSE
        )
    )


@pytest.mark.parametrize(
    "failure_kind",
    (
        "transport",
        "http_status",
        "invalid_response",
    ),
)
def test_generic_lookup_failures_emit_failed_reconciliation_denial(
    monkeypatch: pytest.MonkeyPatch,
    failure_kind: str,
):
    context, correlation = (
        _trusted_values()
    )

    events = _capture_events(
        monkeypatch
    )

    assert (
        integrations
        .emit_servicenow_provider_lookup_failure_security_event(
            tenant_id=context.tenant_id,
            workflow_id=context.workflow_id,
            execution_attempt_id=
                context.execution_attempt_id,
            provider_correlation_id=
                correlation,
            failure_kind=failure_kind,
        )
        is True
    )

    assert len(events) == 1

    payload = (
        events[0]
        .to_dict()
    )

    assert (
        payload["event_type"]
        == "security.provider.reconciliation_denied"
    )

    assert (
        payload["outcome"]
        == "failed"
    )

    assert (
        payload["reason_code"]
        == "reconciliation_denied"
    )

    assert (
        payload["source_component"]
        == "servicenow_provider"
    )

    assert (
        payload["resource_type"]
        == "reconciliation"
    )

    assert (
        payload["provider_correlation_id"]
        == correlation
    )

    assert (
        payload[
            "execution_attempt_ref"
        ].startswith(
            "EA1-"
        )
    )

    assert (
        context.execution_attempt_id
        not in str(
            payload
        )
    )


def test_provider_correlation_mismatch_emits_specific_denial(
    monkeypatch: pytest.MonkeyPatch,
):
    context, correlation = (
        _trusted_values()
    )

    events = _capture_events(
        monkeypatch
    )

    assert (
        integrations
        .emit_servicenow_provider_lookup_failure_security_event(
            tenant_id=context.tenant_id,
            workflow_id=context.workflow_id,
            execution_attempt_id=
                context.execution_attempt_id,
            provider_correlation_id=
                correlation,
            failure_kind=
                "correlation_mismatch",
        )
        is True
    )

    payload = (
        events[0]
        .to_dict()
    )

    assert (
        payload["outcome"]
        == "denied"
    )

    assert (
        payload["reason_code"]
        == "provider_correlation_mismatch"
    )

    assert (
        payload["provider_correlation_id"]
        == correlation
    )


def test_unknown_lookup_failure_kind_is_not_emitted(
    monkeypatch: pytest.MonkeyPatch,
):
    context, correlation = (
        _trusted_values()
    )

    events = _capture_events(
        monkeypatch
    )

    assert (
        integrations
        .emit_servicenow_provider_lookup_failure_security_event(
            tenant_id=context.tenant_id,
            workflow_id=context.workflow_id,
            execution_attempt_id=
                context.execution_attempt_id,
            provider_correlation_id=
                correlation,
            failure_kind="unbounded",
        )
        is False
    )

    assert events == []


def test_conflict_refusal_is_bounded_provider_ambiguity_denial(
    monkeypatch: pytest.MonkeyPatch,
):
    context, correlation = (
        _trusted_values()
    )

    events = _capture_events(
        monkeypatch
    )

    assert (
        integrations
        .emit_servicenow_provider_conflict_denied_security_event(
            tenant_id=context.tenant_id,
            workflow_id=context.workflow_id,
            execution_attempt_id=
                context.execution_attempt_id,
            provider_correlation_id=
                correlation,
        )
        is True
    )

    payload = (
        events[0]
        .to_dict()
    )

    assert (
        payload["event_type"]
        == "security.provider.reconciliation_denied"
    )

    assert (
        payload["outcome"]
        == "denied"
    )

    assert (
        payload["reason_code"]
        == "provider_ambiguous"
    )

    assert (
        payload["source_component"]
        == "servicenow_reconciliation"
    )


def test_all_client_lookup_errors_have_bounded_failure_kind():
    source = CLIENT_PATH.read_text(
        encoding="utf-8-sig"
    )

    tree = ast.parse(
        source,
        filename=str(
            CLIENT_PATH
        ),
    )

    client = next(
        node
        for node in tree.body
        if (
            isinstance(
                node,
                ast.ClassDef,
            )
            and node.name
            == "ServiceNowClient"
        )
    )

    method = next(
        node
        for node in client.body
        if (
            isinstance(
                node,
                ast.FunctionDef,
            )
            and node.name
            == "find_records_by_correlation_id"
        )
    )

    calls = [
        node
        for node in ast.walk(
            method
        )
        if (
            isinstance(
                node,
                ast.Call,
            )
            and isinstance(
                node.func,
                ast.Name,
            )
            and node.func.id
            == "ServiceNowLookupError"
        )
    ]

    assert len(calls) == 11

    observed = []

    for call in calls:

        keywords = [
            keyword
            for keyword in call.keywords
            if keyword.arg
            == "failure_kind"
        ]

        assert len(
            keywords
        ) == 1

        value = (
            keywords[0].value
        )

        assert isinstance(
            value,
            ast.Attribute,
        )

        observed.append(
            value.attr
        )

    assert observed.count(
        "TRANSPORT"
    ) == 1

    assert observed.count(
        "HTTP_STATUS"
    ) == 1

    assert observed.count(
        "INVALID_RESPONSE"
    ) == 8

    assert observed.count(
        "CORRELATION_MISMATCH"
    ) == 1


def test_lookup_failure_handler_re_raises_without_exception_text():
    source = RECONCILIATION_PATH.read_text(
        encoding="utf-8-sig"
    )

    tree = ast.parse(
        source,
        filename=str(
            RECONCILIATION_PATH
        ),
    )

    method = next(
        node
        for node in tree.body
        if (
            isinstance(
                node,
                ast.FunctionDef,
            )
            and node.name
            == "reconcile_servicenow_workflow"
        )
    )

    lookup_try = next(
        node
        for node in ast.walk(
            method
        )
        if (
            isinstance(
                node,
                ast.Try,
            )
            and (
                "find_records_by_correlation_id"
                in (
                    ast.get_source_segment(
                        source,
                        node,
                    )
                    or ""
                )
            )
        )
    )

    assert len(
        lookup_try.handlers
    ) == 1

    handler = (
        lookup_try.handlers[0]
    )

    assert isinstance(
        handler.type,
        ast.Name,
    )

    assert (
        handler.type.id
        == "ServiceNowLookupError"
    )

    handler_source = (
        ast.get_source_segment(
            source,
            handler,
        )
        or ""
    )

    assert (
        "error.failure_kind.value"
        in handler_source
    )

    assert (
        "str(error)"
        not in handler_source
    )

    assert (
        "error.__cause__"
        not in handler_source
    )

    assert any(
        (
            isinstance(
                node,
                ast.Raise,
            )
            and node.exc is None
        )
        for node in ast.walk(
            handler
        )
    )


def test_failed_lookup_does_not_move_request_completed_into_handler():
    source = RECONCILIATION_PATH.read_text(
        encoding="utf-8-sig"
    )

    tree = ast.parse(
        source,
        filename=str(
            RECONCILIATION_PATH
        ),
    )

    method = next(
        node
        for node in tree.body
        if (
            isinstance(
                node,
                ast.FunctionDef,
            )
            and node.name
            == "reconcile_servicenow_workflow"
        )
    )

    lookup_try = next(
        node
        for node in ast.walk(
            method
        )
        if (
            isinstance(
                node,
                ast.Try,
            )
            and (
                "find_records_by_correlation_id"
                in (
                    ast.get_source_segment(
                        source,
                        node,
                    )
                    or ""
                )
            )
        )
    )

    body_source = (
        "\n".join(
            (
                ast.get_source_segment(
                    source,
                    statement,
                )
                or ""
            )
            for statement
            in lookup_try.body
        )
    )

    handler_source = (
        "\n".join(
            (
                ast.get_source_segment(
                    source,
                    statement,
                )
                or ""
            )
            for statement
            in lookup_try.handlers[0].body
        )
    )

    final_source = (
        "\n".join(
            (
                ast.get_source_segment(
                    source,
                    statement,
                )
                or ""
            )
            for statement
            in lookup_try.finalbody
        )
    )

    assert (
        "emit_servicenow_provider_request_completed_security_event"
        in body_source
    )

    assert (
        "emit_servicenow_provider_request_completed_security_event"
        not in handler_source
    )

    assert (
        "client.close()"
        in final_source
    )


def test_conflict_denial_event_precedes_existing_refusal_raise():
    source = RECONCILIATION_PATH.read_text(
        encoding="utf-8-sig"
    )

    tree = ast.parse(
        source,
        filename=str(
            RECONCILIATION_PATH
        ),
    )

    method = next(
        node
        for node in tree.body
        if (
            isinstance(
                node,
                ast.FunctionDef,
            )
            and node.name
            == "resolve_servicenow_workflow"
        )
    )

    event_calls = [
        node
        for node in ast.walk(
            method
        )
        if (
            isinstance(
                node,
                ast.Call,
            )
            and isinstance(
                node.func,
                ast.Name,
            )
            and node.func.id
            == (
                "emit_servicenow_provider_"
                "conflict_denied_security_event"
            )
        )
    ]

    refusal_raises = [
        node
        for node in ast.walk(
            method
        )
        if (
            isinstance(
                node,
                ast.Raise,
            )
            and (
                "multiple matching records"
                in (
                    ast.get_source_segment(
                        source,
                        node,
                    )
                    or ""
                )
            )
        )
    ]

    assert len(
        event_calls
    ) == 1

    assert len(
        refusal_raises
    ) == 1

    assert (
        event_calls[0].lineno
        < refusal_raises[0].lineno
    )


def test_failure_adapter_never_accepts_raw_provider_record_fields():
    source = Path(
        "app/security_observability_integrations.py"
    ).read_text(
        encoding="utf-8-sig"
    )

    tree = ast.parse(
        source
    )

    target = next(
        node
        for node in tree.body
        if (
            isinstance(
                node,
                ast.FunctionDef,
            )
            and node.name
            == "emit_servicenow_provider_lookup_failure_security_event"
        )
    )

    arguments = {
        argument.arg
        for argument in (
            list(
                target.args.args
            )
            + list(
                target.args.kwonlyargs
            )
        )
    }

    assert arguments == {
        "tenant_id",
        "workflow_id",
        "execution_attempt_id",
        "provider_correlation_id",
        "failure_kind",
    }

    assert "response" not in arguments
    assert "record" not in arguments
    assert "sys_id" not in arguments
    assert "ticket_number" not in arguments
    assert "error" not in arguments
