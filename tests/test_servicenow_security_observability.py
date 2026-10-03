from __future__ import annotations

import ast
from pathlib import Path

import pytest

import app.security_observability_integrations as integrations
from app.providers.servicenow_correlation import (
    build_servicenow_correlation_id,
)
from app.ticket_execution_context import (
    TicketExecutionContext,
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


@pytest.mark.parametrize(
    (
        "emitter",
        "event_type",
        "source_component",
    ),
    (
        (
            integrations
            .emit_servicenow_reconciliation_started_security_event,
            "security.workflow.reconciliation_started",
            "servicenow_reconciliation",
        ),
        (
            integrations
            .emit_servicenow_provider_request_started_security_event,
            "security.provider.request_started",
            "servicenow_provider",
        ),
        (
            integrations
            .emit_servicenow_provider_request_completed_security_event,
            "security.provider.request_completed",
            "servicenow_provider",
        ),
        (
            integrations
            .emit_servicenow_provider_result_correlated_security_event,
            "security.provider.result_correlated",
            "servicenow_provider",
        ),
        (
            integrations
            .emit_servicenow_reconciliation_resolved_security_event,
            "security.workflow.reconciliation_resolved",
            "servicenow_reconciliation",
        ),
    ),
)
def test_positive_servicenow_events_are_canonically_correlated(
    monkeypatch: pytest.MonkeyPatch,
    emitter,
    event_type: str,
    source_component: str,
):
    context, correlation = (
        _trusted_values()
    )

    events = _capture_events(
        monkeypatch
    )

    assert (
        emitter(
            tenant_id=context.tenant_id,
            workflow_id=context.workflow_id,
            execution_attempt_id=
                context.execution_attempt_id,
            provider_correlation_id=
                correlation,
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
        == event_type
    )

    assert (
        payload["source_component"]
        == source_component
    )

    assert (
        payload["provider_correlation_id"]
        == correlation
    )

    assert (
        payload["workflow_id"]
        == context.workflow_id
    )

    assert (
        payload["tenant_id"]
        == context.tenant_id
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

    assert (
        "execution_attempt_id"
        not in payload
    )


def test_ambiguous_result_is_review_required(
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
        .emit_servicenow_provider_result_ambiguous_security_event(
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
        == "security.provider.result_ambiguous"
    )

    assert (
        payload["outcome"]
        == "review_required"
    )

    assert (
        payload["reason_code"]
        == "provider_ambiguous"
    )


def test_syntax_valid_but_wrong_vmai_is_not_emitted(
    monkeypatch: pytest.MonkeyPatch,
):
    context, _ = (
        _trusted_values()
    )

    different = (
        build_servicenow_correlation_id(
            TicketExecutionContext(
                tenant_id=
                    context.tenant_id,
                workflow_id=
                    context.workflow_id,
                execution_attempt_id=
                    "EXEC-87654321",
            )
        )
    )

    events = _capture_events(
        monkeypatch
    )

    result = (
        integrations
        .emit_servicenow_provider_request_started_security_event(
            tenant_id=context.tenant_id,
            workflow_id=context.workflow_id,
            execution_attempt_id=
                context.execution_attempt_id,
            provider_correlation_id=
                different,
        )
    )

    assert result is False
    assert events == []


def test_raw_execution_attempt_is_not_a_canonical_event_field():
    source = Path(
        "app/security_observability_integrations.py"
    ).read_text(
        encoding="utf-8-sig"
    )

    tree = ast.parse(
        source
    )

    target_names = {
        "emit_servicenow_reconciliation_started_security_event",
        "emit_servicenow_provider_request_started_security_event",
        "emit_servicenow_provider_request_completed_security_event",
        "emit_servicenow_provider_result_correlated_security_event",
        "emit_servicenow_provider_result_ambiguous_security_event",
        "emit_servicenow_reconciliation_resolved_security_event",
    }

    functions = {
        node.name: node
        for node in tree.body
        if (
            isinstance(
                node,
                ast.FunctionDef,
            )
            and node.name
            in target_names
        )
    }

    assert (
        set(functions)
        == target_names
    )

    for function in functions.values():

        segment = (
            ast.get_source_segment(
                source,
                function,
            )
            or ""
        )

        assert (
            "execution_attempt_id="
            in segment
        )

        assert (
            "SecurityEvent("
            not in segment
        )


def _call_name(
    node: ast.Call,
) -> str | None:

    if isinstance(
        node.func,
        ast.Name,
    ):
        return node.func.id

    if isinstance(
        node.func,
        ast.Attribute,
    ):
        return node.func.attr

    return None


def test_reconciliation_lookup_event_order_is_authority_preserving():
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

    calls = [
        node
        for node in ast.walk(
            method
        )
        if isinstance(
            node,
            ast.Call,
        )
    ]

    by_name = {}

    for call in calls:

        name = _call_name(
            call
        )

        if name is not None:
            by_name.setdefault(
                name,
                [],
            ).append(
                call
            )

    assert len(
        by_name[
            "build_servicenow_correlation_id"
        ]
    ) == 1

    assert len(
        by_name[
            "emit_servicenow_reconciliation_started_security_event"
        ]
    ) == 1

    assert len(
        by_name[
            "emit_servicenow_provider_request_started_security_event"
        ]
    ) == 1

    assert len(
        by_name[
            "find_records_by_correlation_id"
        ]
    ) == 1

    assert len(
        by_name[
            "emit_servicenow_provider_request_completed_security_event"
        ]
    ) == 1

    build_line = (
        by_name[
            "build_servicenow_correlation_id"
        ][0].lineno
    )

    reconciliation_started_line = (
        by_name[
            "emit_servicenow_reconciliation_started_security_event"
        ][0].lineno
    )

    request_started_line = (
        by_name[
            "emit_servicenow_provider_request_started_security_event"
        ][0].lineno
    )

    lookup_line = (
        by_name[
            "find_records_by_correlation_id"
        ][0].lineno
    )

    request_completed_line = (
        by_name[
            "emit_servicenow_provider_request_completed_security_event"
        ][0].lineno
    )

    assert (
        build_line
        < reconciliation_started_line
        < request_started_line
        < lookup_line
        < request_completed_line
    )


def test_not_found_is_not_instrumented_as_provider_ambiguity():
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

    not_found_returns = []

    for node in ast.walk(
        method
    ):

        if not (
            isinstance(
                node,
                ast.Return,
            )
            and isinstance(
                node.value,
                ast.Call,
            )
        ):
            continue

        for keyword in node.value.keywords:

            if (
                keyword.arg
                == "outcome"
                and isinstance(
                    keyword.value,
                    ast.Constant,
                )
                and keyword.value.value
                == "NOT_FOUND"
            ):
                not_found_returns.append(
                    node
                )

    assert len(
        not_found_returns
    ) == 1

    enclosing = (
        ast.get_source_segment(
            source,
            next(
                node
                for node in ast.walk(
                    method
                )
                if (
                    isinstance(
                        node,
                        ast.If,
                    )
                    and node.lineno
                    < not_found_returns[0].lineno
                    <= getattr(
                        node,
                        "end_lineno",
                        node.lineno,
                    )
                    and (
                        "match_count == 0"
                        in (
                            " ".join(
                                (
                                    ast.get_source_segment(
                                        source,
                                        node.test,
                                    )
                                    or ""
                                ).split()
                            )
                        )
                    )
                )
            ),
        )
        or ""
    )

    assert (
        "emit_servicenow_provider_result_ambiguous_security_event"
        not in enclosing
    )


def test_provider_result_classification_wiring_is_truthful():
    source = RECONCILIATION_PATH.read_text(
        encoding="utf-8-sig"
    )

    assert (
        source.count(
            "emit_servicenow_provider_result_correlated_security_event("
        )
        == 1
    )

    assert (
        source.count(
            "emit_servicenow_provider_result_ambiguous_security_event("
        )
        == 1
    )

    correlated = source.index(
        "emit_servicenow_provider_result_correlated_security_event("
    )

    single_match = source.index(
        "match_count == 1"
    )

    ambiguous = source.index(
        "emit_servicenow_provider_result_ambiguous_security_event("
    )

    conflict = source.index(
        'outcome=\n            "CONFLICT"'
    )

    assert (
        single_match
        < correlated
    )

    assert (
        ambiguous
        < conflict
    )


def test_reconciliation_resolved_event_occurs_after_store_transition():
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

    calls = [
        node
        for node in ast.walk(
            method
        )
        if isinstance(
            node,
            ast.Call,
        )
    ]

    names = {}

    for call in calls:

        name = _call_name(
            call
        )

        if name is not None:
            names.setdefault(
                name,
                [],
            ).append(
                call
            )

    assert len(
        names[
            "confirm_reconciled_ticket_creation"
        ]
    ) == 1

    assert len(
        names[
            "authorize_reconciled_retry"
        ]
    ) == 1

    resolved_events = names[
        "emit_servicenow_reconciliation_resolved_security_event"
    ]

    assert len(
        resolved_events
    ) == 2

    confirm_line = (
        names[
            "confirm_reconciled_ticket_creation"
        ][0].lineno
    )

    retry_line = (
        names[
            "authorize_reconciled_retry"
        ][0].lineno
    )

    event_lines = sorted(
        call.lineno
        for call in resolved_events
    )

    assert (
        confirm_line
        < event_lines[0]
    )

    assert (
        retry_line
        < event_lines[1]
    )
