from __future__ import annotations

import ast
from pathlib import Path

import pytest

import app.security_observability_integrations as integrations


SQLITE_PATH = Path(
    "app/workflow_store.py"
)

POSTGRESQL_PATH = Path(
    "app/workflow_postgresql_store.py"
)

INTEGRATIONS_PATH = Path(
    "app/security_observability_integrations.py"
)


STORE_CONFIGURATIONS = (
    (
        SQLITE_PATH,
        None,
        "_sqlite_claim_workflow_for_execution",
        (
            "emit_sqlite_workflow_execution_"
            "claim_denied_security_event"
        ),
    ),
    (
        POSTGRESQL_PATH,
        "PostgreSQLWorkflowStore",
        "claim_workflow_for_execution",
        (
            "emit_postgresql_workflow_execution_"
            "claim_denied_security_event"
        ),
    ),
)


def _source(
    path: Path,
) -> str:
    return path.read_text(
        encoding="utf-8-sig"
    )


def _call_name(
    call: ast.Call,
) -> str | None:

    if isinstance(
        call.func,
        ast.Name,
    ):
        return call.func.id

    if isinstance(
        call.func,
        ast.Attribute,
    ):
        return call.func.attr

    return None


def _keyword(
    call: ast.Call,
    name: str,
) -> ast.keyword | None:

    return next(
        (
            value
            for value in call.keywords
            if value.arg == name
        ),
        None,
    )


def _literal_keyword(
    call: ast.Call,
    name: str,
) -> str | None:

    value = _keyword(
        call,
        name,
    )

    if value is None:
        return None

    if (
        isinstance(
            value.value,
            ast.Constant,
        )
        and isinstance(
            value.value.value,
            str,
        )
    ):
        return value.value.value

    return None


def _store_method(
    path: Path,
    *,
    class_name: str | None,
    method_name: str,
) -> tuple[
    str,
    ast.FunctionDef,
]:

    source = _source(
        path
    )

    tree = ast.parse(
        source,
        filename=str(path),
    )


    if class_name is None:

        methods = [
            node
            for node in tree.body
            if (
                isinstance(
                    node,
                    ast.FunctionDef,
                )
                and node.name
                == method_name
            )
        ]

    else:

        classes = [
            node
            for node in tree.body
            if (
                isinstance(
                    node,
                    ast.ClassDef,
                )
                and node.name
                == class_name
            )
        ]

        assert len(classes) == 1

        methods = [
            node
            for node in classes[0].body
            if (
                isinstance(
                    node,
                    ast.FunctionDef,
                )
                and node.name
                == method_name
            )
        ]


    assert len(methods) == 1

    return (
        source,
        methods[0],
    )


def _emitter_calls(
    method: ast.FunctionDef,
    emitter_name: str,
) -> list[ast.Call]:

    return [
        node
        for node in ast.walk(
            method
        )
        if (
            isinstance(
                node,
                ast.Call,
            )
            and _call_name(
                node
            )
            == emitter_name
        )
    ]


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
        "expected_source",
    ),
    (
        (
            (
                integrations
                .emit_sqlite_workflow_execution_claim_denied_security_event
            ),
            "workflow_store",
        ),
        (
            (
                integrations
                .emit_postgresql_workflow_execution_claim_denied_security_event
            ),
            "workflow_postgresql_store",
        ),
    ),
)
def test_claim_denial_adapter_emits_canonical_event(
    monkeypatch: pytest.MonkeyPatch,
    emitter,
    expected_source: str,
):
    events = _capture_events(
        monkeypatch
    )

    assert (
        emitter(
            reason="cross_tenant",
            tenant_id="tenant-authoritative",
            workflow_id="WF-12345678",
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
        == "security.workflow.execution_claim_denied"
    )

    assert (
        payload["outcome"]
        == "denied"
    )

    assert (
        payload["source_component"]
        == expected_source
    )

    assert (
        payload["reason_code"]
        == "cross_tenant"
    )

    assert (
        payload["tenant_id"]
        == "tenant-authoritative"
    )

    assert (
        payload["workflow_id"]
        == "WF-12345678"
    )

    assert (
        "execution_attempt_id"
        not in payload
    )

    assert (
        "execution_attempt_ref"
        not in payload
    )


@pytest.mark.parametrize(
    "reason",
    (
        "workflow_transition_not_allowed",
        "execution_already_claimed",
        "security_binding_mismatch",
        "cross_tenant",
    ),
)
def test_claim_denial_reason_vocabulary_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
):
    events = _capture_events(
        monkeypatch
    )

    assert (
        integrations
        .emit_sqlite_workflow_execution_claim_denied_security_event(
            reason=reason,
        )
        is True
    )

    assert (
        events[0]
        .to_dict()[
            "reason_code"
        ]
        == reason
    )


def test_wrong_state_event_may_omit_all_correlation(
    monkeypatch: pytest.MonkeyPatch,
):
    events = _capture_events(
        monkeypatch
    )

    assert (
        integrations
        .emit_sqlite_workflow_execution_claim_denied_security_event(
            reason="workflow_transition_not_allowed",
        )
        is True
    )

    payload = (
        events[0]
        .to_dict()
    )

    assert (
        "workflow_id"
        not in payload
    )

    assert (
        "tenant_id"
        not in payload
    )

    assert (
        "execution_attempt_ref"
        not in payload
    )


def test_claim_denial_adapter_accepts_no_attempt_authority():
    source = _source(
        INTEGRATIONS_PATH
    )

    tree = ast.parse(
        source,
        filename=str(
            INTEGRATIONS_PATH
        ),
    )

    targets = {
        (
            "emit_sqlite_workflow_execution_"
            "claim_denied_security_event"
        ),
        (
            "emit_postgresql_workflow_execution_"
            "claim_denied_security_event"
        ),
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
            in targets
        )
    }

    assert (
        set(functions)
        == targets
    )

    for function in functions.values():

        arguments = {
            arg.arg
            for arg in (
                list(
                    function.args.args
                )
                + list(
                    function.args.kwonlyargs
                )
            )
        }

        assert (
            "execution_attempt_id"
            not in arguments
        )

        assert (
            "execution_attempt_ref"
            not in arguments
        )


@pytest.mark.parametrize(
    (
        "path",
        "class_name",
        "method_name",
        "emitter_name",
    ),
    STORE_CONFIGURATIONS,
)
def test_backend_has_four_authoritative_denial_observations(
    path: Path,
    class_name: str | None,
    method_name: str,
    emitter_name: str,
):
    _, method = _store_method(
        path,
        class_name=class_name,
        method_name=method_name,
    )

    calls = _emitter_calls(
        method,
        emitter_name,
    )

    assert len(calls) == 4


@pytest.mark.parametrize(
    (
        "path",
        "class_name",
        "method_name",
        "emitter_name",
    ),
    STORE_CONFIGURATIONS,
)
def test_backend_has_two_truthful_conditional_classifiers(
    path: Path,
    class_name: str | None,
    method_name: str,
    emitter_name: str,
):
    source, method = _store_method(
        path,
        class_name=class_name,
        method_name=method_name,
    )

    calls = _emitter_calls(
        method,
        emitter_name,
    )

    conditional = [
        call
        for call in calls
        if (
            _keyword(
                call,
                "reason",
            )
            is not None
            and isinstance(
                _keyword(
                    call,
                    "reason",
                ).value,
                ast.IfExp,
            )
        )
    ]

    assert len(conditional) == 2

    segments = [
        (
            ast.get_source_segment(
                source,
                call,
            )
            or ""
        )
        for call in conditional
    ]

    assert (
        sum(
            (
                "workflow_transition_not_allowed"
                in segment
            )
            for segment in segments
        )
        == 1
    )

    assert (
        sum(
            (
                '"cross_tenant"'
                in segment
            )
            for segment in segments
        )
        == 1
    )


@pytest.mark.parametrize(
    (
        "path",
        "class_name",
        "method_name",
        "emitter_name",
    ),
    STORE_CONFIGURATIONS,
)
def test_wrong_state_does_not_promote_lookup_correlation(
    path: Path,
    class_name: str | None,
    method_name: str,
    emitter_name: str,
):
    source, method = _store_method(
        path,
        class_name=class_name,
        method_name=method_name,
    )

    calls = _emitter_calls(
        method,
        emitter_name,
    )

    matching = [
        call
        for call in calls
        if (
            "workflow_transition_not_allowed"
            in (
                ast.get_source_segment(
                    source,
                    call,
                )
                or ""
            )
        )
    ]

    assert len(matching) == 1

    keywords = {
        item.arg
        for item in matching[0].keywords
    }

    assert (
        "workflow_id"
        not in keywords
    )

    assert (
        "tenant_id"
        not in keywords
    )

    assert (
        "execution_attempt_ref"
        not in keywords
    )


@pytest.mark.parametrize(
    (
        "path",
        "class_name",
        "method_name",
        "emitter_name",
    ),
    STORE_CONFIGURATIONS,
)
def test_missing_context_uses_authoritative_current_workflow(
    path: Path,
    class_name: str | None,
    method_name: str,
    emitter_name: str,
):
    source, method = _store_method(
        path,
        class_name=class_name,
        method_name=method_name,
    )

    matching = [
        call
        for call in _emitter_calls(
            method,
            emitter_name,
        )
        if (
            _literal_keyword(
                call,
                "reason",
            )
            == "security_binding_mismatch"
        )
    ]

    assert len(matching) == 1

    segment = (
        ast.get_source_segment(
            source,
            matching[0],
        )
        or ""
    )

    assert (
        "tenant_id=current.tenant_id"
        in segment
    )

    assert (
        "workflow_id=current.workflow_id"
        in segment
    )


@pytest.mark.parametrize(
    (
        "path",
        "class_name",
        "method_name",
        "emitter_name",
    ),
    STORE_CONFIGURATIONS,
)
def test_tenant_binding_denial_preserves_existing_exception(
    path: Path,
    class_name: str | None,
    method_name: str,
    emitter_name: str,
):
    source, method = _store_method(
        path,
        class_name=class_name,
        method_name=method_name,
    )

    handlers = [
        node
        for node in ast.walk(
            method
        )
        if (
            isinstance(
                node,
                ast.ExceptHandler,
            )
            and isinstance(
                node.type,
                ast.Name,
            )
            and node.type.id
            == "WorkflowTenantBindingError"
        )
    ]

    assert len(handlers) == 1

    segment = (
        ast.get_source_segment(
            source,
            handlers[0],
        )
        or ""
    )

    assert emitter_name in segment

    assert (
        '"cross_tenant"'
        in segment
    )

    assert (
        '"security_binding_mismatch"'
        in segment
    )

    assert (
        "tenant_id=canonical_tenant_id"
        in segment
    )

    assert (
        "workflow_id=current.workflow_id"
        in segment
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
            handlers[0]
        )
    )


@pytest.mark.parametrize(
    (
        "path",
        "class_name",
        "method_name",
        "emitter_name",
    ),
    STORE_CONFIGURATIONS,
)
def test_cas_loser_never_correlates_candidate_attempt(
    path: Path,
    class_name: str | None,
    method_name: str,
    emitter_name: str,
):
    source, method = _store_method(
        path,
        class_name=class_name,
        method_name=method_name,
    )

    matching = [
        call
        for call in _emitter_calls(
            method,
            emitter_name,
        )
        if (
            _literal_keyword(
                call,
                "reason",
            )
            == "execution_already_claimed"
        )
    ]

    assert len(matching) == 1

    segment = (
        ast.get_source_segment(
            source,
            matching[0],
        )
        or ""
    )

    assert (
        "tenant_id=current.tenant_id"
        in segment
    )

    assert (
        "workflow_id=current.workflow_id"
        in segment
    )

    assert (
        "execution_attempt_id"
        not in segment
    )

    assert (
        "execution_attempt_ref"
        not in segment
    )

    assert (
        "claimed.execution_attempt_id"
        not in segment
    )


def test_unknown_sqlite_workflow_is_not_promoted_to_canonical_correlation():
    _, method = _store_method(
        SQLITE_PATH,
        class_name=None,
        method_name=(
            "_sqlite_claim_workflow_for_execution"
        ),
    )

    key_errors = [
        node
        for node in ast.walk(
            method
        )
        if (
            isinstance(
                node,
                ast.Raise,
            )
            and isinstance(
                node.exc,
                ast.Call,
            )
            and isinstance(
                node.exc.func,
                ast.Name,
            )
            and node.exc.func.id
            == "KeyError"
        )
    ]

    emitters = _emitter_calls(
        method,
        (
            "emit_sqlite_workflow_execution_"
            "claim_denied_security_event"
        ),
    )

    assert len(key_errors) == 1
    assert emitters

    assert (
        key_errors[0].lineno
        < min(
            call.lineno
            for call in emitters
        )
    )


@pytest.mark.parametrize(
    (
        "path",
        "required_values",
    ),
    (
        (
            SQLITE_PATH,
            (
                "BEGIN IMMEDIATE",
                "cursor.rowcount != 1",
                "require_workflow_tenant(",
            ),
        ),
        (
            POSTGRESQL_PATH,
            (
                "SELECT ... FOR UPDATE",
                "cursor.rowcount != 1",
                "require_workflow_tenant(",
            ),
        ),
    ),
)
def test_existing_claim_authority_gates_remain_present(
    path: Path,
    required_values: tuple[str, ...],
):
    source = _source(
        path
    )

    for value in required_values:
        assert value in source
