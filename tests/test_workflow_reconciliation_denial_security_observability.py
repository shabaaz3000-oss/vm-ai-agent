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

HELPER = (
    "emit_workflow_store_reconciliation_denied_security_event"
)


def _capture(
    monkeypatch: pytest.MonkeyPatch,
):
    events = []

    monkeypatch.setattr(
        integrations,
        "_emit_best_effort",
        lambda event:
            (
                events.append(
                    event
                )
                or True
            ),
    )

    return events


@pytest.mark.parametrize(
    "source",
    (
        "workflow_store",
        "workflow_postgresql_store",
    ),
)
def test_correlated_denial_uses_ea1_not_raw_attempt(
    monkeypatch,
    source,
):
    events = _capture(
        monkeypatch
    )

    assert (
        integrations
        .emit_workflow_store_reconciliation_denied_security_event(
            source_component=
                source,
            reason_code=
                "execution_attempt_mismatch",
            workflow_id=
                "WF-AUTH",
            tenant_id=
                "tenant-auth",
            execution_attempt_id=
                "EXEC-CURRENT",
        )
        is True
    )

    payload = (
        events[
            0
        ]
        .to_dict()
    )

    assert (
        payload["workflow_id"]
        == "WF-AUTH"
    )

    assert (
        payload["tenant_id"]
        == "tenant-auth"
    )

    assert (
        payload[
            "execution_attempt_ref"
        ].startswith(
            "EA1-"
        )
    )

    assert (
        "EXEC-CURRENT"
        not in str(
            payload
        )
    )

    assert (
        payload.get(
            "provider_correlation_id"
        )
        is None
    )


@pytest.mark.parametrize(
    "source",
    (
        "workflow_store",
        "workflow_postgresql_store",
    ),
)
def test_wrong_state_can_be_intentionally_uncorrelated(
    monkeypatch,
    source,
):
    events = _capture(
        monkeypatch
    )

    assert (
        integrations
        .emit_workflow_store_reconciliation_denied_security_event(
            source_component=
                source,
            reason_code=
                "workflow_transition_not_allowed",
        )
        is True
    )

    payload = (
        events[
            0
        ]
        .to_dict()
    )

    assert (
        payload.get(
            "workflow_id"
        )
        is None
    )

    assert (
        payload.get(
            "tenant_id"
        )
        is None
    )

    assert (
        payload.get(
            "execution_attempt_ref"
        )
        is None
    )

    assert (
        payload.get(
            "provider_correlation_id"
        )
        is None
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


def _container(
    tree,
    class_name,
):
    if class_name is None:
        return tree.body

    return next(
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
    ).body


@pytest.mark.parametrize(
    (
        "path",
        "class_name",
        "confirm",
        "retry",
    ),
    (
        (
            SQLITE_PATH,
            None,
            "_sqlite_confirm_reconciled_ticket_creation",
            "_sqlite_authorize_reconciled_retry",
        ),
        (
            POSTGRESQL_PATH,
            "PostgreSQLWorkflowStore",
            "confirm_reconciled_ticket_creation",
            "authorize_reconciled_retry",
        ),
    ),
)
def test_backends_have_symmetric_denial_wiring(
    path,
    class_name,
    confirm,
    retry,
):
    source = path.read_text(
        encoding="utf-8-sig"
    )

    tree = ast.parse(
        source,
        filename=str(
            path
        ),
    )

    container = _container(
        tree,
        class_name,
    )

    validator = next(
        node
        for node in container
        if (
            isinstance(
                node,
                ast.FunctionDef,
            )
            and node.name
            == "_validate_reconciliation_transition_target"
        )
    )

    validator_source = (
        ast.get_source_segment(
            source,
            validator,
        )
        or ""
    )

    assert (
        validator_source.count(
            HELPER
            + "("
        )
        == 5
    )

    assert (
        "except WorkflowTenantBindingError:"
        in validator_source
    )

    assert (
        '"cross_tenant"'
        in validator_source
    )

    assert (
        '"security_binding_mismatch"'
        in validator_source
    )

    assert (
        '"execution_attempt_mismatch"'
        in validator_source
    )


    for (
        name,
        expected,
    ) in (
        (
            confirm,
            3,
        ),
        (
            retry,
            2,
        ),
    ):

        method = next(
            node
            for node in container
            if (
                isinstance(
                    node,
                    ast.FunctionDef,
                )
                and node.name
                == name
            )
        )

        segment = (
            ast.get_source_segment(
                source,
                method,
            )
            or ""
        )

        assert (
            segment.count(
                HELPER
                + "("
            )
            == expected
        )

        assert (
            "provider_correlation_id"
            not in segment
        )


def test_no_telemetry_ea1_comes_from_expected_attempt():
    for path in (
        SQLITE_PATH,
        POSTGRESQL_PATH,
    ):

        source = path.read_text(
            encoding="utf-8-sig"
        )

        tree = ast.parse(
            source,
            filename=str(
                path
            ),
        )


        for node in ast.walk(
            tree
        ):

            if not (
                isinstance(
                    node,
                    ast.Call,
                )
                and _call_name(
                    node
                )
                == HELPER
            ):
                continue


            for keyword in node.keywords:

                if (
                    keyword.arg
                    != "execution_attempt_id"
                ):
                    continue


                value = (
                    ast.get_source_segment(
                        source,
                        keyword.value,
                    )
                    or ""
                )


                assert (
                    value
                    == "current.execution_attempt_id"
                )


def test_wrong_state_branch_does_not_copy_workflow_argument():
    configurations = (
        (
            SQLITE_PATH,
            None,
            (
                "_sqlite_confirm_reconciled_ticket_creation",
                "_sqlite_authorize_reconciled_retry",
            ),
        ),
        (
            POSTGRESQL_PATH,
            "PostgreSQLWorkflowStore",
            (
                "confirm_reconciled_ticket_creation",
                "authorize_reconciled_retry",
            ),
        ),
    )


    for (
        path,
        class_name,
        names,
    ) in configurations:

        source = path.read_text(
            encoding="utf-8-sig"
        )

        tree = ast.parse(
            source,
            filename=str(
                path
            ),
        )

        container = _container(
            tree,
            class_name,
        )


        for name in names:

            method = next(
                node
                for node in container
                if (
                    isinstance(
                        node,
                        ast.FunctionDef,
                    )
                    and node.name
                    == name
                )
            )


            branches = []


            for node in ast.walk(
                method
            ):

                if not isinstance(
                    node,
                    ast.If,
                ):
                    continue

                segment = (
                    ast.get_source_segment(
                        source,
                        node,
                    )
                    or ""
                )

                if (
                    "Only a NEEDS_REVIEW workflow can"
                    in segment
                ):

                    branches.append(
                        node
                    )


            assert len(
                branches
            ) == 1


            calls = [
                node
                for node in ast.walk(
                    branches[
                        0
                    ]
                )
                if (
                    isinstance(
                        node,
                        ast.Call,
                    )
                    and _call_name(
                        node
                    )
                    == HELPER
                )
            ]


            assert len(
                calls
            ) == 1


            keyword_names = {
                keyword.arg
                for keyword in calls[
                    0
                ].keywords
            }


            assert (
                "workflow_id"
                not in keyword_names
            )

            assert (
                "tenant_id"
                not in keyword_names
            )

            assert (
                "execution_attempt_id"
                not in keyword_names
            )


def test_generic_workflow_stores_do_not_build_servicenow_correlation():
    for path in (
        SQLITE_PATH,
        POSTGRESQL_PATH,
    ):

        source = path.read_text(
            encoding="utf-8-sig"
        )

        assert (
            "build_servicenow_correlation_id"
            not in source
        )


def test_adapter_has_no_provider_correlation_parameter():
    source = Path(
        "app/security_observability_integrations.py"
    ).read_text(
        encoding="utf-8-sig"
    )

    tree = ast.parse(
        source
    )

    function = next(
        node
        for node in tree.body
        if (
            isinstance(
                node,
                ast.FunctionDef,
            )
            and node.name
            == HELPER
        )
    )

    parameters = {
        argument.arg
        for argument in (
            list(
                function.args.args
            )
            + list(
                function.args.kwonlyargs
            )
        )
    }

    assert (
        "provider_correlation_id"
        not in parameters
    )
