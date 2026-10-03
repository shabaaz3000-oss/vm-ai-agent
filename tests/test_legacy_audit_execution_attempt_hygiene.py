from __future__ import annotations

import ast
from pathlib import Path

from app.legacy_audit_hygiene import (
    build_legacy_execution_attempt_audit_fields,
)
from app.security_observability_correlation import (
    build_execution_attempt_ref,
)


_TARGETS = {
    "SERVICENOW_RECONCILIATION_RESOLVED":
        (
            Path(
                "app/api.py"
            ),
            {
                "tenant_id":
                    "trusted_context.tenant_id",

                "workflow_id":
                    "resolved.workflow_id",

                "execution_attempt_id":
                    "resolved.execution_attempt_id",
            },
        ),

    "TICKET_APPROVED":
        (
            Path(
                "app/execution.py"
            ),
            {
                "tenant_id":
                    "result.tenant_id",

                "workflow_id":
                    "result.workflow_id",

                "execution_attempt_id":
                    "result.execution_attempt_id",
            },
        ),

    "TICKET_EXECUTION_BLOCKED":
        (
            Path(
                "app/execution.py"
            ),
            {
                "tenant_id":
                    "result.tenant_id",

                "workflow_id":
                    "result.workflow_id",

                "execution_attempt_id":
                    "result.execution_attempt_id",
            },
        ),

    "MOCK_TICKET_CREATED":
        (
            Path(
                "app/execution.py"
            ),
            {
                "tenant_id":
                    "result.tenant_id",

                "workflow_id":
                    "result.workflow_id",

                "execution_attempt_id":
                    "result.execution_attempt_id",
            },
        ),

    "WORKFLOW_EXECUTION_CLAIMED":
        (
            Path(
                "app/execution.py"
            ),
            {
                "tenant_id":
                    "claimed_result.tenant_id",

                "workflow_id":
                    "claimed_result.workflow_id",

                "execution_attempt_id":
                    "claimed_result.execution_attempt_id",
            },
        ),

    "WORKFLOW_RECOVERY_MARK_FAILED":
        (
            Path(
                "app/execution.py"
            ),
            {
                "tenant_id":
                    "claimed_result.tenant_id",

                "workflow_id":
                    "claimed_result.workflow_id",

                "execution_attempt_id":
                    "claimed_result.execution_attempt_id",
            },
        ),

    "WORKFLOW_EXECUTION_NEEDS_REVIEW":
        (
            Path(
                "app/execution.py"
            ),
            {
                "tenant_id":
                    "review_result.tenant_id",

                "workflow_id":
                    "review_result.workflow_id",

                "execution_attempt_id":
                    "review_result.execution_attempt_id",
            },
        ),

    "STALE_WORKFLOW_NEEDS_REVIEW":
        (
            Path(
                "app/execution.py"
            ),
            {
                "tenant_id":
                    "result.tenant_id",

                "workflow_id":
                    "result.workflow_id",

                "execution_attempt_id":
                    "result.execution_attempt_id",
            },
        ),
}


def _log_event_records():
    records = []


    for path in Path(
        "app"
    ).rglob(
        "*.py"
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

            if not isinstance(
                node,
                ast.Call,
            ):
                continue


            called = None


            if isinstance(
                node.func,
                ast.Name,
            ):
                called = (
                    node.func.id
                )

            elif isinstance(
                node.func,
                ast.Attribute,
            ):
                called = (
                    node.func.attr
                )


            if called != "log_event":
                continue


            records.append(
                (
                    path,
                    source,
                    node,
                )
            )


    return records


def test_authoritative_tuple_produces_ea1_only():
    raw_attempt = (
        "EXEC-ABCDEF12"
    )


    fields = (
        build_legacy_execution_attempt_audit_fields(
            tenant_id=
                "tenant-alpha",

            workflow_id=
                "WF-1234ABCD",

            execution_attempt_id=
                raw_attempt,
        )
    )


    assert set(
        fields
    ) == {
        "execution_attempt_ref",
    }


    expected = (
        build_execution_attempt_ref(
            tenant_id=
                "tenant-alpha",

            workflow_id=
                "WF-1234ABCD",

            execution_attempt_id=
                raw_attempt,
        )
    )


    assert (
        fields[
            "execution_attempt_ref"
        ]
        == expected
    )


    assert (
        fields[
            "execution_attempt_ref"
        ].startswith(
            "EA1-"
        )
    )


    assert (
        raw_attempt
        not in fields[
            "execution_attempt_ref"
        ]
    )


def test_missing_tenant_omits_attempt_correlation():
    assert (
        build_legacy_execution_attempt_audit_fields(
            tenant_id=None,

            workflow_id=
                "WF-1234ABCD",

            execution_attempt_id=
                "EXEC-ABCDEF12",
        )
        == {}
    )


def test_missing_attempt_omits_attempt_correlation():
    assert (
        build_legacy_execution_attempt_audit_fields(
            tenant_id=
                "tenant-alpha",

            workflow_id=
                "WF-1234ABCD",

            execution_attempt_id=None,
        )
        == {}
    )


def test_invalid_optional_correlation_does_not_break_workflow_path():
    assert (
        build_legacy_execution_attempt_audit_fields(
            tenant_id=
                "tenant-alpha",

            workflow_id=
                "WF-1234ABCD",

            execution_attempt_id=
                "EXEC-\nSECRET",
        )
        == {}
    )


def test_no_legacy_log_event_persists_raw_execution_attempt():
    findings = []


    for (
        path,
        _,
        node,
    ) in _log_event_records():

        if (
            len(
                node.args
            )
            < 2
            or not isinstance(
                node.args[
                    1
                ],
                ast.Dict,
            )
        ):
            continue


        for key in node.args[
            1
        ].keys:

            if (
                isinstance(
                    key,
                    ast.Constant,
                )
                and key.value
                == "execution_attempt_id"
            ):

                findings.append(
                    (
                        path,
                        node.lineno,
                    )
                )


    assert not findings


def test_exact_eight_events_use_expected_trusted_sources():
    observed = {}


    for (
        path,
        source,
        node,
    ) in _log_event_records():

        if not node.args:
            continue


        first = (
            node.args[
                0
            ]
        )


        if not (
            isinstance(
                first,
                ast.Constant,
            )
            and isinstance(
                first.value,
                str,
            )
        ):
            continue


        event_name = (
            first.value
        )


        if (
            event_name
            not in _TARGETS
        ):
            continue


        expected_path, expected_keywords = (
            _TARGETS[
                event_name
            ]
        )


        assert path == expected_path


        details = (
            node.args[
                1
            ]
        )


        assert isinstance(
            details,
            ast.Dict,
        )


        helper_calls = []


        for key, value in zip(
            details.keys,
            details.values,
        ):

            if (
                key is None
                and isinstance(
                    value,
                    ast.Call,
                )
                and isinstance(
                    value.func,
                    ast.Name,
                )
                and value.func.id
                == (
                    "build_legacy_execution_attempt_audit_fields"
                )
            ):

                helper_calls.append(
                    value
                )


        assert len(
            helper_calls
        ) == 1


        keywords = {
            keyword.arg:
                (
                    ast.get_source_segment(
                        source,
                        keyword.value,
                    )
                    or ""
                )
            for keyword
            in helper_calls[
                0
            ].keywords
        }


        assert (
            keywords
            == expected_keywords
        )


        observed[
            event_name
        ] = keywords


    assert (
        set(
            observed
        )
        == set(
            _TARGETS
        )
    )


def test_servicenow_does_not_use_caller_path_workflow_for_ea1():
    _, expected = (
        _TARGETS[
            "SERVICENOW_RECONCILIATION_RESOLVED"
        ]
    )


    assert (
        expected[
            "tenant_id"
        ]
        == "trusted_context.tenant_id"
    )

    assert (
        expected[
            "workflow_id"
        ]
        == "resolved.workflow_id"
    )

    assert (
        expected[
            "workflow_id"
        ]
        != "workflow_id"
    )


def test_raw_execution_authority_remains_in_store_code():
    sources = "\n".join(
        (
            Path(
                "app/workflow_store.py"
            ).read_text(
                encoding="utf-8-sig"
            ),

            Path(
                "app/workflow_postgresql_store.py"
            ).read_text(
                encoding="utf-8-sig"
            ),
        )
    )


    assert (
        "expected_execution_attempt_id"
        in sources
    )

    assert (
        "current.execution_attempt_id"
        in sources
    )

    assert (
        "build_legacy_execution_attempt_audit_fields"
        not in sources
    )


def test_unexpected_correlation_failure_is_not_suppressed(
    monkeypatch,
):
    import app.legacy_audit_hygiene as hygiene


    def unexpected_failure(
        **kwargs,
    ):
        raise RuntimeError(
            "unexpected implementation failure"
        )


    monkeypatch.setattr(
        hygiene,
        "build_execution_attempt_ref",
        unexpected_failure,
    )


    try:

        hygiene.build_legacy_execution_attempt_audit_fields(
            tenant_id=
                "tenant-alpha",

            workflow_id=
                "WF-1234ABCD",

            execution_attempt_id=
                "EXEC-ABCDEF12",
        )

    except RuntimeError as error:

        assert (
            str(
                error
            )
            == "unexpected implementation failure"
        )

    else:

        raise AssertionError(
            "Unexpected correlation failure was suppressed."
        )
