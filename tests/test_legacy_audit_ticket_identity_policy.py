from __future__ import annotations

import ast
from pathlib import Path

from app.security_observability import (
    SecurityEvent,
)


_EXPECTED_TICKET_AUDIT_SITES = {
    (
        "app/execution.py",
        "MOCK_TICKET_CREATED",
        'created_ticket["ticket_id"]',
    ),

    (
        "app/tools/ticketing.py",
        "TOOL_EXECUTED",
        "result.ticket_id",
    ),
}


def _normalize_expression(
    expression: str,
) -> str:
    return "".join(
        expression.split()
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


def _legacy_ticket_id_records():
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


            if (
                _call_name(
                    node
                )
                != "log_event"
            ):
                continue


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


            if not (
                isinstance(
                    node.args[
                        0
                    ],
                    ast.Constant,
                )
                and isinstance(
                    node.args[
                        0
                    ].value,
                    str,
                )
            ):
                continue


            event_name = (
                node.args[
                    0
                ].value
            )


            for key, value in zip(
                node.args[
                    1
                ].keys,
                node.args[
                    1
                ].values,
            ):

                if not (
                    isinstance(
                        key,
                        ast.Constant,
                    )
                    and key.value
                    == "ticket_id"
                ):
                    continue


                expression = (
                    ast.get_source_segment(
                        source,
                        value,
                    )
                    or ""
                )


                records.append(
                    (
                        path.as_posix(),
                        event_name,
                        _normalize_expression(
                            expression
                        ),
                    )
                )


    return records


def test_ticket_identity_remains_legacy_audit_only():
    annotations = (
        SecurityEvent
        .__annotations__
    )


    assert (
        "provider_correlation_id"
        in annotations
    )


    for field in (
        "ticket_id",
        "ticket_number",
        "external_sys_id",
        "sys_id",
    ):

        assert (
            field
            not in annotations
        ), field


def test_exact_two_trusted_ticket_identity_audit_sites():
    records = (
        _legacy_ticket_id_records()
    )


    assert len(
        records
    ) == 2


    assert set(
        records
    ) == _EXPECTED_TICKET_AUDIT_SITES


def test_mock_ticket_created_uses_provider_selector_return():
    path = Path(
        "app/execution.py"
    )

    source = path.read_text(
        encoding="utf-8-sig"
    )

    tree = ast.parse(
        source,
        filename=str(
            path
        ),
    )


    workflow_function = next(
        node
        for node in tree.body
        if (
            isinstance(
                node,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                ),
            )
            and node.name
            == "_execute_ticket_bound_workflow"
        )
    )


    assignments = []


    for node in ast.walk(
        workflow_function
    ):

        if not isinstance(
            node,
            ast.Assign,
        ):
            continue


        if not any(
            (
                isinstance(
                    target,
                    ast.Name,
                )
                and target.id
                == "created_ticket"
            )
            for target in node.targets
        ):
            continue


        assert isinstance(
            node.value,
            ast.Call,
        )

        assert isinstance(
            node.value.func,
            ast.Name,
        )

        assignments.append(
            (
                node.value.func.id,
                {
                    keyword.arg:
                        (
                            ast.get_source_segment(
                                source,
                                keyword.value,
                            )
                            or ""
                        )
                    for keyword
                    in node.value.keywords
                },
            )
        )


    assert len(
        assignments
    ) == 2


    for (
        producer,
        keywords,
    ) in assignments:

        assert (
            producer
            == "_create_ticket_with_selected_provider"
        )

        assert (
            keywords[
                "ticket"
            ]
            == "ticket"
        )

        assert (
            keywords[
                "approval"
            ]
            == "approval_record"
        )


def test_provider_selector_has_no_ticket_id_input():
    path = Path(
        "app/execution.py"
    )

    source = path.read_text(
        encoding="utf-8-sig"
    )

    tree = ast.parse(
        source,
        filename=str(
            path
        ),
    )


    selector = next(
        node
        for node in tree.body
        if (
            isinstance(
                node,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                ),
            )
            and node.name
            == "_create_ticket_with_selected_provider"
        )
    )


    parameters = {
        argument.arg
        for argument
        in (
            selector.args.args
            + selector.args.kwonlyargs
        )
    }


    assert (
        "ticket_id"
        not in parameters
    )


    return_calls = []


    for node in ast.walk(
        selector
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


        call = (
            node.value
        )


        assert isinstance(
            call.func,
            ast.Attribute,
        )

        assert (
            call.func.attr
            == "create_ticket"
        )


        return_calls.append(
            call
        )


    assert len(
        return_calls
    ) == 2


def test_mock_audit_and_workflow_result_share_created_ticket_id():
    path = Path(
        "app/execution.py"
    )

    source = path.read_text(
        encoding="utf-8-sig"
    )

    tree = ast.parse(
        source,
        filename=str(
            path
        ),
    )


    workflow_function = next(
        node
        for node in tree.body
        if (
            isinstance(
                node,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                ),
            )
            and node.name
            == "_execute_ticket_bound_workflow"
        )
    )


    audit_expression = None

    workflow_expression = None


    for node in ast.walk(
        workflow_function
    ):

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
            == "log_event"
            and node.args
            and isinstance(
                node.args[
                    0
                ],
                ast.Constant,
            )
            and node.args[
                0
            ].value
            == "MOCK_TICKET_CREATED"
        ):

            details = (
                node.args[
                    1
                ]
            )


            assert isinstance(
                details,
                ast.Dict,
            )


            for key, value in zip(
                details.keys,
                details.values,
            ):

                if (
                    isinstance(
                        key,
                        ast.Constant,
                    )
                    and key.value
                    == "ticket_id"
                ):

                    audit_expression = (
                        _normalize_expression(
                            ast.get_source_segment(
                                source,
                                value,
                            )
                            or ""
                        )
                    )


        if (
            isinstance(
                node,
                ast.Call,
            )
            and isinstance(
                node.func,
                ast.Attribute,
            )
            and node.func.attr
            == "update"
            and node.args
            and isinstance(
                node.args[
                    0
                ],
                ast.Dict,
            )
        ):

            for key, value in zip(
                node.args[
                    0
                ].keys,
                node.args[
                    0
                ].values,
            ):

                if (
                    isinstance(
                        key,
                        ast.Constant,
                    )
                    and key.value
                    == "ticket_id"
                ):

                    workflow_expression = (
                        _normalize_expression(
                            ast.get_source_segment(
                                source,
                                value,
                            )
                            or ""
                        )
                    )


    assert (
        audit_expression
        == 'created_ticket["ticket_id"]'
    )

    assert (
        workflow_expression
        == 'created_ticket["ticket_id"]'
    )


def test_tool_execution_uses_authoritative_workflow_result_ticket_id():
    records = (
        _legacy_ticket_id_records()
    )


    target = next(
        record
        for record in records
        if (
            record[
                0
            ]
            == "app/tools/ticketing.py"
            and record[
                1
            ]
            == "TOOL_EXECUTED"
        )
    )


    assert (
        target[
            2
        ]
        == "result.ticket_id"
    )


def test_servicenow_ticket_identity_comes_from_provider_response():
    path = Path(
        "app/providers/servicenow_ticket_provider.py"
    )

    source = path.read_text(
        encoding="utf-8-sig"
    )

    tree = ast.parse(
        source,
        filename=str(
            path
        ),
    )


    provider_class = next(
        node
        for node in tree.body
        if (
            isinstance(
                node,
                ast.ClassDef,
            )
            and node.name
            == "ServiceNowTicketProvider"
        )
    )


    function = next(
        node
        for node in provider_class.body
        if (
            isinstance(
                node,
                ast.FunctionDef,
            )
            and node.name
            == "create_ticket"
        )
    )


    returns = [
        node
        for node in ast.walk(
            function
        )
        if (
            isinstance(
                node,
                ast.Return,
            )
            and isinstance(
                node.value,
                ast.Dict,
            )
        )
    ]


    assert len(
        returns
    ) == 1


    mapping = {}


    for key, value in zip(
        returns[
            0
        ].value.keys,
        returns[
            0
        ].value.values,
    ):

        if (
            isinstance(
                key,
                ast.Constant,
            )
            and isinstance(
                key.value,
                str,
            )
        ):

            mapping[
                key.value
            ] = (
                ast.get_source_segment(
                    source,
                    value,
                )
                or ""
            )


    assert (
        mapping[
            "ticket_id"
        ]
        == 'result["number"]'
    )

    assert (
        mapping[
            "external_sys_id"
        ]
        == 'result["sys_id"]'
    )


def test_provider_correlation_is_not_ticket_identity():
    annotations = (
        SecurityEvent
        .__annotations__
    )


    assert (
        "provider_correlation_id"
        in annotations
    )

    assert (
        "ticket_id"
        not in annotations
    )


def test_repository_does_not_invent_ticket_reference_builder():
    forbidden = {
        "build_ticket_ref",
        "build_ticket_reference",
        "build_ticket_id_ref",
    }


    findings = []


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

            if (
                isinstance(
                    node,
                    (
                        ast.FunctionDef,
                        ast.AsyncFunctionDef,
                    ),
                )
                and node.name
                in forbidden
            ):

                findings.append(
                    (
                        path,
                        node.lineno,
                        node.name,
                    )
                )


    assert not findings
