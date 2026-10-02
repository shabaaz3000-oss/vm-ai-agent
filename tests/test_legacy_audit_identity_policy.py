from __future__ import annotations

import ast
from pathlib import Path

from app.security_observability import (
    SecurityEvent,
)


_RAW_IDENTITY_FIELDS = {
    "username",
    "principal_id",
    "actor_principal_id",
    "target_principal_id",
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

            else:

                continue


            if called != "log_event":

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


            event_name = None


            if (
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

                event_name = (
                    node.args[
                        0
                    ].value
                )


            mapping = {}


            for key, value in zip(
                node.args[
                    1
                ].keys,
                node.args[
                    1
                ].values,
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
                        value
                    )


            records.append(
                (
                    path,
                    source,
                    node,
                    event_name,
                    mapping,
                )
            )


    return records


def _source_expression(
    source: str,
    node: ast.AST,
) -> str:
    return (
        ast.get_source_segment(
            source,
            node,
        )
        or ""
    )


def test_canonical_security_event_excludes_raw_identity():
    annotations = (
        SecurityEvent
        .__annotations__
    )


    assert (
        "principal_ref"
        in annotations
    )


    for field in (
        _RAW_IDENTITY_FIELDS
    ):

        assert (
            field
            not in annotations
        ), field


def test_repository_does_not_invent_principal_ref_derivation():
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
                == "build_principal_ref"
            ):

                findings.append(
                    (
                        path,
                        node.lineno,
                    )
                )


    assert not findings


def test_username_audit_identity_comes_from_principal_object():
    observed = []


    for (
        path,
        source,
        node,
        event_name,
        mapping,
    ) in _log_event_records():

        if (
            "username"
            not in mapping
        ):

            continue


        expression = (
            _source_expression(
                source,
                mapping[
                    "username"
                ],
            )
        )


        observed.append(
            (
                path,
                node.lineno,
                event_name,
                expression,
            )
        )


        assert (
            expression
            == "principal.username"
        ), (
            path,
            node.lineno,
            event_name,
            expression,
        )


        # Role is not universally required for every legacy
        # username-bearing audit event. When role is present, its
        # provenance must remain the same trusted principal object.
        if (
            "role"
            in mapping
        ):

            role_expression = (
                _source_expression(
                    source,
                    mapping[
                        "role"
                    ],
                )
            )


            assert (
                role_expression
                == "principal.role"
            ), (
                path,
                node.lineno,
                event_name,
                role_expression,
            )


    assert observed


def test_mcp_principal_identity_has_tenant_and_session_correlation():
    path = Path(
        "app/mcp_session.py"
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


    observed = []


    for node in ast.walk(
        tree
    ):

        if not isinstance(
            node,
            ast.Call,
        ):

            continue


        if not (
            isinstance(
                node.func,
                ast.Name,
            )
            and node.func.id
            == "log_event"
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


        mapping = {}


        for key, value in zip(
            node.args[
                1
            ].keys,
            node.args[
                1
            ].values,
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
                ] = value


        if (
            "principal_id"
            not in mapping
        ):

            continue


        expression = (
            _source_expression(
                source,
                mapping[
                    "principal_id"
                ],
            )
        )


        assert (
            expression
            == "principal.username"
        )


        assert (
            "tenant_id"
            in mapping
        )


        assert (
            "session_correlation_id"
            in mapping
        )


        observed.append(
            node.lineno
        )


    assert observed


def test_mcp_actor_target_identity_preserves_accountability_context():
    path = Path(
        "app/mcp_session.py"
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


    observed = []


    for node in ast.walk(
        tree
    ):

        if not isinstance(
            node,
            ast.Call,
        ):

            continue


        if not (
            isinstance(
                node.func,
                ast.Name,
            )
            and node.func.id
            == "log_event"
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


        mapping = {}


        for key, value in zip(
            node.args[
                1
            ].keys,
            node.args[
                1
            ].values,
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
                ] = value


        identity = (
            set(
                mapping
            )
            & {
                "actor_principal_id",
                "target_principal_id",
            }
        )


        if not identity:

            continue


        assert identity == {
            "actor_principal_id",
            "target_principal_id",
        }


        actor_expression = (
            _source_expression(
                source,
                mapping[
                    "actor_principal_id"
                ],
            )
        )

        target_expression = (
            _source_expression(
                source,
                mapping[
                    "target_principal_id"
                ],
            )
        )


        assert (
            actor_expression
            == "actor.username"
        )

        assert (
            target_expression
            == "target_principal_id"
        )


        assert (
            "tenant_id"
            in mapping
        )

        assert (
            "actor_session_correlation_id"
            in mapping
        )


        observed.append(
            node.lineno
        )


    assert observed


def test_non_mcp_principal_id_audit_is_not_literal_identity():
    findings = []


    for (
        path,
        source,
        node,
        event_name,
        mapping,
    ) in _log_event_records():

        if (
            path.name
            == "mcp_session.py"
        ):

            continue


        if (
            "principal_id"
            not in mapping
        ):

            continue


        value = (
            mapping[
                "principal_id"
            ]
        )


        # A raw hard-coded identity literal in a production audit
        # call would violate the trusted-source requirement.
        assert not (
            isinstance(
                value,
                ast.Constant,
            )
            and isinstance(
                value.value,
                str,
            )
        ), (
            path,
            node.lineno,
            event_name,
        )


        expression = (
            _source_expression(
                source,
                value,
            )
        )


        assert (
            "principal"
            in expression.lower()
        ), (
            path,
            node.lineno,
            event_name,
            expression,
        )


        findings.append(
            (
                path,
                node.lineno,
                event_name,
                expression,
            )
        )


    # Current repository includes at least one non-MCP
    # principal-attributed audit path.
    assert findings


def test_raw_identity_remains_legacy_audit_only_not_canonical_schema():
    legacy_identity_records = []


    for (
        path,
        source,
        node,
        event_name,
        mapping,
    ) in _log_event_records():

        fields = (
            set(
                mapping
            )
            & _RAW_IDENTITY_FIELDS
        )


        if fields:

            legacy_identity_records.append(
                (
                    path,
                    node.lineno,
                    event_name,
                    fields,
                )
            )


    assert legacy_identity_records


    annotations = (
        SecurityEvent
        .__annotations__
    )


    assert not (
        _RAW_IDENTITY_FIELDS
        & set(
            annotations
        )
    )
