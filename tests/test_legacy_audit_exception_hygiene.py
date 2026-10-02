from __future__ import annotations

import ast
import json
from pathlib import Path

from app import audit


_TARGET_EVENTS = {
    "TICKET_EXECUTION_BLOCKED",
    "WORKFLOW_EXECUTION_CLAIM_BLOCKED",
}


def _legacy_log_event_payloads():
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


    records = {}


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


        if (
            event_name
            not in _TARGET_EVENTS
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


        records[
            event_name
        ] = (
            mapping
        )


    return records


def test_blocked_execution_audit_events_omit_free_form_message():
    records = (
        _legacy_log_event_payloads()
    )


    assert (
        set(
            records
        )
        == _TARGET_EVENTS
    )


    for (
        event_name,
        mapping,
    ) in records.items():

        assert (
            "message"
            not in mapping
        ), event_name

        assert (
            "error_message"
            not in mapping
        ), event_name

        assert (
            "exception_message"
            not in mapping
        ), event_name

        assert (
            "sanitized_message"
            not in mapping
        ), event_name


def test_blocked_execution_audit_events_preserve_bounded_error_type():
    records = (
        _legacy_log_event_payloads()
    )


    for (
        event_name,
        mapping,
    ) in records.items():

        assert (
            "error_type"
            in mapping
        ), event_name


        value = (
            mapping[
                "error_type"
            ]
        )


        assert isinstance(
            value,
            ast.Constant,
        ), event_name

        assert (
            value.value
            == "PermissionError"
        ), event_name


def test_execution_source_does_not_serialize_caught_error_text():
    source = Path(
        "app/execution.py"
    ).read_text(
        encoding="utf-8-sig"
    )


    tree = ast.parse(
        source
    )


    unsafe = []


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


        segment = (
            ast.get_source_segment(
                source,
                node,
            )
            or ""
        )


        if (
            "str(error)"
            in segment
        ):

            unsafe.append(
                node.lineno
            )


    assert not unsafe


def test_bounded_exception_audit_payload_does_not_persist_secret(
    monkeypatch,
    tmp_path,
):
    audit_file = (
        tmp_path
        / "audit.jsonl"
    )


    monkeypatch.setattr(
        audit,
        "AUDIT_FILE",
        audit_file,
    )


    secret = (
        "LEGACY-AUDIT-SECRET-MARKER"
    )


    try:

        raise PermissionError(
            "Authorization: Bearer "
            + secret
        )

    except PermissionError as error:

        # This mirrors the hardened legacy audit contract:
        # retain only bounded exception type metadata.
        audit.log_event(
            "WORKFLOW_EXECUTION_CLAIM_BLOCKED",
            {
                "workflow_id":
                    "WF-TEST",
                "error_type":
                    type(
                        error
                    ).__name__,
            },
        )


    raw = audit_file.read_text(
        encoding="utf-8"
    )


    assert (
        secret
        not in raw
    )

    assert (
        "Authorization: Bearer"
        not in raw
    )


    records = [
        json.loads(
            line
        )
        for line in raw.splitlines()
        if line.strip()
    ]


    assert len(
        records
    ) == 1


    details = (
        records[
            0
        ][
            "details"
        ]
    )


    assert (
        details[
            "error_type"
        ]
        == "PermissionError"
    )

    assert (
        "message"
        not in details
    )
