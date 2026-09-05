import json

import pytest

from app import audit_trace


# -------------------------------------------------
# MISSING AUDIT FILE HAS ZERO OFFSET
# -------------------------------------------------


def test_missing_audit_file_has_zero_offset(
    monkeypatch,
    tmp_path,
):

    audit_file = (
        tmp_path
        / "audit.jsonl"
    )

    monkeypatch.setattr(
        audit_trace,
        "AUDIT_FILE",
        audit_file,
    )

    assert (
        audit_trace.get_audit_offset()
        == 0
    )


# -------------------------------------------------
# READ ONLY EVENTS AFTER OFFSET
# -------------------------------------------------


def test_read_events_from_offset(
    monkeypatch,
    tmp_path,
):

    audit_file = (
        tmp_path
        / "audit.jsonl"
    )

    monkeypatch.setattr(
        audit_trace,
        "AUDIT_FILE",
        audit_file,
    )

    first_record = {
        "event_type":
            "OLD_EVENT",

        "details":
            {},
    }

    with open(
        audit_file,
        "wb",
    ) as file:

        file.write(
            (
                json.dumps(
                    first_record
                )
                + "\n"
            ).encode(
                "utf-8"
            )
        )

    offset = (
        audit_trace
        .get_audit_offset()
    )

    new_records = [
        {
            "event_type":
                "TOOL_EXECUTED",

            "details": {
                "tool":
                    "get_finding",
            },
        },

        {
            "event_type":
                "AGENT_COMPLETED",

            "details": {
                "tool_steps":
                    1,

                "knowledge_used":
                    False,
            },
        },
    ]

    with open(
        audit_file,
        "ab",
    ) as file:

        for record in new_records:

            file.write(
                (
                    json.dumps(
                        record
                    )
                    + "\n"
                ).encode(
                    "utf-8"
                )
            )

    result = (
        audit_trace
        .read_audit_events_from_offset(
            offset
        )
    )

    assert result == new_records


# -------------------------------------------------
# NEGATIVE OFFSET IS REJECTED
# -------------------------------------------------


def test_negative_offset_is_rejected():

    with pytest.raises(
        ValueError
    ):

        audit_trace.read_audit_events_from_offset(
            -1
        )


# -------------------------------------------------
# TRACE PRESERVES TOOL ORDER
# -------------------------------------------------


def test_trace_preserves_tool_order():

    events = [
        {
            "event_type":
                "TOOL_EXECUTED",

            "details": {
                "tool":
                    "get_finding",
            },
        },

        {
            "event_type":
                "TOOL_EXECUTED",

            "details": {
                "tool":
                    "get_asset_details",
            },
        },

        {
            "event_type":
                "AGENT_AUTHORITATIVE_RISK_CALCULATED",

            "details": {
                "rating":
                    "CRITICAL",

                "score":
                    100,

                "sla_hours":
                    24,
            },
        },

        {
            "event_type":
                "AGENT_COMPLETED",

            "details": {
                "tool_steps":
                    2,

                "knowledge_used":
                    False,
            },
        },
    ]

    trace = (
        audit_trace
        .build_agent_trace(
            events
        )
    )

    assert (
        trace[0]
        == "1. get_finding — executed"
    )

    assert (
        trace[1]
        == "2. get_asset_details — executed"
    )

    assert (
        "CRITICAL / 100 / 24h SLA"
        in trace[2]
    )


# -------------------------------------------------
# KNOWLEDGE TRACE SHOWS RAG COUNTS
# -------------------------------------------------


def test_trace_shows_rag_counts():

    events = [
        {
            "event_type":
                "TOOL_EXECUTED",

            "details": {
                "tool":
                    "search_knowledge",

                "retrieved_count":
                    2,

                "result_count":
                    1,
            },
        },
    ]

    trace = (
        audit_trace
        .build_agent_trace(
            events
        )
    )

    assert (
        "1. search_knowledge — executed"
        in trace
    )

    assert (
        "   RAG evidence: "
        "2 retrieved, 1 safe"
        in trace
    )