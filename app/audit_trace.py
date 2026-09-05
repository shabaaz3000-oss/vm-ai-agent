import json

from app.audit import AUDIT_FILE


# -------------------------------------------------
# CURRENT AUDIT FILE OFFSET
# -------------------------------------------------


def get_audit_offset() -> int:

    if not AUDIT_FILE.exists():

        return 0

    return AUDIT_FILE.stat().st_size


# -------------------------------------------------
# READ NEW AUDIT EVENTS
# -------------------------------------------------


def read_audit_events_from_offset(
    offset: int,
) -> list[dict]:

    if offset < 0:

        raise ValueError(
            "Audit offset cannot be negative."
        )

    if not AUDIT_FILE.exists():

        return []

    file_size = (
        AUDIT_FILE.stat().st_size
    )

    if offset > file_size:

        raise ValueError(
            "Audit offset is beyond "
            "the end of the audit file."
        )

    events = []

    # Binary mode allows us to safely use
    # the byte offset returned by stat().
    with open(
        AUDIT_FILE,
        "rb",
    ) as file:

        file.seek(
            offset
        )

        for raw_line in file:

            if not raw_line.strip():

                continue

            try:

                decoded = (
                    raw_line.decode(
                        "utf-8"
                    )
                )

                record = json.loads(
                    decoded
                )

            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
            ) as error:

                raise ValueError(
                    "Audit log contains "
                    "a malformed record."
                ) from error

            events.append(
                record
            )

    return events


# -------------------------------------------------
# BUILD HUMAN-READABLE AGENT TRACE
# -------------------------------------------------


def build_agent_trace(
    events: list[dict],
) -> list[str]:

    lines = []

    tool_step = 0

    for record in events:

        event_type = (
            record.get(
                "event_type"
            )
        )

        details = (
            record.get(
                "details",
                {},
            )
        )

        # -------------------------------------------------
        # TOOL EXECUTION
        # -------------------------------------------------

        if (
            event_type
            == "TOOL_EXECUTED"
        ):

            tool_step += 1

            tool_name = (
                details.get(
                    "tool",
                    "unknown",
                )
            )

            lines.append(
                f"{tool_step}. "
                f"{tool_name} "
                f"— executed"
            )

            if (
                tool_name
                == "search_knowledge"
            ):

                retrieved_count = (
                    details.get(
                        "retrieved_count"
                    )
                )

                result_count = (
                    details.get(
                        "result_count"
                    )
                )

                if (
                    retrieved_count
                    is not None
                    and result_count
                    is not None
                ):

                    lines.append(
                        "   RAG evidence: "
                        f"{retrieved_count} "
                        "retrieved, "
                        f"{result_count} "
                        "safe"
                    )

        # -------------------------------------------------
        # AUTHORITATIVE RISK
        # -------------------------------------------------

        elif (
            event_type
            == "AGENT_AUTHORITATIVE_RISK_CALCULATED"
        ):

            lines.append(
                "   Authoritative risk: "
                f"{details.get('rating')} / "
                f"{details.get('score')} / "
                f"{details.get('sla_hours')}h SLA"
            )

        # -------------------------------------------------
        # RAG QUARANTINE
        # -------------------------------------------------

        elif (
            event_type
            == "TOOL_RAG_EVIDENCE_QUARANTINED"
        ):

            quarantined = (
                details.get(
                    "quarantined_chunk_ids",
                    [],
                )
            )

            lines.append(
                "   RAG quarantine: "
                f"{len(quarantined)} "
                "suspicious chunk(s)"
            )

        # -------------------------------------------------
        # TOOL OUTPUT PROMPT INJECTION
        # -------------------------------------------------

        elif (
            event_type
            == "AGENT_TOOL_PROMPT_INJECTION_SUSPECTED"
        ):

            lines.append(
                "   SECURITY: "
                "prompt-injection-like "
                "content detected in "
                "tool output"
            )

        # -------------------------------------------------
        # BLOCKED TOOL
        # -------------------------------------------------

        elif (
            event_type
            == "AGENT_TOOL_BLOCKED"
        ):

            lines.append(
                "   BLOCKED: "
                f"{details.get('tool')} — "
                f"{details.get('reason')}"
            )

        # -------------------------------------------------
        # AGENT COMPLETE
        # -------------------------------------------------

        elif (
            event_type
            == "AGENT_COMPLETED"
        ):

            lines.append(
                "Agent completed — "
                f"{details.get('tool_steps')} "
                "tool step(s), "
                "knowledge used: "
                f"{details.get('knowledge_used')}"
            )

    return lines