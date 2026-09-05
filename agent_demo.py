import os

from dotenv import load_dotenv

from app.agent import run_agent

from app.audit_trace import (
    build_agent_trace,
    get_audit_offset,
    read_audit_events_from_offset,
)

from app.auth import authenticate_token


# -------------------------------------------------
# ENVIRONMENT
# -------------------------------------------------


load_dotenv()


# -------------------------------------------------
# DEMO
# -------------------------------------------------


def main():

    # -------------------------------------------------
    # 1. USE REAL APPLICATION AUTHENTICATION
    # -------------------------------------------------

    analyst_token = os.getenv(
        "VM_AI_ANALYST_TOKEN"
    )

    if not analyst_token:

        raise RuntimeError(
            "VM_AI_ANALYST_TOKEN "
            "is not configured."
        )

    principal = authenticate_token(
        analyst_token
    )

    # -------------------------------------------------
    # 2. CAPTURE AUDIT START POSITION
    # -------------------------------------------------

    audit_offset = (
        get_audit_offset()
    )

    # -------------------------------------------------
    # 3. RUN READ-ONLY AGENT
    # -------------------------------------------------

    result = run_agent(
        principal=principal,

        user_request=(
            "Investigate the current demo "
            "vulnerability. Use the available "
            "security tools to gather the facts. "
            "Use security reference knowledge "
            "if it would improve the assessment. "
            "Provide the authoritative risk, "
            "recommended remediation, and "
            "validation guidance."
        ),
    )

    # -------------------------------------------------
    # 4. READ ONLY EVENTS FROM THIS RUN
    # -------------------------------------------------

    audit_events = (
        read_audit_events_from_offset(
            audit_offset
        )
    )

    trace = build_agent_trace(
        audit_events
    )

    # -------------------------------------------------
    # 5. DISPLAY TOOL TRACE
    # -------------------------------------------------

    print()
    print("=" * 70)
    print("AGENT TOOL TRACE")
    print("=" * 70)
    print()

    if trace:

        for line in trace:

            print(line)

    else:

        print(
            "No agent audit events found."
        )

    # -------------------------------------------------
    # 6. DISPLAY FINAL AGENT RESPONSE
    # -------------------------------------------------

    print()
    print("=" * 70)
    print("VM AI AGENT RESULT")
    print("=" * 70)
    print()

    print(result)

    print()
    print("=" * 70)


# -------------------------------------------------
# ENTRY POINT
# -------------------------------------------------


if __name__ == "__main__":

    main()