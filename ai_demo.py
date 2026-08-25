import json

from pydantic import ValidationError

from app.audit import log_event

from app.execution import (
    approve_and_execute_workflow,
    reject_workflow,
)

from app.workflow import prepare_workflow


# -------------------------------------------------
# DISPLAY SECURITY WARNING
# -------------------------------------------------


def display_security_warning(result):

    if not result.security.prompt_injection_detected:
        return

    print()
    print("=" * 70)
    print("SECURITY WARNING")
    print("=" * 70)

    print()
    print(
        "Potential prompt injection detected "
        "in vulnerability data."
    )

    print()
    print("Matched indicators:")

    for match in (
        result.security.prompt_injection_matches
    ):
        print("-", match)

    print()
    print(
        "The content will remain untrusted. "
        "Authoritative risk policy cannot be overridden."
    )


# -------------------------------------------------
# DISPLAY PREPARED WORKFLOW
# -------------------------------------------------


def display_prepared_workflow(result):

    risk = result.risk
    analysis = result.analysis
    ticket = result.ticket

    # -------------------------------------------------
    # AUTHORITATIVE RISK RESULT
    # -------------------------------------------------

    print()
    print("=" * 70)
    print("AUTHORITATIVE RISK RESULT")
    print("=" * 70)

    print()
    print("Workflow ID:", result.workflow_id)
    print("Asset:", result.asset_name)
    print("CVE:", result.cve)
    print("Risk Score:", risk.score)
    print("Risk Rating:", risk.rating)

    print(
        "Remediation SLA:",
        risk.sla_hours,
        "hours"
    )

    # -------------------------------------------------
    # AI SECURITY ANALYSIS
    # -------------------------------------------------

    print()
    print("=" * 70)
    print("AI SECURITY ANALYSIS")
    print("=" * 70)

    print()
    print("Executive Summary:")
    print(analysis.executive_summary)

    print()
    print("Rationale:")

    for item in analysis.rationale:
        print("-", item)

    print()
    print("Recommended Remediation:")
    print(analysis.remediation)

    print()
    print("Compensating Controls:")

    for control in analysis.compensating_controls:
        print("-", control)

    print()
    print("Validation Steps:")

    for step in analysis.validation_steps:
        print("-", step)

    print()
    print("AI Confidence:")
    print(analysis.confidence)

    print()
    print("Human Review Required:")
    print(analysis.requires_human_review)

    # -------------------------------------------------
    # VALIDATED TICKET DRAFT
    # -------------------------------------------------

    print()
    print("=" * 70)
    print("PROPOSED TICKET")
    print("=" * 70)

    print()
    print("Short Description:")
    print(ticket.short_description)

    print()
    print("Priority:")
    print(ticket.priority)

    print()
    print("Assignment Group:")
    print(ticket.assignment_group)

    print()
    print("Asset:")
    print(ticket.asset_name)

    print()
    print("CVE:")
    print(ticket.cve)

    print()
    print("Risk Rating:")
    print(ticket.risk_rating)

    print()
    print("Risk Score:")
    print(ticket.risk_score)

    print()
    print("SLA:")
    print(ticket.sla_hours, "hours")

    print()
    print("Description:")
    print(ticket.description)

    print()
    print("Remediation:")
    print(ticket.remediation)

    print()
    print("Validation Steps:")

    for step in ticket.validation_steps:
        print("-", step)


# -------------------------------------------------
# DISPLAY COMPLETED EXECUTION
# -------------------------------------------------


def display_created_ticket(result):

    print()
    print("=" * 70)
    print("MOCK TICKET CREATED")
    print("=" * 70)

    print()
    print(
        "Workflow ID:",
        result.workflow_id
    )

    print(
        "Ticket ID:",
        result.ticket_id
    )

    print(
        "Approval ID:",
        result.approval_id
    )

    print(
        "Status:",
        result.status
    )

    print(
        "Priority:",
        result.ticket.priority
    )

    print(
        "Risk Rating:",
        result.ticket.risk_rating
    )


# -------------------------------------------------
# HUMAN-FACING CLI WORKFLOW
# -------------------------------------------------


def run_workflow():

    # -------------------------------------------------
    # 1. PREPARE WORKFLOW
    # -------------------------------------------------

    result = prepare_workflow()

    # -------------------------------------------------
    # 2. DISPLAY SECURITY WARNING
    # -------------------------------------------------

    display_security_warning(
        result
    )

    # -------------------------------------------------
    # 3. DISPLAY PREPARED RESULT
    # -------------------------------------------------

    display_prepared_workflow(
        result
    )

    # -------------------------------------------------
    # 4. HUMAN APPROVAL GATE
    # -------------------------------------------------

    print()
    print("=" * 70)
    print("HUMAN APPROVAL REQUIRED")
    print("=" * 70)

    print()
    print("No ticket has been created.")

    approval_input = input(
        "\nType APPROVE to create the mock ticket, "
        "or press Enter to reject: "
    )

    # -------------------------------------------------
    # 5. APPROVE OR REJECT THROUGH EXECUTION SERVICE
    # -------------------------------------------------

    if (
        approval_input
        .strip()
        .upper()
        == "APPROVE"
    ):

        completed_result = (
            approve_and_execute_workflow(
                result=result,
                approved_by="demo-analyst"
            )
        )

        display_created_ticket(
            completed_result
        )

    else:

        rejected_result = (
            reject_workflow(
                result=result
            )
        )

        print()
        print("=" * 70)
        print("TICKET REJECTED")
        print("=" * 70)

        print()
        print(
            "Workflow ID:",
            rejected_result.workflow_id
        )

        print(
            "Workflow Status:",
            rejected_result.status
        )

        print()
        print("No ticket was created.")


# -------------------------------------------------
# SAFE TOP-LEVEL ERROR HANDLING
# -------------------------------------------------


def main():

    try:

        run_workflow()

    except json.JSONDecodeError as error:

        log_event(
            "WORKFLOW_FAILED",
            {
                "error_type":
                    "JSONDecodeError",

                "stage":
                    "input_loading",

                "line":
                    error.lineno,

                "column":
                    error.colno
            }
        )

        print()
        print("=" * 70)
        print("WORKFLOW FAILED")
        print("=" * 70)

        print()
        print(
            "The vulnerability input file "
            "contains invalid JSON."
        )

        print(
            "Check the JSON syntax and try again."
        )

        print()
        print("Error location:")

        print(
            "Line:",
            error.lineno,
            "Column:",
            error.colno
        )

    except ValidationError as error:

        log_event(
            "WORKFLOW_FAILED",
            {
                "error_type":
                    "ValidationError",

                "stage":
                    "input_validation",

                "error_count":
                    error.error_count()
            }
        )

        print()
        print("=" * 70)
        print("WORKFLOW FAILED")
        print("=" * 70)

        print()
        print(
            "Security input validation failed."
        )

        print(
            "One or more input values do not match "
            "the required schema."
        )

        print()
        print(
            "Validation errors:",
            error.error_count()
        )

    except PermissionError as error:

        log_event(
            "WORKFLOW_FAILED",
            {
                "error_type":
                    "PermissionError",

                "stage":
                    "ticket_execution_authorization",

                "message":
                    str(error)
            }
        )

        print()
        print("=" * 70)
        print("WORKFLOW FAILED")
        print("=" * 70)

        print()
        print(
            "Ticket execution was blocked by "
            "the approval security control."
        )

        print()
        print(
            "No ticket was created."
        )

        print()
        print(
            "Review the approval and audit records "
            "before retrying."
        )

    except Exception as error:

        log_event(
            "WORKFLOW_FAILED",
            {
                "error_type":
                    type(error).__name__,

                "stage":
                    "unhandled_workflow_error"
            }
        )

        print()
        print("=" * 70)
        print("WORKFLOW FAILED")
        print("=" * 70)

        print()
        print(
            "The vulnerability workflow "
            "could not complete safely."
        )

        print(
            "Error type:",
            type(error).__name__
        )

        print()
        print(
            "Review the audit log before retrying."
        )


if __name__ == "__main__":
    main()