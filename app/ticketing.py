import json

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.approval import consume_approval

from app.models import AIAnalysis
from app.models import AssetContext
from app.models import RiskResult
from app.models import TicketDraft
from app.models import VulnerabilityFinding


BASE_DIR = (
    Path(__file__)
    .resolve()
    .parent
    .parent
)

TICKET_FILE = (
    BASE_DIR
    / "data"
    / "tickets.jsonl"
)


# -------------------------------------------------
# AUTHORITATIVE TICKET ROUTING
# -------------------------------------------------


DEFAULT_ASSIGNMENT_GROUP = (
    "Vulnerability Management"
)


# -------------------------------------------------
# RISK TO PRIORITY
# -------------------------------------------------


def risk_to_priority(
    risk_rating: str
) -> str:

    mapping = {
        "CRITICAL": "P1",
        "HIGH": "P2",
        "MEDIUM": "P3",
        "LOW": "P4"
    }

    return mapping[
        risk_rating
    ]


# -------------------------------------------------
# BUILD TICKET
# -------------------------------------------------


def build_ticket(
    finding: VulnerabilityFinding,
    asset: AssetContext,
    risk: RiskResult,
    analysis: AIAnalysis
) -> TicketDraft:

    return TicketDraft(
        short_description=
            analysis.ticket_summary,

        priority=
            risk_to_priority(
                risk.rating
            ),

        asset_name=
            finding.asset_name,

        cve=
            finding.cve,

        # Asset ownership is provider-controlled
        # business context and is not authoritative
        # for external ticket routing.
        assignment_group=
            DEFAULT_ASSIGNMENT_GROUP,

        risk_rating=
            risk.rating,

        risk_score=
            risk.score,

        sla_hours=
            risk.sla_hours,

        description=
            analysis.ticket_description,

        remediation=
            analysis.remediation,

        validation_steps=
            analysis.validation_steps
    )


# -------------------------------------------------
# CREATE MOCK TICKET
# -------------------------------------------------


def create_mock_ticket(
    ticket: TicketDraft,
    approval: dict
) -> dict:

    # -------------------------------------------------
    # SECURITY ENFORCEMENT
    # -------------------------------------------------
    #
    # Approval must:
    #
    # - exist in the trusted server-side store
    # - match the caller-supplied approval record
    # - match this exact ticket
    # - have an APPROVED decision
    # - contain a valid approver
    # - not have been consumed previously
    #
    # Successful validation consumes the approval
    # before the external side effect occurs.

    if not consume_approval(
        ticket=ticket,
        approval=approval
    ):

        raise PermissionError(
            "Valid application-issued approval "
            "is required before ticket creation."
        )

    # -------------------------------------------------
    # CREATE TICKET RECORD
    # -------------------------------------------------

    ticket_record = {
        "ticket_id":
            "VM-"
            + uuid4().hex[:8].upper(),

        "created_at":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "approval_id":
            approval[
                "approval_id"
            ],

        "approved_by":
            approval[
                "approved_by"
            ],

        "approved_at":
            approval[
                "approved_at"
            ],

        "status":
            "OPEN",

        **ticket.model_dump()
    }

    # -------------------------------------------------
    # PERSIST MOCK TICKET
    # -------------------------------------------------

    with open(
        TICKET_FILE,
        "a",
        encoding="utf-8"
    ) as file:

        file.write(
            json.dumps(
                ticket_record
            )
            + "\n"
        )

    return ticket_record