import json

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.models import AIAnalysis
from app.models import AssetContext
from app.models import RiskResult
from app.models import TicketDraft
from app.models import VulnerabilityFinding


BASE_DIR = Path(__file__).resolve().parent.parent

TICKET_FILE = BASE_DIR / "data" / "tickets.jsonl"


def risk_to_priority(risk_rating: str) -> str:

    mapping = {
        "CRITICAL": "P1",
        "HIGH": "P2",
        "MEDIUM": "P3",
        "LOW": "P4"
    }

    return mapping[risk_rating]


def build_ticket(
    finding: VulnerabilityFinding,
    asset: AssetContext,
    risk: RiskResult,
    analysis: AIAnalysis
) -> TicketDraft:

    return TicketDraft(
        short_description=analysis.ticket_summary,

        priority=risk_to_priority(
            risk.rating
        ),

        asset_name=finding.asset_name,

        cve=finding.cve,

        assignment_group=asset.owner,

        risk_rating=risk.rating,

        risk_score=risk.score,

        sla_hours=risk.sla_hours,

        description=analysis.ticket_description,

        remediation=analysis.remediation,

        validation_steps=analysis.validation_steps
    )


def create_mock_ticket(
    ticket: TicketDraft,
    approved_by: str
) -> dict:

    ticket_record = {
        "ticket_id": "VM-" + uuid4().hex[:8].upper(),

        "created_at": datetime.now(
            timezone.utc
        ).isoformat(),

        "approved_by": approved_by,

        "status": "OPEN",

        **ticket.model_dump()
    }

    with open(
        TICKET_FILE,
        "a",
        encoding="utf-8"
    ) as file:

        file.write(
            json.dumps(ticket_record)
            + "\n"
        )

    return ticket_record