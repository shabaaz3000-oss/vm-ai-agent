import hashlib
import json

from datetime import datetime, timezone
from uuid import uuid4

from app.models import TicketDraft


def calculate_ticket_fingerprint(
    ticket: TicketDraft
) -> str:
    """
    Create a stable SHA-256 fingerprint of the exact
    ticket contents being approved.
    """

    ticket_data = ticket.model_dump()

    canonical_json = json.dumps(
        ticket_data,
        sort_keys=True,
        separators=(",", ":")
    )

    return hashlib.sha256(
        canonical_json.encode("utf-8")
    ).hexdigest()


def create_approval(
    ticket: TicketDraft,
    approved_by: str
) -> dict:
    """
    Create an approval record tied to the exact
    contents of a ticket draft.
    """

    approver = approved_by.strip()

    if not approver:
        raise ValueError(
            "approved_by cannot be empty"
        )

    return {
        "approval_id":
            "APR-" + uuid4().hex[:8].upper(),

        "decision":
            "APPROVED",

        "approved_by":
            approver,

        "approved_at":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "ticket_fingerprint":
            calculate_ticket_fingerprint(
                ticket
            )
    }


def validate_approval(
    ticket: TicketDraft,
    approval: dict
) -> bool:
    """
    Verify that an approval is valid for the exact
    ticket that is about to be executed.
    """

    if not isinstance(approval, dict):
        return False

    if approval.get("decision") != "APPROVED":
        return False

    approved_by = approval.get(
        "approved_by"
    )

    if not isinstance(
        approved_by,
        str
    ):
        return False

    if not approved_by.strip():
        return False

    expected_fingerprint = (
        calculate_ticket_fingerprint(
            ticket
        )
    )

    supplied_fingerprint = approval.get(
        "ticket_fingerprint"
    )

    if (
        supplied_fingerprint
        != expected_fingerprint
    ):
        return False

    return True