import hashlib
import json

from datetime import datetime, timezone
from threading import RLock
from uuid import uuid4

from app.models import TicketDraft


# -------------------------------------------------
# TRUSTED SERVER-SIDE APPROVAL STORE
# -------------------------------------------------


_APPROVAL_STORE: dict[
    str,
    dict
] = {}


_APPROVAL_STORE_LOCK = (
    RLock()
)


# -------------------------------------------------
# TICKET FINGERPRINT
# -------------------------------------------------


def calculate_ticket_fingerprint(
    ticket: TicketDraft
) -> str:

    """
    Create a stable SHA-256 fingerprint of the exact
    ticket contents being approved.

    The fingerprint binds an approval to one exact
    ticket draft.

    It is integrity metadata, not proof that an
    approval was legitimately issued.
    """

    ticket_data = (
        ticket.model_dump()
    )

    canonical_json = json.dumps(
        ticket_data,
        sort_keys=True,
        separators=(",", ":")
    )

    return hashlib.sha256(
        canonical_json.encode(
            "utf-8"
        )
    ).hexdigest()


# -------------------------------------------------
# APPROVAL CREATION
# -------------------------------------------------


def create_approval(
    ticket: TicketDraft,
    approved_by: str
) -> dict:

    """
    Create a trusted application-issued approval
    tied to the exact contents of a ticket draft.

    The authoritative approval record is stored
    server-side.

    Callers receive a copy so modifying the returned
    dictionary cannot modify the trusted record.
    """

    approver = (
        approved_by.strip()
    )

    if not approver:

        raise ValueError(
            "approved_by cannot be empty"
        )

    approval_record = {
        "approval_id":
            "APR-"
            + uuid4().hex[:8].upper(),

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

    approval_id = (
        approval_record[
            "approval_id"
        ]
    )

    # Store an independent authoritative copy.
    #
    # The caller must not be able to mutate the
    # trusted approval by modifying the dictionary
    # returned from this function.

    with _APPROVAL_STORE_LOCK:

        _APPROVAL_STORE[
            approval_id
        ] = dict(
            approval_record
        )

    return dict(
        approval_record
    )


# -------------------------------------------------
# INTERNAL APPROVAL MATCHING
# -------------------------------------------------


def _approval_matches_trusted_record(
    ticket: TicketDraft,
    approval: dict,
    trusted_approval: dict
) -> bool:

    """
    Verify that caller-supplied approval data matches
    the application-issued authoritative record and
    remains bound to the exact ticket being executed.
    """

    if not isinstance(
        approval,
        dict
    ):

        return False

    if not isinstance(
        trusted_approval,
        dict
    ):

        return False

    approval_id = (
        approval.get(
            "approval_id"
        )
    )

    if not isinstance(
        approval_id,
        str
    ):

        return False

    if not approval_id.strip():

        return False

    if (
        approval_id
        != trusted_approval.get(
            "approval_id"
        )
    ):

        return False

    # -------------------------------------------------
    # APPROVAL DECISION
    # -------------------------------------------------

    if (
        approval.get(
            "decision"
        )
        != "APPROVED"
    ):

        return False

    if (
        trusted_approval.get(
            "decision"
        )
        != "APPROVED"
    ):

        return False

    # -------------------------------------------------
    # APPROVER IDENTITY
    # -------------------------------------------------

    approved_by = (
        approval.get(
            "approved_by"
        )
    )

    if not isinstance(
        approved_by,
        str
    ):

        return False

    if not approved_by.strip():

        return False

    if (
        approved_by
        != trusted_approval.get(
            "approved_by"
        )
    ):

        return False

    # -------------------------------------------------
    # APPROVAL TIMESTAMP
    # -------------------------------------------------

    if (
        approval.get(
            "approved_at"
        )
        != trusted_approval.get(
            "approved_at"
        )
    ):

        return False

    # -------------------------------------------------
    # TRUSTED TICKET BINDING
    # -------------------------------------------------

    expected_fingerprint = (
        calculate_ticket_fingerprint(
            ticket
        )
    )

    supplied_fingerprint = (
        approval.get(
            "ticket_fingerprint"
        )
    )

    trusted_fingerprint = (
        trusted_approval.get(
            "ticket_fingerprint"
        )
    )

    if (
        supplied_fingerprint
        != trusted_fingerprint
    ):

        return False

    if (
        trusted_fingerprint
        != expected_fingerprint
    ):

        return False

    return True


# -------------------------------------------------
# APPROVAL VALIDATION
# -------------------------------------------------


def validate_approval(
    ticket: TicketDraft,
    approval: dict
) -> bool:

    """
    Verify that an approval:

    1. Was actually issued by this application
    2. Still matches the trusted server-side record
    3. Is APPROVED
    4. Belongs to a nonblank approver
    5. Is bound to the exact ticket being executed

    Validation alone does not consume the approval.
    """

    if not isinstance(
        approval,
        dict
    ):

        return False

    approval_id = (
        approval.get(
            "approval_id"
        )
    )

    if not isinstance(
        approval_id,
        str
    ):

        return False

    if not approval_id.strip():

        return False

    with _APPROVAL_STORE_LOCK:

        trusted_approval = (
            _APPROVAL_STORE.get(
                approval_id
            )
        )

        if trusted_approval is None:

            return False

        return (
            _approval_matches_trusted_record(
                ticket=ticket,
                approval=approval,
                trusted_approval=
                    trusted_approval,
            )
        )


# -------------------------------------------------
# ONE-TIME APPROVAL CONSUMPTION
# -------------------------------------------------


def consume_approval(
    ticket: TicketDraft,
    approval: dict
) -> bool:

    """
    Atomically validate and consume an approval.

    Successful consumption removes the approval from
    the trusted store so the same approval cannot be
    replayed for another ticket execution.

    Returns True only when a legitimate approval was
    successfully consumed.
    """

    if not isinstance(
        approval,
        dict
    ):

        return False

    approval_id = (
        approval.get(
            "approval_id"
        )
    )

    if not isinstance(
        approval_id,
        str
    ):

        return False

    if not approval_id.strip():

        return False

    with _APPROVAL_STORE_LOCK:

        trusted_approval = (
            _APPROVAL_STORE.get(
                approval_id
            )
        )

        if trusted_approval is None:

            return False

        valid = (
            _approval_matches_trusted_record(
                ticket=ticket,
                approval=approval,
                trusted_approval=
                    trusted_approval,
            )
        )

        if not valid:

            return False

        # One-time authorization token.
        #
        # Remove before the external side effect so
        # the approval cannot be replayed.

        del _APPROVAL_STORE[
            approval_id
        ]

        return True