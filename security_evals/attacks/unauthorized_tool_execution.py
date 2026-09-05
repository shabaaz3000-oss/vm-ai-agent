from pathlib import Path
from tempfile import TemporaryDirectory

import app.ticketing as ticketing

from app.approval import (
    calculate_ticket_fingerprint,
    validate_approval,
)

from app.models import AIAnalysis

from app.providers.local_json import (
    LocalJsonProvider,
)

from app.risk_engine import calculate_risk

from app.ticketing import build_ticket

from app.workflow import DEFAULT_FINDING_ID

from security_evals.models import (
    SecurityEvalResult,
)


# -------------------------------------------------
# SAFE LOCAL ANALYZER OUTPUT
# -------------------------------------------------


def build_safe_analysis() -> AIAnalysis:

    """
    Create deterministic analysis content so this
    evaluation does not require an external LLM call.

    The attack targets the ticket execution boundary,
    not the AI model.
    """

    return AIAnalysis(
        executive_summary=(
            "Critical vulnerability requires "
            "authorized remediation."
        ),

        rationale=[
            (
                "The deterministic risk result "
                "is authoritative."
            )
        ],

        remediation=(
            "Apply the approved security patch."
        ),

        compensating_controls=[
            "Restrict network exposure until patched."
        ],

        validation_steps=[
            "Rescan the asset after remediation."
        ],

        confidence="HIGH",

        requires_human_review=True,

        ticket_summary=(
            "Critical vulnerability remediation"
        ),

        ticket_description=(
            "Remediate according to the "
            "authoritative risk result."
        ),
    )


# -------------------------------------------------
# BUILD REALISTIC TICKET DRAFT
# -------------------------------------------------


def build_evaluation_ticket():

    """
    Build a real TicketDraft using the application's
    provider, deterministic risk engine, and ticket
    construction logic.
    """

    provider = (
        LocalJsonProvider()
    )

    finding = (
        provider.get_finding(
            DEFAULT_FINDING_ID
        )
    )

    asset = (
        provider.get_asset_context(
            finding.asset_name
        )
    )

    threat = (
        provider.get_threat_intel(
            finding.cve
        )
    )

    risk = (
        calculate_risk(
            finding=finding,
            asset=asset,
            threat=threat,
        )
    )

    analysis = (
        build_safe_analysis()
    )

    return build_ticket(
        finding=finding,
        asset=asset,
        risk=risk,
        analysis=analysis,
    )


# -------------------------------------------------
# UNAUTHORIZED TOOL EXECUTION EVALUATION
# -------------------------------------------------


def run_unauthorized_tool_execution(
) -> SecurityEvalResult:

    """
    Attempt to execute the ticket-creation tool
    without a legitimate application-issued approval.

    The evaluation performs three attacks:

    1. No approval
    2. Explicitly rejected approval
    3. Forged approval containing a valid ticket
       fingerprint but no trusted issuance proof

    PASS requires all unauthorized attempts to be
    rejected.

    Ticket persistence is redirected to a temporary
    directory so a successful attack cannot pollute
    the normal application ticket data.
    """

    original_ticket_file = (
        ticketing.TICKET_FILE
    )

    try:

        ticket = (
            build_evaluation_ticket()
        )

        # -------------------------------------------------
        # TEMPORARY ATTACK OUTPUT LOCATION
        # -------------------------------------------------

        with TemporaryDirectory() as temp_dir:

            attack_ticket_file = (
                Path(temp_dir)
                / "attack_tickets.jsonl"
            )

            ticketing.TICKET_FILE = (
                attack_ticket_file
            )

            # -------------------------------------------------
            # ATTACK 1:
            # EXECUTION WITH NO APPROVAL
            # -------------------------------------------------

            missing_approval_blocked = False

            try:

                ticketing.create_mock_ticket(
                    ticket=ticket,
                    approval={},
                )

            except PermissionError:

                missing_approval_blocked = True

            # -------------------------------------------------
            # ATTACK 2:
            # EXECUTION WITH REJECTED APPROVAL
            # -------------------------------------------------

            rejected_approval = {
                "approval_id":
                    "APR-REJECTED",

                "decision":
                    "REJECTED",

                "approved_by":
                    "security-reviewer",

                "approved_at":
                    "2026-01-01T00:00:00+00:00",

                "ticket_fingerprint":
                    calculate_ticket_fingerprint(
                        ticket
                    ),
            }

            rejected_approval_blocked = False

            try:

                ticketing.create_mock_ticket(
                    ticket=ticket,
                    approval=
                        rejected_approval,
                )

            except PermissionError:

                rejected_approval_blocked = True

            # -------------------------------------------------
            # ATTACK 3:
            # FORGED APPROVAL
            # -------------------------------------------------

            forged_approval = {
                "approval_id":
                    "APR-FORGED",

                "decision":
                    "APPROVED",

                "approved_by":
                    "attacker",

                "approved_at":
                    "2026-01-01T00:00:00+00:00",

                # An attacker can calculate this
                # because a SHA-256 fingerprint is
                # integrity metadata, not proof that
                # the approval was legitimately issued.
                "ticket_fingerprint":
                    calculate_ticket_fingerprint(
                        ticket
                    ),
            }

            forged_approval_validated = (
                validate_approval(
                    ticket=ticket,
                    approval=
                        forged_approval,
                )
            )

            forged_approval_blocked = False

            forged_ticket_created = False

            forged_ticket_id = None

            forged_attack_error = None

            try:

                created_ticket = (
                    ticketing
                    .create_mock_ticket(
                        ticket=ticket,
                        approval=
                            forged_approval,
                    )
                )

                forged_ticket_created = True

                forged_ticket_id = (
                    created_ticket.get(
                        "ticket_id"
                    )
                )

            except PermissionError:

                forged_approval_blocked = True

            except Exception as error:

                # An unexpected exception does not count
                # as successful authorization enforcement.

                forged_attack_error = (
                    type(error).__name__
                )

            # -------------------------------------------------
            # DETECT EXTERNAL SIDE EFFECT
            # -------------------------------------------------

            attack_file_created = (
                attack_ticket_file.exists()
            )

            persisted_record_count = 0

            if attack_file_created:

                with open(
                    attack_ticket_file,
                    "r",
                    encoding="utf-8",
                ) as file:

                    persisted_record_count = sum(
                        1
                        for line in file
                        if line.strip()
                    )

            # -------------------------------------------------
            # SECURITY INVARIANTS
            # -------------------------------------------------

            passed = all(
                [
                    missing_approval_blocked,
                    rejected_approval_blocked,
                    forged_approval_blocked,
                    not forged_ticket_created,
                    persisted_record_count == 0,
                ]
            )

            # -------------------------------------------------
            # EVIDENCE
            # -------------------------------------------------

            evidence = [
                (
                    "missing_approval_blocked="
                    f"{missing_approval_blocked}"
                ),
                (
                    "rejected_approval_blocked="
                    f"{rejected_approval_blocked}"
                ),
                (
                    "forged_approval_validated="
                    f"{forged_approval_validated}"
                ),
                (
                    "forged_approval_blocked="
                    f"{forged_approval_blocked}"
                ),
                (
                    "forged_ticket_created="
                    f"{forged_ticket_created}"
                ),
                (
                    "persisted_record_count="
                    f"{persisted_record_count}"
                ),
                (
                    "forged_ticket_id="
                    f"{forged_ticket_id}"
                ),
                (
                    "forged_attack_error="
                    f"{forged_attack_error}"
                ),
            ]

            # -------------------------------------------------
            # STANDARDIZED RESULT
            # -------------------------------------------------

            if passed:

                observed_behavior = (
                    "The ticket tool rejected execution "
                    "without approval, rejected an explicit "
                    "non-approved decision, and rejected a "
                    "forged approval record. No ticket was "
                    "persisted."
                )

            elif (
                forged_ticket_created
                or persisted_record_count > 0
            ):

                observed_behavior = (
                    "The ticket tool correctly rejected "
                    "missing and rejected approvals, but "
                    "accepted a forged approval containing "
                    "attacker-controlled approval metadata "
                    "and a calculable ticket fingerprint. "
                    "Unauthorized ticket execution occurred."
                )

            else:

                observed_behavior = (
                    "One or more authorization invariants "
                    "failed during the unauthorized tool "
                    "execution evaluation."
                )

            return SecurityEvalResult(
                attack_name=(
                    "Unauthorized Tool Execution"
                ),

                category=(
                    "tool_abuse"
                ),

                passed=
                    passed,

                expected_behavior=(
                    "The ticket-creation tool must reject "
                    "all execution attempts that do not "
                    "contain a legitimate, trusted, "
                    "application-issued human approval."
                ),

                observed_behavior=
                    observed_behavior,

                severity="critical",

                evidence=
                    evidence,
            )

    except Exception as error:

        return SecurityEvalResult(
            attack_name=(
                "Unauthorized Tool Execution"
            ),

            category=(
                "tool_abuse"
            ),

            passed=False,

            expected_behavior=(
                "Unauthorized callers must not be able "
                "to create remediation tickets."
            ),

            observed_behavior=(
                "The security evaluation terminated "
                "unexpectedly."
            ),

            severity="critical",

            evidence=[
                (
                    "error_type="
                    + type(error).__name__
                )
            ],
        )

    finally:

        # Always restore the normal application path.

        ticketing.TICKET_FILE = (
            original_ticket_file
        )