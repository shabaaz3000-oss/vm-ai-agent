from app.ai_analyzer import analyze_vulnerability

from app.loaders import load_asset
from app.loaders import load_finding
from app.loaders import load_threat_intel

from app.risk_engine import calculate_risk

from app.ticketing import build_ticket
from app.ticketing import create_mock_ticket


def main():

    # -------------------------------------------------
    # 1. LOAD AND VALIDATE SECURITY DATA
    # -------------------------------------------------

    finding = load_finding()
    asset = load_asset()
    threat = load_threat_intel()


    # -------------------------------------------------
    # 2. CALCULATE AUTHORITATIVE RISK
    # -------------------------------------------------

    risk = calculate_risk(
        finding=finding,
        asset=asset,
        threat=threat
    )


    # -------------------------------------------------
    # 3. GENERATE AI SECURITY ANALYSIS
    # -------------------------------------------------

    analysis = analyze_vulnerability(
        finding=finding,
        asset=asset,
        threat=threat,
        risk=risk
    )


    # -------------------------------------------------
    # 4. BUILD VALIDATED TICKET DRAFT
    # -------------------------------------------------

    ticket = build_ticket(
        finding=finding,
        asset=asset,
        risk=risk,
        analysis=analysis
    )


    # -------------------------------------------------
    # 5. DISPLAY AUTHORITATIVE RISK RESULT
    # -------------------------------------------------

    print()
    print("=" * 70)
    print("AUTHORITATIVE RISK RESULT")
    print("=" * 70)

    print()
    print("Asset:", finding.asset_name)
    print("CVE:", finding.cve)
    print("Risk Score:", risk.score)
    print("Risk Rating:", risk.rating)

    print(
        "Remediation SLA:",
        risk.sla_hours,
        "hours"
    )


    # -------------------------------------------------
    # 6. DISPLAY AI SECURITY ANALYSIS
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
    # 7. DISPLAY VALIDATED TICKET DRAFT
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
    # 8. HUMAN APPROVAL GATE
    # -------------------------------------------------

    print()
    print("=" * 70)
    print("HUMAN APPROVAL REQUIRED")
    print("=" * 70)

    print()
    print("No ticket has been created.")

    approval = input(
        "\nType APPROVE to create the mock ticket, "
        "or press Enter to reject: "
    )


    # -------------------------------------------------
    # 9. EXECUTE ONLY AFTER EXPLICIT APPROVAL
    # -------------------------------------------------

    if approval.strip().upper() == "APPROVE":

        created_ticket = create_mock_ticket(
            ticket=ticket,
            approved_by="demo-analyst"
        )

        print()
        print("=" * 70)
        print("MOCK TICKET CREATED")
        print("=" * 70)

        print()
        print(
            "Ticket ID:",
            created_ticket["ticket_id"]
        )

        print(
            "Status:",
            created_ticket["status"]
        )

        print(
            "Approved By:",
            created_ticket["approved_by"]
        )

        print(
            "Priority:",
            created_ticket["priority"]
        )

        print(
            "Risk Rating:",
            created_ticket["risk_rating"]
        )

    else:

        print()
        print("=" * 70)
        print("TICKET REJECTED")
        print("=" * 70)

        print()
        print("No ticket was created.")


if __name__ == "__main__":
    main()