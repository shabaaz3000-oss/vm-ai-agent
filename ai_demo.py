from app.ai_analyzer import analyze_vulnerability
from app.loaders import load_asset
from app.loaders import load_finding
from app.loaders import load_threat_intel
from app.risk_engine import calculate_risk


def main():

    # 1. Load and validate security data
    finding = load_finding()
    asset = load_asset()
    threat = load_threat_intel()

    # 2. Calculate authoritative risk in Python
    risk = calculate_risk(
        finding=finding,
        asset=asset,
        threat=threat
    )

    # 3. Ask AI to analyze/explain
    analysis = analyze_vulnerability(
        finding=finding,
        asset=asset,
        threat=threat,
        risk=risk
    )

    # 4. Display authoritative Python result
    print()
    print("=" * 70)
    print("AUTHORITATIVE RISK RESULT")
    print("=" * 70)

    print("Asset:", finding.asset_name)
    print("CVE:", finding.cve)
    print("Risk Score:", risk.score)
    print("Risk Rating:", risk.rating)
    print(
        "Remediation SLA:",
        risk.sla_hours,
        "hours"
    )

    # 5. Display AI analysis
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

    print()
    print("=" * 70)
    print("PROPOSED TICKET DRAFT")
    print("=" * 70)

    print()
    print("Summary:")
    print(analysis.ticket_summary)

    print()
    print("Description:")
    print(analysis.ticket_description)


if __name__ == "__main__":
    main()