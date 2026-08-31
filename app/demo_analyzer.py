from app.models import AIAnalysis
from app.models import AssetContext
from app.models import RiskResult
from app.models import ThreatIntel
from app.models import VulnerabilityFinding


# -------------------------------------------------
# DETERMINISTIC PORTFOLIO DEMO ANALYZER
# -------------------------------------------------


def analyze_demo_vulnerability(
    finding: VulnerabilityFinding,
    asset: AssetContext,
    threat: ThreatIntel,
    risk: RiskResult,
) -> AIAnalysis:

    """
    Produce deterministic advisory analysis for the
    credential-free portfolio demo.

    This function deliberately does not:

    - call OpenAI
    - call any external AI provider
    - calculate authoritative risk
    - change the authoritative risk score
    - change the authoritative risk rating
    - change the remediation SLA
    - approve workflows
    - create tickets
    - perform remediation

    Python policy remains authoritative for risk.
    """

    rationale = [
        (
            f"The deterministic risk engine rated "
            f"this finding {risk.rating} with a "
            f"score of {risk.score}."
        ),
        (
            f"The affected asset is classified as "
            f"{asset.business_criticality} business "
            f"criticality."
        ),
    ]

    if asset.internet_exposed:

        rationale.append(
            "The affected asset is internet exposed."
        )

    if threat.kev:

        rationale.append(
            "The vulnerability is listed as known "
            "exploited."
        )

    if threat.epss is not None:

        rationale.append(
            (
                "The available EPSS probability is "
                f"{threat.epss:.2f}."
            )
        )

    if finding.patch_available:

        remediation = (
            "Validate and deploy the approved vendor "
            "patch according to change-management "
            "procedures."
        )

    else:

        remediation = (
            "A confirmed patch is not currently "
            "available in the supplied data. Apply "
            "approved compensating controls and "
            "continue monitoring for a vendor fix."
        )

    compensating_controls = list(
        asset.current_controls
    )

    if not compensating_controls:

        compensating_controls = [
            (
                "Restrict unnecessary network access "
                "to the affected service."
            ),
            (
                "Increase endpoint and security-event "
                "monitoring until remediation is "
                "completed."
            ),
        ]

    validation_steps = [
        (
            "Confirm the approved remediation was "
            "successfully applied."
        ),
        (
            "Run an authenticated vulnerability "
            "rescan."
        ),
        (
            "Verify that the finding is no longer "
            "detected."
        ),
    ]

    executive_summary = (
        f"{risk.rating} vulnerability "
        f"{finding.cve} affects "
        f"{finding.asset_name}. "
        f"The authoritative deterministic risk "
        f"score is {risk.score}, with a remediation "
        f"SLA of {risk.sla_hours} hours."
    )

    return AIAnalysis(
        executive_summary=
            executive_summary,

        rationale=
            rationale,

        remediation=
            remediation,

        compensating_controls=
            compensating_controls,

        validation_steps=
            validation_steps,

        confidence=
            "HIGH",

        requires_human_review=
            True,

        ticket_summary=(
            f"{risk.rating}: Remediate "
            f"{finding.cve} on "
            f"{finding.asset_name}"
        ),

        ticket_description=(
            "Portfolio demo advisory analysis. "
            "Authoritative risk values are supplied "
            "by the deterministic Python risk engine. "
            "Human approval is required before any "
            "external action."
        ),
    )