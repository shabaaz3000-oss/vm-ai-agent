from app.loaders import load_asset
from app.loaders import load_finding
from app.loaders import load_threat_intel

from app.models import AssetContext
from app.models import RiskResult
from app.models import ThreatIntel
from app.models import VulnerabilityFinding


def calculate_risk(
    finding: VulnerabilityFinding,
    asset: AssetContext,
    threat: ThreatIntel
) -> RiskResult:

    risk_score = 0
    risk_factors = []

    # Known exploitation
    if threat.kev:
        risk_score += 30
        risk_factors.append(
            "Listed in CISA KEV"
        )

    # Internet exposure
    if asset.internet_exposed:
        risk_score += 25
        risk_factors.append(
            "Asset is internet exposed"
        )

    # Business criticality
    if asset.business_criticality == "critical":
        risk_score += 20
        risk_factors.append(
            "Asset is business critical"
        )

    # Exploitation probability
    if threat.epss is not None and threat.epss >= 0.70:
        risk_score += 15
        risk_factors.append(
            "EPSS indicates high exploitation probability"
        )

    # Technical severity
    if finding.cvss >= 9.0:
        risk_score += 10
        risk_factors.append(
            "CVSS severity is critical"
        )

    # Determine rating and SLA
    if risk_score >= 75:
        risk_rating = "CRITICAL"
        sla_hours = 24

    elif risk_score >= 50:
        risk_rating = "HIGH"
        sla_hours = 168

    elif risk_score >= 25:
        risk_rating = "MEDIUM"
        sla_hours = 720

    else:
        risk_rating = "LOW"
        sla_hours = 2160

    return RiskResult(
        score=risk_score,
        rating=risk_rating,
        sla_hours=sla_hours,
        factors=risk_factors
    )


def main():

    # Load and validate our data
    finding = load_finding()
    asset = load_asset()
    threat = load_threat_intel()

    # Calculate the authoritative risk
    risk = calculate_risk(
        finding=finding,
        asset=asset,
        threat=threat
    )

    # Display vulnerability context
    print()
    print("Vulnerability Context")
    print("---------------------")

    print("Asset:", finding.asset_name)
    print("CVE:", finding.cve)
    print("CVSS:", finding.cvss)
    print("EPSS:", threat.epss)
    print("CISA KEV:", threat.kev)
    print("Internet Exposed:", asset.internet_exposed)
    print(
        "Business Criticality:",
        asset.business_criticality
    )
    print("Environment:", asset.environment)

    # Display risk assessment
    print()
    print("Risk Assessment")
    print("---------------------")

    print("Risk Score:", risk.score)
    print("Risk Rating:", risk.rating)
    print(
        "Remediation SLA:",
        risk.sla_hours,
        "hours"
    )

    # Display reasons
    print()
    print("Risk Factors")
    print("---------------------")

    for factor in risk.factors:
        print("-", factor)


if __name__ == "__main__":
    main()