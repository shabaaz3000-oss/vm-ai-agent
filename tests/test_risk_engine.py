from app.models import AssetContext
from app.models import ThreatIntel
from app.models import VulnerabilityFinding

from app.risk_engine import calculate_risk


# -------------------------------------------------
# TEST DATA HELPERS
# -------------------------------------------------


def make_finding(
    cvss: float = 5.0
) -> VulnerabilityFinding:

    return VulnerabilityFinding(
        finding_id="FIND-TEST-001",
        asset_name="test-server-01",
        cve="CVE-2026-99999",
        title="Test Vulnerability",
        description="Test vulnerability description.",
        cvss=cvss,
        patch_available=True
    )


def make_asset(
    internet_exposed: bool = False,
    business_criticality: str = "high"
) -> AssetContext:

    return AssetContext(
        asset_name="test-server-01",
        owner="Security Test Team",
        application="Test Application",
        environment="production",
        business_criticality=business_criticality,
        internet_exposed=internet_exposed,
        data_classification="confidential",
        current_controls=[
            "WAF enabled",
            "EDR installed",
            "SIEM logging enabled"
        ]
    )


def make_threat(
    kev: bool = False,
    epss: float = 0.10
) -> ThreatIntel:

    return ThreatIntel(
        cve="CVE-2026-99999",
        epss=epss,
        kev=kev,
        data_source="test"
    )


# -------------------------------------------------
# MAXIMUM-RISK TEST
# -------------------------------------------------


def test_all_risk_factors_produce_score_100():

    finding = make_finding(
        cvss=9.8
    )

    asset = make_asset(
        internet_exposed=True,
        business_criticality="critical"
    )

    threat = make_threat(
        kev=True,
        epss=0.94
    )

    result = calculate_risk(
        finding=finding,
        asset=asset,
        threat=threat
    )

    assert result.score == 100
    assert result.rating == "CRITICAL"
    assert result.sla_hours == 24

    assert result.factors == [
        "Listed in CISA KEV",
        "Asset is internet exposed",
        "Asset is business critical",
        "EPSS indicates high exploitation probability",
        "CVSS severity is critical"
    ]


# -------------------------------------------------
# RATING THRESHOLD TESTS
# -------------------------------------------------


def test_score_75_is_critical():

    finding = make_finding(
        cvss=5.0
    )

    asset = make_asset(
        internet_exposed=True,
        business_criticality="critical"
    )

    threat = make_threat(
        kev=True,
        epss=0.10
    )

    result = calculate_risk(
        finding=finding,
        asset=asset,
        threat=threat
    )

    # 30 KEV + 25 internet + 20 criticality = 75
    assert result.score == 75
    assert result.rating == "CRITICAL"
    assert result.sla_hours == 24


def test_score_70_is_high():

    finding = make_finding(
        cvss=5.0
    )

    asset = make_asset(
        internet_exposed=True,
        business_criticality="high"
    )

    threat = make_threat(
        kev=True,
        epss=0.70
    )

    result = calculate_risk(
        finding=finding,
        asset=asset,
        threat=threat
    )

    # 30 KEV + 25 internet + 15 EPSS = 70
    assert result.score == 70
    assert result.rating == "HIGH"
    assert result.sla_hours == 168


def test_score_50_is_high():

    finding = make_finding(
        cvss=5.0
    )

    asset = make_asset(
        internet_exposed=False,
        business_criticality="critical"
    )

    threat = make_threat(
        kev=True,
        epss=0.10
    )

    result = calculate_risk(
        finding=finding,
        asset=asset,
        threat=threat
    )

    # 30 KEV + 20 criticality = 50
    assert result.score == 50
    assert result.rating == "HIGH"
    assert result.sla_hours == 168


def test_score_45_is_medium():

    finding = make_finding(
        cvss=5.0
    )

    asset = make_asset(
        internet_exposed=True,
        business_criticality="critical"
    )

    threat = make_threat(
        kev=False,
        epss=0.10
    )

    result = calculate_risk(
        finding=finding,
        asset=asset,
        threat=threat
    )

    # 25 internet + 20 criticality = 45
    assert result.score == 45
    assert result.rating == "MEDIUM"
    assert result.sla_hours == 720


def test_score_25_is_medium():

    finding = make_finding(
        cvss=5.0
    )

    asset = make_asset(
        internet_exposed=True,
        business_criticality="high"
    )

    threat = make_threat(
        kev=False,
        epss=0.10
    )

    result = calculate_risk(
        finding=finding,
        asset=asset,
        threat=threat
    )

    # Internet exposure alone = 25
    assert result.score == 25
    assert result.rating == "MEDIUM"
    assert result.sla_hours == 720


def test_score_20_is_low():

    finding = make_finding(
        cvss=5.0
    )

    asset = make_asset(
        internet_exposed=False,
        business_criticality="critical"
    )

    threat = make_threat(
        kev=False,
        epss=0.10
    )

    result = calculate_risk(
        finding=finding,
        asset=asset,
        threat=threat
    )

    # Critical business asset alone = 20
    assert result.score == 20
    assert result.rating == "LOW"
    assert result.sla_hours == 2160


# -------------------------------------------------
# EPSS BOUNDARY TESTS
# -------------------------------------------------


def test_epss_070_adds_risk_points():

    finding = make_finding(
        cvss=5.0
    )

    asset = make_asset(
        internet_exposed=False,
        business_criticality="high"
    )

    threat = make_threat(
        kev=False,
        epss=0.70
    )

    result = calculate_risk(
        finding=finding,
        asset=asset,
        threat=threat
    )

    assert result.score == 15

    assert (
        "EPSS indicates high exploitation probability"
        in result.factors
    )


def test_epss_069_does_not_add_risk_points():

    finding = make_finding(
        cvss=5.0
    )

    asset = make_asset(
        internet_exposed=False,
        business_criticality="high"
    )

    threat = make_threat(
        kev=False,
        epss=0.69
    )

    result = calculate_risk(
        finding=finding,
        asset=asset,
        threat=threat
    )

    assert result.score == 0

    assert (
        "EPSS indicates high exploitation probability"
        not in result.factors
    )


# -------------------------------------------------
# CVSS BOUNDARY TESTS
# -------------------------------------------------


def test_cvss_90_adds_risk_points():

    finding = make_finding(
        cvss=9.0
    )

    asset = make_asset(
        internet_exposed=False,
        business_criticality="high"
    )

    threat = make_threat(
        kev=False,
        epss=0.10
    )

    result = calculate_risk(
        finding=finding,
        asset=asset,
        threat=threat
    )

    assert result.score == 10

    assert (
        "CVSS severity is critical"
        in result.factors
    )


def test_cvss_89_does_not_add_risk_points():

    finding = make_finding(
        cvss=8.9
    )

    asset = make_asset(
        internet_exposed=False,
        business_criticality="high"
    )

    threat = make_threat(
        kev=False,
        epss=0.10
    )

    result = calculate_risk(
        finding=finding,
        asset=asset,
        threat=threat
    )

    assert result.score == 0

    assert (
        "CVSS severity is critical"
        not in result.factors
    )


# -------------------------------------------------
# ZERO-RISK TEST
# -------------------------------------------------


def test_no_risk_factors_produce_low_risk():

    finding = make_finding(
        cvss=5.0
    )

    asset = make_asset(
        internet_exposed=False,
        business_criticality="high"
    )

    threat = make_threat(
        kev=False,
        epss=0.10
    )

    result = calculate_risk(
        finding=finding,
        asset=asset,
        threat=threat
    )

    assert result.score == 0
    assert result.rating == "LOW"
    assert result.sla_hours == 2160
    assert result.factors == []