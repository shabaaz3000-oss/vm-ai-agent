import pytest

from pydantic import ValidationError

from app.models import AssetContext
from app.models import ThreatIntel
from app.models import VulnerabilityFinding


# -------------------------------------------------
# HELPER FUNCTIONS
# -------------------------------------------------


def make_finding(cvss: float) -> VulnerabilityFinding:

    return VulnerabilityFinding(
        finding_id="FIND-TEST-001",
        asset_name="test-server-01",
        cve="CVE-2026-99999",
        title="Test Vulnerability",
        description="Test vulnerability description.",
        cvss=cvss,
        patch_available=True
    )


def make_asset(environment: str) -> AssetContext:

    return AssetContext(
        asset_name="test-server-01",
        owner="Security Test Team",
        application="Test Application",
        environment=environment,
        business_criticality="critical",
        internet_exposed=True,
        data_classification="confidential",
        current_controls=[
            "WAF enabled",
            "EDR installed",
            "SIEM logging enabled"
        ]
    )


def make_threat_intel(epss: float) -> ThreatIntel:

    return ThreatIntel(
        cve="CVE-2026-99999",
        epss=epss,
        kev=True,
        data_source="test"
    )


# -------------------------------------------------
# CVSS TESTS
# -------------------------------------------------


def test_valid_cvss_accepted():

    finding = make_finding(
        cvss=9.8
    )

    assert finding.cvss == 9.8


def test_cvss_zero_accepted():

    finding = make_finding(
        cvss=0
    )

    assert finding.cvss == 0


def test_cvss_ten_accepted():

    finding = make_finding(
        cvss=10
    )

    assert finding.cvss == 10


def test_cvss_above_ten_rejected():

    with pytest.raises(ValidationError):

        make_finding(
            cvss=99
        )


def test_negative_cvss_rejected():

    with pytest.raises(ValidationError):

        make_finding(
            cvss=-1
        )


# -------------------------------------------------
# ASSET ENVIRONMENT TESTS
# -------------------------------------------------


def test_valid_production_environment_accepted():

    asset = make_asset(
        environment="production"
    )

    assert asset.environment == "production"


def test_invalid_environment_rejected():

    with pytest.raises(ValidationError):

        make_asset(
            environment="banana"
        )


# -------------------------------------------------
# EPSS TESTS
# -------------------------------------------------


def test_valid_epss_accepted():

    threat = make_threat_intel(
        epss=0.94
    )

    assert threat.epss == 0.94


def test_epss_above_one_rejected():

    with pytest.raises(ValidationError):

        make_threat_intel(
            epss=5
        )