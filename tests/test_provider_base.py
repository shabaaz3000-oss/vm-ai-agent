import pytest

from app.models import AssetContext
from app.models import ThreatIntel
from app.models import VulnerabilityFinding

from app.providers.base import VulnerabilityProvider


# -------------------------------------------------
# COMPLETE TEST PROVIDER
# -------------------------------------------------


class TestProvider(VulnerabilityProvider):

    def get_finding(
        self,
        finding_id: str
    ) -> VulnerabilityFinding:

        return VulnerabilityFinding(
            finding_id=finding_id,
            asset_name="internet-web-01",
            cve="CVE-2026-12345",
            title="Critical web vulnerability",
            description=(
                "Validated vulnerability finding."
            ),
            cvss=9.8,
            patch_available=True,
        )


    def get_asset_context(
        self,
        asset_name: str
    ) -> AssetContext:

        return AssetContext(
            asset_name=asset_name,
            owner="Web Platform Team",
            application="Customer Portal",
            environment="production",
            business_criticality="critical",
            internet_exposed=True,
            data_classification="confidential",
            current_controls=[
                "WAF",
                "EDR",
            ],
        )


    def get_threat_intel(
        self,
        cve: str
    ) -> ThreatIntel:

        return ThreatIntel(
            cve=cve,
            epss=0.91,
            kev=True,
            data_source="Test Threat Feed",
        )


# -------------------------------------------------
# INCOMPLETE PROVIDER
# -------------------------------------------------


class IncompleteProvider(VulnerabilityProvider):

    def get_finding(
        self,
        finding_id: str
    ) -> VulnerabilityFinding:

        return VulnerabilityFinding(
            finding_id=finding_id,
            asset_name="test-asset",
            cve="CVE-2026-12345",
            title="Test finding",
            description="Test description",
            cvss=5.0,
            patch_available=False,
        )


# -------------------------------------------------
# TESTS
# -------------------------------------------------


def test_base_provider_cannot_be_instantiated():

    with pytest.raises(
        TypeError
    ):

        VulnerabilityProvider()


def test_incomplete_provider_cannot_be_instantiated():

    with pytest.raises(
        TypeError
    ):

        IncompleteProvider()


def test_complete_provider_returns_normalized_models():

    provider = TestProvider()

    finding = provider.get_finding(
        "FIND-0001"
    )

    asset = provider.get_asset_context(
        finding.asset_name
    )

    threat = provider.get_threat_intel(
        finding.cve
    )

    assert isinstance(
        finding,
        VulnerabilityFinding
    )

    assert isinstance(
        asset,
        AssetContext
    )

    assert isinstance(
        threat,
        ThreatIntel
    )


def test_provider_preserves_lookup_relationships():

    provider = TestProvider()

    finding = provider.get_finding(
        "FIND-0001"
    )

    asset = provider.get_asset_context(
        finding.asset_name
    )

    threat = provider.get_threat_intel(
        finding.cve
    )

    assert (
        asset.asset_name
        == finding.asset_name
    )

    assert (
        threat.cve
        == finding.cve
    )