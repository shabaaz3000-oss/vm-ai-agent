import pytest

from app.models import AssetContext
from app.models import ThreatIntel
from app.models import VulnerabilityFinding

from app.providers.tenable import TenableProvider


# -------------------------------------------------
# TEST DATA
# -------------------------------------------------


def make_vulnerability_record():

    return {
        "finding_id":
            "FIND-TENABLE-0001",

        # Deliberately contains an embedded name
        # that must NOT become authoritative.

        "asset": {
            "uuid":
                "ASSET-UUID-123",

            "name":
                "stale-embedded-hostname",
        },

        "plugin": {
            "id":
                12345,

            "name":
                "Critical Remote Code Execution",

            "description":
                (
                    "A remote code execution "
                    "vulnerability was detected."
                ),

            "solution":
                "Apply the vendor security update.",

            "cve": [
                "CVE-2026-12345"
            ],

            "cvss4_base_score":
                9.8,

            "cvss3_base_score":
                9.6,

            "epss_score":
                94.0,

            "has_patch":
                True,

            "vpr": {
                "score":
                    9.9,

                "on_cisa_kev":
                    True,
            },
        },

        "state":
            "open",
    }


def make_asset_record():

    return {
        "id":
            "ASSET-UUID-123",

        "types": [
            "host"
        ],

        "network": {
            "hostnames": [
                "current-tenable-hostname"
            ],

            "ipv4s": [
                "203.0.113.10"
            ],
        },

        "timestamps": {
            "created_at":
                "2026-01-01T00:00:00Z",

            "updated_at":
                "2026-08-25T00:00:00Z",
        },
    }


def make_asset_context():

    return AssetContext(
        asset_name=
            "internet-web-01",

        owner=
            "Web Platform Team",

        application=
            "Customer Portal",

        environment=
            "production",

        business_criticality=
            "critical",

        internet_exposed=
            True,

        data_classification=
            "confidential",

        current_controls=[
            "WAF",
            "EDR",
            "SIEM",
        ],
    )


def make_provider():

    return TenableProvider(
        vulnerability_records=[
            make_vulnerability_record()
        ],

        asset_records=[
            make_asset_record()
        ],

        asset_context_by_uuid={
            "ASSET-UUID-123":
                make_asset_context()
        },
    )


# -------------------------------------------------
# NORMALIZATION
# -------------------------------------------------


def test_tenable_provider_returns_normalized_models():

    provider = make_provider()

    finding = provider.get_finding(
        "FIND-TENABLE-0001"
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

    assert (
        finding.cve
        == "CVE-2026-12345"
    )

    assert (
        finding.cvss
        == 9.8
    )

    assert (
        finding.patch_available
        is True
    )


# -------------------------------------------------
# ASSET UUID IS AUTHORITATIVE CORRELATION
# -------------------------------------------------


def test_embedded_finding_hostname_is_not_trusted():

    provider = make_provider()

    finding = provider.get_finding(
        "FIND-TENABLE-0001"
    )

    assert (
        finding.asset_name
        == "internet-web-01"
    )

    assert (
        finding.asset_name
        != "stale-embedded-hostname"
    )


# -------------------------------------------------
# CURRENT ASSET REQUIRED
# -------------------------------------------------


def test_missing_current_asset_is_rejected():

    provider = TenableProvider(
        vulnerability_records=[
            make_vulnerability_record()
        ],

        asset_records=[],

        asset_context_by_uuid={
            "ASSET-UUID-123":
                make_asset_context()
        },
    )

    with pytest.raises(
        KeyError,
        match="Current Tenable asset",
    ):

        provider.get_finding(
            "FIND-TENABLE-0001"
        )


# -------------------------------------------------
# DELETED / TERMINATED ASSETS
# -------------------------------------------------


def test_deleted_asset_is_rejected():

    asset = (
        make_asset_record()
    )

    asset[
        "timestamps"
    ][
        "deleted_at"
    ] = (
        "2026-08-25T12:00:00Z"
    )

    provider = TenableProvider(
        vulnerability_records=[
            make_vulnerability_record()
        ],

        asset_records=[
            asset
        ],

        asset_context_by_uuid={
            "ASSET-UUID-123":
                make_asset_context()
        },
    )

    with pytest.raises(
        ValueError,
        match="deleted or terminated",
    ):

        provider.get_finding(
            "FIND-TENABLE-0001"
        )


# -------------------------------------------------
# MULTIPLE CVES FAIL CLOSED
# -------------------------------------------------


def test_multiple_cves_are_rejected():

    vulnerability = (
        make_vulnerability_record()
    )

    vulnerability[
        "plugin"
    ][
        "cve"
    ] = [
        "CVE-2026-12345",
        "CVE-2026-67890",
    ]

    provider = TenableProvider(
        vulnerability_records=[
            vulnerability
        ],

        asset_records=[
            make_asset_record()
        ],

        asset_context_by_uuid={
            "ASSET-UUID-123":
                make_asset_context()
        },
    )

    with pytest.raises(
        ValueError,
        match="exactly one CVE",
    ):

        provider.get_finding(
            "FIND-TENABLE-0001"
        )


# -------------------------------------------------
# EPSS NORMALIZATION
# -------------------------------------------------


def test_epss_percentage_is_normalized_to_probability():

    provider = make_provider()

    threat = provider.get_threat_intel(
        "CVE-2026-12345"
    )

    assert (
        threat.epss
        == pytest.approx(
            0.94
        )
    )

    assert (
        threat.kev
        is True
    )


# -------------------------------------------------
# KEV MUST NOT SILENTLY BECOME FALSE
# -------------------------------------------------


def test_missing_kev_status_fails_closed():

    vulnerability = (
        make_vulnerability_record()
    )

    vulnerability[
        "plugin"
    ].pop(
        "vpr"
    )

    provider = TenableProvider(
        vulnerability_records=[
            vulnerability
        ],

        asset_records=[
            make_asset_record()
        ],

        asset_context_by_uuid={
            "ASSET-UUID-123":
                make_asset_context()
        },
    )

    with pytest.raises(
        ValueError,
        match="CISA KEV",
    ):

        provider.get_threat_intel(
            "CVE-2026-12345"
        )


# -------------------------------------------------
# CVSS FALLBACK
# -------------------------------------------------


def test_cvss3_is_used_when_cvss4_is_missing():

    vulnerability = (
        make_vulnerability_record()
    )

    vulnerability[
        "plugin"
    ].pop(
        "cvss4_base_score"
    )

    vulnerability[
        "plugin"
    ][
        "cvss3_base_score"
    ] = 9.1

    provider = TenableProvider(
        vulnerability_records=[
            vulnerability
        ],

        asset_records=[
            make_asset_record()
        ],

        asset_context_by_uuid={
            "ASSET-UUID-123":
                make_asset_context()
        },
    )

    finding = provider.get_finding(
        "FIND-TENABLE-0001"
    )

    assert (
        finding.cvss
        == 9.1
    )