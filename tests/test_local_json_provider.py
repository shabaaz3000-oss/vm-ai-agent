import json

import pytest

from pydantic import ValidationError

from app.models import AssetContext
from app.models import ThreatIntel
from app.models import VulnerabilityFinding

from app.providers.local_json import LocalJsonProvider


# -------------------------------------------------
# TEST DATA
# -------------------------------------------------


def write_json(
    path,
    data
):

    path.write_text(
        json.dumps(
            data
        ),
        encoding="utf-8"
    )


def make_provider(
    tmp_path
):

    finding_path = (
        tmp_path / "finding.json"
    )

    asset_path = (
        tmp_path / "asset.json"
    )

    threat_path = (
        tmp_path / "threat_intel.json"
    )

    write_json(
        finding_path,
        {
            "finding_id":
                "FIND-0001",

            "asset_name":
                "internet-web-01",

            "cve":
                "CVE-2026-12345",

            "title":
                "Critical web vulnerability",

            "description":
                "Validated vulnerability finding.",

            "cvss":
                9.8,

            "patch_available":
                True,
        }
    )

    write_json(
        asset_path,
        {
            "asset_name":
                "internet-web-01",

            "owner":
                "Web Platform Team",

            "application":
                "Customer Portal",

            "environment":
                "production",

            "business_criticality":
                "critical",

            "internet_exposed":
                True,

            "data_classification":
                "confidential",

            "current_controls": [
                "WAF",
                "EDR",
            ],
        }
    )

    write_json(
        threat_path,
        {
            "cve":
                "CVE-2026-12345",

            "epss":
                0.91,

            "kev":
                True,

            "data_source":
                "Test Threat Feed",
        }
    )

    return LocalJsonProvider(
        finding_path=finding_path,
        asset_path=asset_path,
        threat_intel_path=threat_path,
    )


# -------------------------------------------------
# NORMALIZED MODELS
# -------------------------------------------------


def test_local_json_provider_returns_normalized_models(
    tmp_path
):

    provider = make_provider(
        tmp_path
    )

    finding = provider.get_finding(
        "FIND-0001"
    )

    asset = provider.get_asset_context(
        "internet-web-01"
    )

    threat = provider.get_threat_intel(
        "CVE-2026-12345"
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


# -------------------------------------------------
# FINDING LOOKUP BINDING
# -------------------------------------------------


def test_finding_lookup_mismatch_is_rejected(
    tmp_path
):

    provider = make_provider(
        tmp_path
    )

    with pytest.raises(
        KeyError
    ):

        provider.get_finding(
            "FIND-WRONG"
        )


# -------------------------------------------------
# ASSET LOOKUP BINDING
# -------------------------------------------------


def test_asset_lookup_mismatch_is_rejected(
    tmp_path
):

    provider = make_provider(
        tmp_path
    )

    with pytest.raises(
        KeyError
    ):

        provider.get_asset_context(
            "different-server"
        )


# -------------------------------------------------
# CVE LOOKUP BINDING
# -------------------------------------------------


def test_threat_lookup_mismatch_is_rejected(
    tmp_path
):

    provider = make_provider(
        tmp_path
    )

    with pytest.raises(
        KeyError
    ):

        provider.get_threat_intel(
            "CVE-2026-99999"
        )


# -------------------------------------------------
# MODEL VALIDATION STILL APPLIES
# -------------------------------------------------


def test_provider_rejects_invalid_security_data(
    tmp_path
):

    provider = make_provider(
        tmp_path
    )

    write_json(
        provider.finding_path,
        {
            "finding_id":
                "FIND-0001",

            "asset_name":
                "internet-web-01",

            "cve":
                "CVE-2026-12345",

            "title":
                "Invalid finding",

            "description":
                "Invalid CVSS test.",

            "cvss":
                99,

            "patch_available":
                True,
        }
    )

    with pytest.raises(
        ValidationError
    ):

        provider.get_finding(
            "FIND-0001"
        )


# -------------------------------------------------
# NON-OBJECT JSON IS REJECTED
# -------------------------------------------------


def test_provider_rejects_non_object_json(
    tmp_path
):

    provider = make_provider(
        tmp_path
    )

    provider.finding_path.write_text(
        json.dumps(
            [
                {
                    "finding_id":
                        "FIND-0001"
                }
            ]
        ),
        encoding="utf-8"
    )

    with pytest.raises(
        ValueError
    ):

        provider.get_finding(
            "FIND-0001"
        )
        