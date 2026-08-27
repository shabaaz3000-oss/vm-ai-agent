import csv

from pathlib import Path

import pytest

from app.models import AssetContext

from app.providers.base import VulnerabilityProvider

from app.providers.tenable_csv import (
    TenableCsvImportError,
    TenableCsvProvider,
)


ASSET_UUID = (
    "11111111-1111-1111-1111-111111111111"
)


# -------------------------------------------------
# HELPERS
# -------------------------------------------------


def finding_row(
    **overrides: str,
) -> dict[str, str]:

    row = {
        "id":
            "FIND-TENABLE-0001",

        "asset.id":
            ASSET_UUID,

        "asset.name":
            "server01",

        "definition.cve":
            "CVE-2026-12345",

        "definition.name":
            "Remote Code Execution",

        "definition.description":
            "A remote code execution "
            "vulnerability was detected.",

        "definition.cvss4.base_score":
            "9.8",

        "definition.cvss3.base_score":
            "9.1",

        "definition.cvss2.base_score":
            "7.5",

        "definition.epss.score":
            "94",

        "definition.vpr.drivers_on_cisa_kev":
            "true",

        "definition.patch_published":
            "2026-08-01T00:00:00Z",

        "severity":
            "critical",
    }

    row.update(
        overrides
    )

    return row


def asset_row(
    **overrides: str,
) -> dict[str, str]:

    row = {
        "id":
            ASSET_UUID,

        "name":
            "server01",

        "terminated_at":
            "",

        "display_fqdn":
            "server01.example.test",
    }

    row.update(
        overrides
    )

    return row


def asset_context() -> dict:

    return {
        ASSET_UUID:
            AssetContext(
                asset_name=
                    "server01",

                owner=
                    "Infrastructure Team",

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
                    "EDR",
                    "WAF",
                ],
            )
    }


def write_csv(
    path: Path,
    rows: list[dict[str, str]],
    *,
    fieldnames: list[str] | None = None,
) -> Path:

    selected_fields = (
        fieldnames
        if fieldnames is not None
        else list(
            rows[0].keys()
        )
    )

    with path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:

        writer = csv.DictWriter(
            handle,
            fieldnames=selected_fields,
        )

        writer.writeheader()

        for row in rows:

            writer.writerow(
                {
                    field:
                        row.get(
                            field,
                            "",
                        )
                    for field
                    in selected_fields
                }
            )

    return path


def build_provider(
    tmp_path: Path,
    *,
    finding: dict[str, str] | None = None,
    asset: dict[str, str] | None = None,
    patch_overrides=None,
) -> TenableCsvProvider:

    finding_csv = write_csv(
        tmp_path / "tenable-findings.csv",
        [
            finding
            if finding is not None
            else finding_row()
        ],
    )

    asset_csv = write_csv(
        tmp_path / "tenable-assets.csv",
        [
            asset
            if asset is not None
            else asset_row()
        ],
    )

    return TenableCsvProvider(
        vulnerability_csv_path=
            finding_csv,

        asset_csv_path=
            asset_csv,

        asset_context_by_uuid=
            asset_context(),

        patch_available_by_finding_id=
            patch_overrides,
    )


# -------------------------------------------------
# CONTRACT
# -------------------------------------------------


def test_tenable_csv_provider_implements_contract(
    tmp_path: Path,
) -> None:

    provider = build_provider(
        tmp_path
    )

    assert isinstance(
        provider,
        VulnerabilityProvider,
    )


# -------------------------------------------------
# NORMALIZATION
# -------------------------------------------------


def test_tenable_csv_provider_normalizes_models(
    tmp_path: Path,
) -> None:

    provider = build_provider(
        tmp_path
    )

    finding = provider.get_finding(
        "FIND-TENABLE-0001"
    )

    asset = provider.get_asset_context(
        "server01"
    )

    threat = provider.get_threat_intel(
        "CVE-2026-12345"
    )

    assert finding.asset_name == (
        "server01"
    )

    assert finding.cve == (
        "CVE-2026-12345"
    )

    assert finding.cvss == 9.8

    assert finding.patch_available is True

    assert asset.owner == (
        "Infrastructure Team"
    )

    assert threat.epss == 0.94

    assert threat.kev is True

    assert threat.data_source == (
        "Tenable Vulnerability Management"
    )


# -------------------------------------------------
# CVSS PRECEDENCE
# -------------------------------------------------


def test_tenable_csv_prefers_cvss4(
    tmp_path: Path,
) -> None:

    provider = build_provider(
        tmp_path
    )

    finding = provider.get_finding(
        "FIND-TENABLE-0001"
    )

    assert finding.cvss == 9.8


def test_tenable_csv_falls_back_to_cvss3(
    tmp_path: Path,
) -> None:

    provider = build_provider(
        tmp_path,
        finding=finding_row(
            **{
                "definition.cvss4.base_score":
                    "",
            }
        ),
    )

    finding = provider.get_finding(
        "FIND-TENABLE-0001"
    )

    assert finding.cvss == 9.1


def test_tenable_csv_falls_back_to_cvss2(
    tmp_path: Path,
) -> None:

    provider = build_provider(
        tmp_path,
        finding=finding_row(
            **{
                "definition.cvss4.base_score":
                    "",

                "definition.cvss3.base_score":
                    "",
            }
        ),
    )

    finding = provider.get_finding(
        "FIND-TENABLE-0001"
    )

    assert finding.cvss == 7.5


def test_tenable_csv_rejects_missing_cvss(
    tmp_path: Path,
) -> None:

    with pytest.raises(
        TenableCsvImportError,
        match="supported CVSS",
    ):

        build_provider(
            tmp_path,
            finding=finding_row(
                **{
                    "definition.cvss4.base_score":
                        "",

                    "definition.cvss3.base_score":
                        "",

                    "definition.cvss2.base_score":
                        "",
                }
            ),
        )


# -------------------------------------------------
# CVE
# -------------------------------------------------


def test_tenable_csv_rejects_multiple_cves(
    tmp_path: Path,
) -> None:

    with pytest.raises(
        TenableCsvImportError,
        match="exactly one CVE",
    ):

        build_provider(
            tmp_path,
            finding=finding_row(
                **{
                    "definition.cve": (
                        "CVE-2026-12345,"
                        "CVE-2026-99999"
                    )
                }
            ),
        )


# -------------------------------------------------
# EPSS
# -------------------------------------------------


def test_tenable_csv_normalizes_epss_percentage(
    tmp_path: Path,
) -> None:

    provider = build_provider(
        tmp_path,
        finding=finding_row(
            **{
                "definition.epss.score":
                    "72.5",
            }
        ),
    )

    threat = provider.get_threat_intel(
        "CVE-2026-12345"
    )

    assert threat.epss == 0.725


def test_tenable_csv_rejects_invalid_epss(
    tmp_path: Path,
) -> None:

    with pytest.raises(
        TenableCsvImportError,
        match="outside the supported range",
    ):

        build_provider(
            tmp_path,
            finding=finding_row(
                **{
                    "definition.epss.score":
                        "101",
                }
            ),
        )


# -------------------------------------------------
# KEV
# -------------------------------------------------


def test_tenable_csv_rejects_unknown_kev_value(
    tmp_path: Path,
) -> None:

    with pytest.raises(
        TenableCsvImportError,
        match="invalid boolean",
    ):

        build_provider(
            tmp_path,
            finding=finding_row(
                **{
                    "definition.vpr."
                    "drivers_on_cisa_kev":
                        "unknown",
                }
            ),
        )


# -------------------------------------------------
# PATCH AVAILABILITY
# -------------------------------------------------


def test_tenable_csv_patch_published_means_patch_available(
    tmp_path: Path,
) -> None:

    provider = build_provider(
        tmp_path
    )

    finding = provider.get_finding(
        "FIND-TENABLE-0001"
    )

    assert finding.patch_available is True


def test_tenable_csv_blank_patch_status_fails_closed(
    tmp_path: Path,
) -> None:

    with pytest.raises(
        TenableCsvImportError,
        match="explicit patch availability",
    ):

        build_provider(
            tmp_path,
            finding=finding_row(
                **{
                    "definition.patch_published":
                        "",
                }
            ),
        )


def test_tenable_csv_patch_override_can_explicitly_set_false(
    tmp_path: Path,
) -> None:

    provider = build_provider(
        tmp_path,
        finding=finding_row(
            **{
                "definition.patch_published":
                    "",
            }
        ),
        patch_overrides={
            "FIND-TENABLE-0001":
                False,
        },
    )

    finding = provider.get_finding(
        "FIND-TENABLE-0001"
    )

    assert finding.patch_available is False


# -------------------------------------------------
# CURRENT ASSET
# -------------------------------------------------


def test_tenable_csv_rejects_terminated_asset(
    tmp_path: Path,
) -> None:

    provider = build_provider(
        tmp_path,
        asset=asset_row(
            terminated_at=
                "2026-08-20T00:00:00Z",
        ),
    )

    with pytest.raises(
        ValueError,
        match="deleted or terminated",
    ):

        provider.get_finding(
            "FIND-TENABLE-0001"
        )


# -------------------------------------------------
# REQUIRED HEADERS
# -------------------------------------------------


def test_tenable_csv_rejects_missing_required_column(
    tmp_path: Path,
) -> None:

    row = finding_row()

    fieldnames = [
        field
        for field
        in row.keys()
        if field != "asset.id"
    ]

    finding_csv = write_csv(
        tmp_path / "tenable-findings.csv",
        [
            row
        ],
        fieldnames=fieldnames,
    )

    asset_csv = write_csv(
        tmp_path / "tenable-assets.csv",
        [
            asset_row()
        ],
    )

    with pytest.raises(
        TenableCsvImportError,
        match="missing required columns",
    ):

        TenableCsvProvider(
            vulnerability_csv_path=
                finding_csv,

            asset_csv_path=
                asset_csv,

            asset_context_by_uuid=
                asset_context(),
        )


# -------------------------------------------------
# EXTRA TENABLE COLUMNS
# -------------------------------------------------


def test_tenable_csv_allows_extra_vendor_columns(
    tmp_path: Path,
) -> None:

    provider = build_provider(
        tmp_path,
        finding=finding_row(
            output=(
                "Additional Tenable "
                "plugin output"
            ),
        ),
    )

    finding = provider.get_finding(
        "FIND-TENABLE-0001"
    )

    assert finding.finding_id == (
        "FIND-TENABLE-0001"
    )