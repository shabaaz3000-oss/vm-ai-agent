import csv

from pathlib import Path

import pytest

from app.models import AssetContext
from app.models import ThreatIntel
from app.models import VulnerabilityFinding

from app.providers.base import VulnerabilityProvider

from app.providers.csv_import import (
    CANONICAL_CSV_COLUMNS,
    CsvImportError,
    CsvImportProvider,
)


# -------------------------------------------------
# TEST HELPERS
# -------------------------------------------------


def canonical_row(
    **overrides: str,
) -> dict[str, str]:

    row = {
        "finding_id": "FIND-0001",
        "asset_name": "server01",
        "cve": "CVE-2026-12345",
        "title": "Critical remote code execution",
        "description": (
            "Remote code execution vulnerability "
            "detected on the affected asset."
        ),
        "cvss": "9.8",
        "patch_available": "true",

        "owner": "Infrastructure Team",
        "application": "Customer Portal",
        "environment": "production",
        "business_criticality": "critical",
        "internet_exposed": "true",
        "data_classification": "confidential",
        "current_controls": "EDR;WAF;Network Segmentation",

        "epss": "0.91",
        "kev": "true",
        "data_source": "Manual CSV Import",
    }

    row.update(
        overrides
    )

    return row


def write_provider_csv(
    path: Path,
    rows: list[dict[str, str]],
    *,
    fieldnames: list[str] | None = None,
) -> Path:

    selected_fields = (
        list(
            CANONICAL_CSV_COLUMNS
        )
        if fieldnames is None
        else fieldnames
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


# -------------------------------------------------
# PROVIDER CONTRACT
# -------------------------------------------------


def test_csv_provider_implements_provider_contract(
    tmp_path: Path,
) -> None:

    csv_path = write_provider_csv(
        tmp_path / "findings.csv",
        [
            canonical_row()
        ],
    )

    provider = CsvImportProvider(
        csv_path
    )

    assert isinstance(
        provider,
        VulnerabilityProvider,
    )


# -------------------------------------------------
# VALID NORMALIZATION
# -------------------------------------------------


def test_csv_provider_returns_normalized_models(
    tmp_path: Path,
) -> None:

    csv_path = write_provider_csv(
        tmp_path / "findings.csv",
        [
            canonical_row()
        ],
    )

    provider = CsvImportProvider(
        csv_path
    )

    finding = (
        provider.get_finding(
            "FIND-0001"
        )
    )

    asset = (
        provider.get_asset_context(
            "server01"
        )
    )

    threat = (
        provider.get_threat_intel(
            "CVE-2026-12345"
        )
    )

    assert isinstance(
        finding,
        VulnerabilityFinding,
    )

    assert isinstance(
        asset,
        AssetContext,
    )

    assert isinstance(
        threat,
        ThreatIntel,
    )

    assert finding.finding_id == (
        "FIND-0001"
    )

    assert finding.asset_name == (
        "server01"
    )

    assert finding.cvss == 9.8

    assert finding.patch_available is True

    assert asset.environment == (
        "production"
    )

    assert asset.business_criticality == (
        "critical"
    )

    assert asset.internet_exposed is True

    assert asset.current_controls == [
        "EDR",
        "WAF",
        "Network Segmentation",
    ]

    assert threat.epss == 0.91

    assert threat.kev is True

    assert threat.data_source == (
        "Manual CSV Import"
    )


def test_csv_provider_allows_blank_epss_and_controls(
    tmp_path: Path,
) -> None:

    csv_path = write_provider_csv(
        tmp_path / "findings.csv",
        [
            canonical_row(
                epss="",
                current_controls="",
            )
        ],
    )

    provider = CsvImportProvider(
        csv_path
    )

    asset = (
        provider.get_asset_context(
            "server01"
        )
    )

    threat = (
        provider.get_threat_intel(
            "CVE-2026-12345"
        )
    )

    assert asset.current_controls == []

    assert threat.epss is None


# -------------------------------------------------
# FINDING UNIQUENESS
# -------------------------------------------------


def test_csv_provider_rejects_duplicate_finding_ids(
    tmp_path: Path,
) -> None:

    csv_path = write_provider_csv(
        tmp_path / "findings.csv",
        [
            canonical_row(),
            canonical_row(),
        ],
    )

    with pytest.raises(
        CsvImportError,
        match="duplicate finding IDs",
    ):

        CsvImportProvider(
            csv_path
        )


# -------------------------------------------------
# ASSET CONSISTENCY
# -------------------------------------------------


def test_csv_provider_rejects_conflicting_asset_context(
    tmp_path: Path,
) -> None:

    first = canonical_row()

    second = canonical_row(
        finding_id="FIND-0002",
        owner="Different Owner",
    )

    csv_path = write_provider_csv(
        tmp_path / "findings.csv",
        [
            first,
            second,
        ],
    )

    with pytest.raises(
        CsvImportError,
        match="conflicting asset context",
    ):

        CsvImportProvider(
            csv_path
        )


# -------------------------------------------------
# THREAT INTEL CONSISTENCY
# -------------------------------------------------


def test_csv_provider_rejects_conflicting_threat_intel(
    tmp_path: Path,
) -> None:

    first = canonical_row()

    second = canonical_row(
        finding_id="FIND-0002",
        asset_name="server02",
        epss="0.25",
    )

    csv_path = write_provider_csv(
        tmp_path / "findings.csv",
        [
            first,
            second,
        ],
    )

    with pytest.raises(
        CsvImportError,
        match="conflicting threat intelligence",
    ):

        CsvImportProvider(
            csv_path
        )


# -------------------------------------------------
# NUMERIC VALIDATION
# -------------------------------------------------


def test_csv_provider_rejects_invalid_cvss(
    tmp_path: Path,
) -> None:

    csv_path = write_provider_csv(
        tmp_path / "findings.csv",
        [
            canonical_row(
                cvss="11"
            )
        ],
    )

    with pytest.raises(
        CsvImportError,
        match="finding validation",
    ):

        CsvImportProvider(
            csv_path
        )


def test_csv_provider_rejects_invalid_epss(
    tmp_path: Path,
) -> None:

    csv_path = write_provider_csv(
        tmp_path / "findings.csv",
        [
            canonical_row(
                epss="1.5"
            )
        ],
    )

    with pytest.raises(
        CsvImportError,
        match="threat intelligence validation",
    ):

        CsvImportProvider(
            csv_path
        )


@pytest.mark.parametrize(
    "bad_value",
    [
        "nan",
        "inf",
    ],
)
def test_csv_provider_rejects_nonfinite_numbers(
    tmp_path: Path,
    bad_value: str,
) -> None:

    csv_path = write_provider_csv(
        tmp_path / "findings.csv",
        [
            canonical_row(
                cvss=bad_value
            )
        ],
    )

    with pytest.raises(
        CsvImportError,
        match="invalid numeric data",
    ):

        CsvImportProvider(
            csv_path
        )


# -------------------------------------------------
# STRICT BOOLEAN VALIDATION
# -------------------------------------------------


@pytest.mark.parametrize(
    "field_name",
    [
        "patch_available",
        "internet_exposed",
        "kev",
    ],
)
def test_csv_provider_rejects_malformed_booleans(
    tmp_path: Path,
    field_name: str,
) -> None:

    row = canonical_row()

    row[
        field_name
    ] = "yes"

    csv_path = write_provider_csv(
        tmp_path / "findings.csv",
        [
            row
        ],
    )

    with pytest.raises(
        CsvImportError,
        match="invalid boolean value",
    ):

        CsvImportProvider(
            csv_path
        )


# -------------------------------------------------
# CANONICAL SCHEMA
# -------------------------------------------------


def test_csv_provider_rejects_missing_required_column(
    tmp_path: Path,
) -> None:

    fieldnames = [
        column
        for column
        in CANONICAL_CSV_COLUMNS
        if column != "data_source"
    ]

    csv_path = write_provider_csv(
        tmp_path / "findings.csv",
        [
            canonical_row()
        ],
        fieldnames=fieldnames,
    )

    with pytest.raises(
        CsvImportError,
        match="missing required columns",
    ):

        CsvImportProvider(
            csv_path
        )


def test_csv_provider_rejects_unexpected_column(
    tmp_path: Path,
) -> None:

    row = canonical_row()

    row[
        "unexpected_column"
    ] = "UNTRUSTED"

    fieldnames = [
        *CANONICAL_CSV_COLUMNS,
        "unexpected_column",
    ]

    csv_path = write_provider_csv(
        tmp_path / "findings.csv",
        [
            row
        ],
        fieldnames=fieldnames,
    )

    with pytest.raises(
        CsvImportError,
        match="unexpected columns",
    ):

        CsvImportProvider(
            csv_path
        )


# -------------------------------------------------
# REQUIRED DATA
# -------------------------------------------------


def test_csv_provider_rejects_blank_required_value(
    tmp_path: Path,
) -> None:

    csv_path = write_provider_csv(
        tmp_path / "findings.csv",
        [
            canonical_row(
                title=""
            )
        ],
    )

    with pytest.raises(
        CsvImportError,
        match="blank required value",
    ):

        CsvImportProvider(
            csv_path
        )


def test_csv_provider_rejects_invalid_environment(
    tmp_path: Path,
) -> None:

    csv_path = write_provider_csv(
        tmp_path / "findings.csv",
        [
            canonical_row(
                environment="staging"
            )
        ],
    )

    with pytest.raises(
        CsvImportError,
        match="asset context validation",
    ):

        CsvImportProvider(
            csv_path
        )


# -------------------------------------------------
# LOOKUP FAILURE
# -------------------------------------------------


def test_csv_provider_rejects_unknown_finding(
    tmp_path: Path,
) -> None:

    csv_path = write_provider_csv(
        tmp_path / "findings.csv",
        [
            canonical_row()
        ],
    )

    provider = CsvImportProvider(
        csv_path
    )

    with pytest.raises(
        KeyError,
        match="FIND-9999",
    ):

        provider.get_finding(
            "FIND-9999"
        )


def test_csv_provider_rejects_unknown_asset(
    tmp_path: Path,
) -> None:

    csv_path = write_provider_csv(
        tmp_path / "findings.csv",
        [
            canonical_row()
        ],
    )

    provider = CsvImportProvider(
        csv_path
    )

    with pytest.raises(
        KeyError,
        match="server99",
    ):

        provider.get_asset_context(
            "server99"
        )


def test_csv_provider_rejects_unknown_cve(
    tmp_path: Path,
) -> None:

    csv_path = write_provider_csv(
        tmp_path / "findings.csv",
        [
            canonical_row()
        ],
    )

    provider = CsvImportProvider(
        csv_path
    )

    with pytest.raises(
        KeyError,
        match="CVE-2026-99999",
    ):

        provider.get_threat_intel(
            "CVE-2026-99999"
        )


# -------------------------------------------------
# ERROR SANITIZATION
# -------------------------------------------------


def test_csv_provider_error_does_not_disclose_bad_value(
    tmp_path: Path,
) -> None:

    secret_marker = (
        "DO_NOT_LEAK_THIS_VALUE"
    )

    csv_path = write_provider_csv(
        tmp_path / "findings.csv",
        [
            canonical_row(
                cvss=secret_marker
            )
        ],
    )

    with pytest.raises(
        CsvImportError
    ) as exc_info:

        CsvImportProvider(
            csv_path
        )

    assert (
        secret_marker
        not in str(
            exc_info.value
        )
    )