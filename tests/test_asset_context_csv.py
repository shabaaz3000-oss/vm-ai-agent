import csv

from pathlib import Path

import pytest

from app.models import AssetContext

from app.providers.asset_context_csv import (
    ASSET_CONTEXT_CSV_COLUMNS,
    AssetContextCsvError,
    AssetContextCsvLoader,
    load_asset_context_csv,
)


ASSET_UUID_1 = (
    "11111111-1111-1111-1111-111111111111"
)

ASSET_UUID_2 = (
    "22222222-2222-2222-2222-222222222222"
)


# -------------------------------------------------
# HELPERS
# -------------------------------------------------


def context_row(
    **overrides: str,
) -> dict[str, str]:

    row = {
        "asset_uuid":
            ASSET_UUID_1,

        "asset_name":
            "server01",

        "owner":
            "Infrastructure Team",

        "application":
            "Customer Portal",

        "environment":
            "production",

        "business_criticality":
            "critical",

        "internet_exposed":
            "true",

        "data_classification":
            "confidential",

        "current_controls":
            "EDR;WAF;SIEM Logging",
    }

    row.update(
        overrides
    )

    return row


def write_context_csv(
    path: Path,
    rows: list[dict[str, str]],
    *,
    fieldnames: list[str] | None = None,
) -> Path:

    selected_fields = (
        list(
            ASSET_CONTEXT_CSV_COLUMNS
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
# VALID NORMALIZATION
# -------------------------------------------------


def test_asset_context_csv_loads_valid_context(
    tmp_path: Path,
) -> None:

    csv_path = write_context_csv(
        tmp_path / "asset-context.csv",
        [
            context_row()
        ],
    )

    contexts = (
        AssetContextCsvLoader(
            csv_path
        )
        .load()
    )

    assert list(
        contexts.keys()
    ) == [
        ASSET_UUID_1
    ]

    context = contexts[
        ASSET_UUID_1
    ]

    assert isinstance(
        context,
        AssetContext,
    )

    assert context.asset_name == (
        "server01"
    )

    assert context.owner == (
        "Infrastructure Team"
    )

    assert context.application == (
        "Customer Portal"
    )

    assert context.environment == (
        "production"
    )

    assert (
        context.business_criticality
        == "critical"
    )

    assert (
        context.internet_exposed
        is True
    )

    assert context.current_controls == [
        "EDR",
        "WAF",
        "SIEM Logging",
    ]


# -------------------------------------------------
# CONVENIENCE FUNCTION
# -------------------------------------------------


def test_load_asset_context_csv_convenience_function(
    tmp_path: Path,
) -> None:

    csv_path = write_context_csv(
        tmp_path / "asset-context.csv",
        [
            context_row()
        ],
    )

    contexts = (
        load_asset_context_csv(
            csv_path
        )
    )

    assert (
        contexts[
            ASSET_UUID_1
        ]
        .asset_name
        == "server01"
    )


# -------------------------------------------------
# MULTIPLE ASSETS
# -------------------------------------------------


def test_asset_context_csv_loads_multiple_assets(
    tmp_path: Path,
) -> None:

    csv_path = write_context_csv(
        tmp_path / "asset-context.csv",
        [
            context_row(),

            context_row(
                asset_uuid=
                    ASSET_UUID_2,

                asset_name=
                    "server02",

                owner=
                    "Database Team",

                application=
                    "Payments Database",

                internet_exposed=
                    "false",
            ),
        ],
    )

    contexts = (
        AssetContextCsvLoader(
            csv_path
        )
        .load()
    )

    assert len(
        contexts
    ) == 2

    assert (
        contexts[
            ASSET_UUID_2
        ]
        .asset_name
        == "server02"
    )

    assert (
        contexts[
            ASSET_UUID_2
        ]
        .internet_exposed
        is False
    )


# -------------------------------------------------
# OPTIONAL CONTROLS
# -------------------------------------------------


def test_asset_context_csv_allows_blank_controls(
    tmp_path: Path,
) -> None:

    csv_path = write_context_csv(
        tmp_path / "asset-context.csv",
        [
            context_row(
                current_controls=""
            )
        ],
    )

    contexts = (
        load_asset_context_csv(
            csv_path
        )
    )

    assert (
        contexts[
            ASSET_UUID_1
        ]
        .current_controls
        == []
    )


# -------------------------------------------------
# UUID UNIQUENESS
# -------------------------------------------------


def test_asset_context_csv_rejects_duplicate_uuid(
    tmp_path: Path,
) -> None:

    csv_path = write_context_csv(
        tmp_path / "asset-context.csv",
        [
            context_row(),

            context_row(
                asset_name=
                    "different-server"
            ),
        ],
    )

    with pytest.raises(
        AssetContextCsvError,
        match="duplicate asset UUIDs",
    ):

        load_asset_context_csv(
            csv_path
        )


# -------------------------------------------------
# SCHEMA
# -------------------------------------------------


def test_asset_context_csv_rejects_missing_column(
    tmp_path: Path,
) -> None:

    fieldnames = [
        column
        for column
        in ASSET_CONTEXT_CSV_COLUMNS
        if column != "owner"
    ]

    csv_path = write_context_csv(
        tmp_path / "asset-context.csv",
        [
            context_row()
        ],
        fieldnames=fieldnames,
    )

    with pytest.raises(
        AssetContextCsvError,
        match="missing required columns",
    ):

        load_asset_context_csv(
            csv_path
        )


def test_asset_context_csv_rejects_unexpected_column(
    tmp_path: Path,
) -> None:

    row = context_row()

    row[
        "unexpected"
    ] = "value"

    fieldnames = [
        *ASSET_CONTEXT_CSV_COLUMNS,
        "unexpected",
    ]

    csv_path = write_context_csv(
        tmp_path / "asset-context.csv",
        [
            row
        ],
        fieldnames=fieldnames,
    )

    with pytest.raises(
        AssetContextCsvError,
        match="unexpected columns",
    ):

        load_asset_context_csv(
            csv_path
        )


# -------------------------------------------------
# BOOLEAN
# -------------------------------------------------


def test_asset_context_csv_rejects_bad_boolean(
    tmp_path: Path,
) -> None:

    csv_path = write_context_csv(
        tmp_path / "asset-context.csv",
        [
            context_row(
                internet_exposed="yes"
            )
        ],
    )

    with pytest.raises(
        AssetContextCsvError,
        match="invalid boolean",
    ):

        load_asset_context_csv(
            csv_path
        )


# -------------------------------------------------
# PYDANTIC DOMAIN VALIDATION
# -------------------------------------------------


def test_asset_context_csv_rejects_invalid_environment(
    tmp_path: Path,
) -> None:

    csv_path = write_context_csv(
        tmp_path / "asset-context.csv",
        [
            context_row(
                environment="staging"
            )
        ],
    )

    with pytest.raises(
        AssetContextCsvError,
        match="failed model validation",
    ):

        load_asset_context_csv(
            csv_path
        )


def test_asset_context_csv_rejects_invalid_criticality(
    tmp_path: Path,
) -> None:

    csv_path = write_context_csv(
        tmp_path / "asset-context.csv",
        [
            context_row(
                business_criticality=
                    "extreme"
            )
        ],
    )

    with pytest.raises(
        AssetContextCsvError,
        match="failed model validation",
    ):

        load_asset_context_csv(
            csv_path
        )


# -------------------------------------------------
# REQUIRED VALUES
# -------------------------------------------------


def test_asset_context_csv_rejects_blank_required_value(
    tmp_path: Path,
) -> None:

    csv_path = write_context_csv(
        tmp_path / "asset-context.csv",
        [
            context_row(
                owner=""
            )
        ],
    )

    with pytest.raises(
        AssetContextCsvError,
        match="blank required value",
    ):

        load_asset_context_csv(
            csv_path
        )


# -------------------------------------------------
# CONTROL FORMAT
# -------------------------------------------------


def test_asset_context_csv_rejects_empty_control_entry(
    tmp_path: Path,
) -> None:

    csv_path = write_context_csv(
        tmp_path / "asset-context.csv",
        [
            context_row(
                current_controls=
                    "EDR;;WAF"
            )
        ],
    )

    with pytest.raises(
        AssetContextCsvError,
        match="invalid current controls",
    ):

        load_asset_context_csv(
            csv_path
        )


# -------------------------------------------------
# ERROR SANITIZATION
# -------------------------------------------------


def test_asset_context_csv_error_does_not_disclose_bad_value(
    tmp_path: Path,
) -> None:

    secret_marker = (
        "DO_NOT_LEAK_THIS_VALUE"
    )

    csv_path = write_context_csv(
        tmp_path / "asset-context.csv",
        [
            context_row(
                environment=
                    secret_marker
            )
        ],
    )

    with pytest.raises(
        AssetContextCsvError
    ) as exc_info:

        load_asset_context_csv(
            csv_path
        )

    assert (
        secret_marker
        not in str(
            exc_info.value
        )
    )