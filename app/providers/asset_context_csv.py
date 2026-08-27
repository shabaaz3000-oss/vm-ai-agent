from __future__ import annotations

from pathlib import Path
from typing import Mapping

from pydantic import ValidationError

from app.models import AssetContext

from app.providers.csv_import import SecureCsvReader


# -------------------------------------------------
# ASSET CONTEXT CSV ERROR
# -------------------------------------------------


class AssetContextCsvError(ValueError):
    """
    Raised when enterprise asset-context CSV input
    cannot be safely accepted.
    """


# -------------------------------------------------
# CANONICAL ASSET CONTEXT SCHEMA
# -------------------------------------------------


ASSET_CONTEXT_CSV_COLUMNS: tuple[str, ...] = (
    "asset_uuid",
    "asset_name",
    "owner",
    "application",
    "environment",
    "business_criticality",
    "internet_exposed",
    "data_classification",
    "current_controls",
)


# -------------------------------------------------
# ASSET CONTEXT CSV LOADER
# -------------------------------------------------


class AssetContextCsvLoader:

    """
    Load enterprise asset/business context from a
    canonical CSV file.

    The Tenable asset UUID is used as the correlation
    key.

    CSV input is treated as untrusted and must pass:

    - secure structural CSV validation
    - exact schema validation
    - UUID uniqueness validation
    - strict boolean parsing
    - Pydantic AssetContext validation

    This loader does NOT:

    - calculate vulnerability risk
    - call AI
    - approve workflows
    - create tickets
    - perform remediation
    """

    def __init__(
        self,
        path: str | Path,
        *,
        max_file_bytes: int
        = SecureCsvReader.DEFAULT_MAX_FILE_BYTES,
        max_rows: int
        = SecureCsvReader.DEFAULT_MAX_ROWS,
    ) -> None:

        self.path = Path(
            path
        )

        self.max_file_bytes = (
            max_file_bytes
        )

        self.max_rows = (
            max_rows
        )


    # -------------------------------------------------
    # LOAD
    # -------------------------------------------------


    def load(
        self
    ) -> dict[str, AssetContext]:

        rows = (
    SecureCsvReader(
        self.path,
        max_file_bytes=
            self.max_file_bytes,
        max_rows=
            self.max_rows,
        max_columns=
            SecureCsvReader
            .DEFAULT_MAX_COLUMNS,
    )
    .read_rows()
    )

        self._validate_schema(
            rows
        )

        contexts: dict[
            str,
            AssetContext,
        ] = {}

        for (
            row_number,
            row,
        ) in enumerate(
            rows,
            start=2,
        ):

            asset_uuid = (
                self._require_nonblank(
                    row,
                    "asset_uuid",
                    row_number=row_number,
                )
            )

            if asset_uuid in contexts:

                raise AssetContextCsvError(
                    "Asset context CSV contains "
                    "duplicate asset UUIDs."
                )

            context = (
                self._build_context(
                    row,
                    row_number=row_number,
                )
            )

            contexts[
                asset_uuid
            ] = context

        return {
            asset_uuid:
                context.model_copy(
                    deep=True
                )
            for (
                asset_uuid,
                context
            ) in contexts.items()
        }


    # -------------------------------------------------
    # SCHEMA
    # -------------------------------------------------


    @staticmethod
    def _validate_schema(
        rows: list[dict[str, str]]
    ) -> None:

        actual_columns = set(
            rows[0].keys()
        )

        required_columns = set(
            ASSET_CONTEXT_CSV_COLUMNS
        )

        missing_columns = (
            required_columns
            - actual_columns
        )

        unexpected_columns = (
            actual_columns
            - required_columns
        )

        if missing_columns:

            raise AssetContextCsvError(
                "Asset context CSV is missing "
                "required columns."
            )

        if unexpected_columns:

            raise AssetContextCsvError(
                "Asset context CSV contains "
                "unexpected columns."
            )


    # -------------------------------------------------
    # REQUIRED TEXT
    # -------------------------------------------------


    @staticmethod
    def _require_nonblank(
        row: Mapping[str, str],
        column: str,
        *,
        row_number: int,
    ) -> str:

        value = (
            row[column]
            .strip()
        )

        if not value:

            raise AssetContextCsvError(
                f"Asset context CSV row "
                f"{row_number} contains a blank "
                "required value."
            )

        return value


    # -------------------------------------------------
    # BOOLEAN
    # -------------------------------------------------


    @staticmethod
    def _parse_boolean(
        value: str,
        *,
        row_number: int,
    ) -> bool:

        normalized = (
            value
            .strip()
            .lower()
        )

        if normalized == "true":

            return True

        if normalized == "false":

            return False

        raise AssetContextCsvError(
            f"Asset context CSV row "
            f"{row_number} contains an invalid "
            "boolean value."
        )


    # -------------------------------------------------
    # CONTROLS
    # -------------------------------------------------


    @staticmethod
    def _parse_controls(
        value: str,
        *,
        row_number: int,
    ) -> list[str]:

        normalized = (
            value.strip()
        )

        if not normalized:

            return []

        controls = [
            control.strip()
            for control
            in normalized.split(";")
        ]

        if any(
            not control
            for control
            in controls
        ):

            raise AssetContextCsvError(
                f"Asset context CSV row "
                f"{row_number} contains invalid "
                "current controls."
            )

        return controls


    # -------------------------------------------------
    # PYDANTIC NORMALIZATION
    # -------------------------------------------------


    @classmethod
    def _build_context(
        cls,
        row: Mapping[str, str],
        *,
        row_number: int,
    ) -> AssetContext:

        try:

            return (
                AssetContext
                .model_validate(
                    {
                        "asset_name":
                            cls._require_nonblank(
                                row,
                                "asset_name",
                                row_number=
                                    row_number,
                            ),

                        "owner":
                            cls._require_nonblank(
                                row,
                                "owner",
                                row_number=
                                    row_number,
                            ),

                        "application":
                            cls._require_nonblank(
                                row,
                                "application",
                                row_number=
                                    row_number,
                            ),

                        "environment":
                            cls._require_nonblank(
                                row,
                                "environment",
                                row_number=
                                    row_number,
                            ),

                        "business_criticality":
                            cls._require_nonblank(
                                row,
                                "business_criticality",
                                row_number=
                                    row_number,
                            ),

                        "internet_exposed":
                            cls._parse_boolean(
                                row[
                                    "internet_exposed"
                                ],
                                row_number=
                                    row_number,
                            ),

                        "data_classification":
                            cls._require_nonblank(
                                row,
                                "data_classification",
                                row_number=
                                    row_number,
                            ),

                        "current_controls":
                            cls._parse_controls(
                                row[
                                    "current_controls"
                                ],
                                row_number=
                                    row_number,
                            ),
                    }
                )
            )

        except ValidationError as exc:

            raise AssetContextCsvError(
                f"Asset context CSV row "
                f"{row_number} failed model "
                "validation."
            ) from exc


# -------------------------------------------------
# CONVENIENCE FUNCTION
# -------------------------------------------------


def load_asset_context_csv(
    path: str | Path,
) -> dict[str, AssetContext]:

    return (
        AssetContextCsvLoader(
            path
        )
        .load()
    )