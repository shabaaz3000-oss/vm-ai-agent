from __future__ import annotations

import csv

from math import isfinite
from pathlib import Path
from typing import Mapping

from pydantic import ValidationError

from app.models import AssetContext
from app.models import ThreatIntel
from app.models import VulnerabilityFinding

from app.providers.base import VulnerabilityProvider


# -------------------------------------------------
# CSV IMPORT ERROR
# -------------------------------------------------


class CsvImportError(ValueError):
    """
    Raised when CSV input cannot be safely accepted.
    """


# -------------------------------------------------
# CANONICAL CSV SCHEMA
# -------------------------------------------------


CANONICAL_CSV_COLUMNS: tuple[str, ...] = (
    "finding_id",
    "asset_name",
    "cve",
    "title",
    "description",
    "cvss",
    "patch_available",
    "owner",
    "application",
    "environment",
    "business_criticality",
    "internet_exposed",
    "data_classification",
    "current_controls",
    "epss",
    "kev",
    "data_source",
)


# -------------------------------------------------
# SECURE CSV READER
# -------------------------------------------------


class SecureCsvReader:
    """
    Safely loads untrusted CSV input.

    This layer performs structural validation only.

    It does NOT:

    - determine authoritative risk
    - call AI
    - approve workflows
    - create tickets
    - execute remediation
    - bypass Pydantic/domain validation

    Domain normalization is performed by
    CsvImportProvider.
    """

    DEFAULT_MAX_FILE_BYTES = 5_000_000
    DEFAULT_MAX_ROWS = 10_000
    DEFAULT_MAX_COLUMNS = 100

    def __init__(
        self,
        path: str | Path,
        *,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_rows: int = DEFAULT_MAX_ROWS,
        max_columns: int = DEFAULT_MAX_COLUMNS,
    ) -> None:

        self.path = Path(
            path
        )

        if max_file_bytes <= 0:
            raise ValueError(
                "max_file_bytes must be positive"
            )

        if max_rows <= 0:
            raise ValueError(
                "max_rows must be positive"
            )

        if max_columns <= 0:
            raise ValueError(
                "max_columns must be positive"
            )

        self.max_file_bytes = (
            max_file_bytes
        )

        self.max_rows = (
            max_rows
        )

        self.max_columns = (
            max_columns
        )


    # -------------------------------------------------
    # READ
    # -------------------------------------------------


    def read_rows(
        self
    ) -> list[dict[str, str]]:

        self._validate_path()

        try:

            file_size = (
                self.path
                .stat()
                .st_size
            )

        except OSError as exc:

            raise CsvImportError(
                "CSV file metadata could not be read"
            ) from exc

        if file_size == 0:

            raise CsvImportError(
                "CSV file is empty"
            )

        if (
            file_size
            > self.max_file_bytes
        ):

            raise CsvImportError(
                "CSV file exceeds the configured "
                "size limit"
            )

        try:

            with self.path.open(
                "r",
                encoding="utf-8-sig",
                newline="",
            ) as handle:

                reader = csv.DictReader(
                    handle
                )

                headers = (
                    self._validate_headers(
                        reader.fieldnames
                    )
                )

                rows: list[
                    dict[str, str]
                ] = []

                try:

                    for (
                        row_number,
                        raw_row
                    ) in enumerate(
                        reader,
                        start=2,
                    ):

                        if (
                            len(rows)
                            >= self.max_rows
                        ):

                            raise CsvImportError(
                                "CSV file exceeds the "
                                "configured row limit"
                            )

                        row = (
                            self._validate_row(
                                raw_row,
                                headers=headers,
                                row_number=row_number,
                            )
                        )

                        rows.append(
                            row
                        )

                except csv.Error as exc:

                    raise CsvImportError(
                        "CSV file is malformed"
                    ) from exc

        except UnicodeDecodeError as exc:

            raise CsvImportError(
                "CSV file must be valid UTF-8"
            ) from exc

        except OSError as exc:

            raise CsvImportError(
                "CSV file could not be read"
            ) from exc

        if not rows:

            raise CsvImportError(
                "CSV file contains no data rows"
            )

        return rows


    # -------------------------------------------------
    # PATH VALIDATION
    # -------------------------------------------------


    def _validate_path(
        self
    ) -> None:

        if (
            self.path.suffix.lower()
            != ".csv"
        ):

            raise CsvImportError(
                "Import file must use the "
                ".csv extension"
            )

        if not self.path.exists():

            raise CsvImportError(
                "CSV file does not exist"
            )

        if not self.path.is_file():

            raise CsvImportError(
                "CSV import path must reference "
                "a file"
            )


    # -------------------------------------------------
    # HEADER VALIDATION
    # -------------------------------------------------


    def _validate_headers(
        self,
        fieldnames: list[str] | None,
    ) -> list[str]:

        if not fieldnames:

            raise CsvImportError(
                "CSV file does not contain "
                "a valid header row"
            )

        if (
            len(fieldnames)
            > self.max_columns
        ):

            raise CsvImportError(
                "CSV file exceeds the configured "
                "column limit"
            )

        normalized_headers: list[str] = []

        for header in fieldnames:

            normalized = (
                header.strip()
            )

            if not normalized:

                raise CsvImportError(
                    "CSV file contains a blank "
                    "column name"
                )

            normalized_headers.append(
                normalized
            )

        if (
            len(normalized_headers)
            != len(
                set(
                    normalized_headers
                )
            )
        ):

            raise CsvImportError(
                "CSV file contains duplicate "
                "column names"
            )

        return normalized_headers


    # -------------------------------------------------
    # ROW STRUCTURE VALIDATION
    # -------------------------------------------------


    @staticmethod
    def _validate_row(
        raw_row: Mapping[
            str | None,
            str | list[str] | None,
        ],
        *,
        headers: list[str],
        row_number: int,
    ) -> dict[str, str]:

        # DictReader places unexpected extra cells
        # under the None key.

        if None in raw_row:

            raise CsvImportError(
                f"CSV row {row_number} contains "
                "more fields than the header"
            )

        validated_row: dict[
            str,
            str,
        ] = {}

        for (
            original_header,
            normalized_header,
        ) in zip(
            raw_row.keys(),
            headers,
            strict=True,
        ):

            if original_header is None:

                raise CsvImportError(
                    f"CSV row {row_number} "
                    "contains an invalid column"
                )

            value = (
                raw_row[
                    original_header
                ]
            )

            if isinstance(
                value,
                list,
            ):

                raise CsvImportError(
                    f"CSV row {row_number} "
                    "contains an invalid field"
                )

            if value is None:

                value = ""

            validated_row[
                normalized_header
            ] = value.strip()

        if (
            len(validated_row)
            != len(headers)
        ):

            raise CsvImportError(
                f"CSV row {row_number} does not "
                "match the header structure"
            )

        return validated_row


# -------------------------------------------------
# CSV VULNERABILITY PROVIDER
# -------------------------------------------------


class CsvImportProvider(
    VulnerabilityProvider
):

    """
    Vulnerability provider backed by a manually
    supplied canonical CSV export.

    The provider normalizes CSV input into the same
    domain models used by every other vulnerability
    provider.

    CSV input is treated as untrusted.

    This provider does NOT:

    - calculate authoritative risk
    - call the AI analyzer
    - approve workflows
    - create tickets
    - perform external remediation actions
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

        reader = SecureCsvReader(
            path,
            max_file_bytes=max_file_bytes,
            max_rows=max_rows,
        )

        rows = (
            reader.read_rows()
        )

        self._validate_schema(
            rows
        )

        self._findings: dict[
            str,
            VulnerabilityFinding,
        ] = {}

        self._assets: dict[
            str,
            AssetContext,
        ] = {}

        self._threat_intel: dict[
            str,
            ThreatIntel,
        ] = {}

        for (
            row_number,
            row,
        ) in enumerate(
            rows,
            start=2,
        ):

            finding = (
                self._build_finding(
                    row,
                    row_number=row_number,
                )
            )

            asset = (
                self._build_asset_context(
                    row,
                    row_number=row_number,
                )
            )

            threat = (
                self._build_threat_intel(
                    row,
                    row_number=row_number,
                )
            )

            # -----------------------------------------
            # FINDING UNIQUENESS
            # -----------------------------------------

            if (
                finding.finding_id
                in self._findings
            ):

                raise CsvImportError(
                    "CSV file contains duplicate "
                    "finding IDs"
                )

            self._findings[
                finding.finding_id
            ] = finding

            # -----------------------------------------
            # ASSET CONSISTENCY
            # -----------------------------------------

            existing_asset = (
                self._assets.get(
                    asset.asset_name
                )
            )

            if (
                existing_asset
                is not None
                and existing_asset != asset
            ):

                raise CsvImportError(
                    "CSV file contains conflicting "
                    "asset context"
                )

            if existing_asset is None:

                self._assets[
                    asset.asset_name
                ] = asset

            # -----------------------------------------
            # THREAT INTEL CONSISTENCY
            # -----------------------------------------

            existing_threat = (
                self._threat_intel.get(
                    threat.cve
                )
            )

            if (
                existing_threat
                is not None
                and existing_threat != threat
            ):

                raise CsvImportError(
                    "CSV file contains conflicting "
                    "threat intelligence"
                )

            if existing_threat is None:

                self._threat_intel[
                    threat.cve
                ] = threat


    # -------------------------------------------------
    # SCHEMA VALIDATION
    # -------------------------------------------------


    @staticmethod
    def _validate_schema(
        rows: list[dict[str, str]]
    ) -> None:

        actual_columns = set(
            rows[0].keys()
        )

        required_columns = set(
            CANONICAL_CSV_COLUMNS
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

            raise CsvImportError(
                "CSV file is missing required "
                "columns"
            )

        if unexpected_columns:

            raise CsvImportError(
                "CSV file contains unexpected "
                "columns"
            )


    # -------------------------------------------------
    # SAFE VALUE HELPERS
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

            raise CsvImportError(
                f"CSV row {row_number} contains "
                "a blank required value"
            )

        return value


    @staticmethod
    def _parse_boolean(
        value: str,
        *,
        row_number: int,
    ) -> bool:

        normalized = (
            value.strip().lower()
        )

        if normalized == "true":

            return True

        if normalized == "false":

            return False

        raise CsvImportError(
            f"CSV row {row_number} contains "
            "an invalid boolean value"
        )


    @staticmethod
    def _parse_number(
        value: str,
        *,
        row_number: int,
        allow_blank: bool = False,
    ) -> float | None:

        normalized = (
            value.strip()
        )

        if (
            allow_blank
            and not normalized
        ):

            return None

        if not normalized:

            raise CsvImportError(
                f"CSV row {row_number} contains "
                "a blank numeric value"
            )

        try:

            parsed = float(
                normalized
            )

        except ValueError as exc:

            raise CsvImportError(
                f"CSV row {row_number} contains "
                "invalid numeric data"
            ) from exc

        if not isfinite(
            parsed
        ):

            raise CsvImportError(
                f"CSV row {row_number} contains "
                "invalid numeric data"
            )

        return parsed


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

            raise CsvImportError(
                f"CSV row {row_number} contains "
                "invalid current controls"
            )

        return controls


    # -------------------------------------------------
    # MODEL BUILDERS
    # -------------------------------------------------


    @classmethod
    def _build_finding(
        cls,
        row: Mapping[str, str],
        *,
        row_number: int,
    ) -> VulnerabilityFinding:

        try:

            return (
                VulnerabilityFinding
                .model_validate(
                    {
                        "finding_id":
                            cls._require_nonblank(
                                row,
                                "finding_id",
                                row_number=row_number,
                            ),

                        "asset_name":
                            cls._require_nonblank(
                                row,
                                "asset_name",
                                row_number=row_number,
                            ),

                        "cve":
                            cls._require_nonblank(
                                row,
                                "cve",
                                row_number=row_number,
                            ),

                        "title":
                            cls._require_nonblank(
                                row,
                                "title",
                                row_number=row_number,
                            ),

                        "description":
                            cls._require_nonblank(
                                row,
                                "description",
                                row_number=row_number,
                            ),

                        "cvss":
                            cls._parse_number(
                                row["cvss"],
                                row_number=row_number,
                            ),

                        "patch_available":
                            cls._parse_boolean(
                                row[
                                    "patch_available"
                                ],
                                row_number=row_number,
                            ),
                    }
                )
            )

        except ValidationError as exc:

            raise CsvImportError(
                f"CSV row {row_number} failed "
                "finding validation"
            ) from exc


    @classmethod
    def _build_asset_context(
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
                                row_number=row_number,
                            ),

                        "owner":
                            cls._require_nonblank(
                                row,
                                "owner",
                                row_number=row_number,
                            ),

                        "application":
                            cls._require_nonblank(
                                row,
                                "application",
                                row_number=row_number,
                            ),

                        "environment":
                            cls._require_nonblank(
                                row,
                                "environment",
                                row_number=row_number,
                            ),

                        "business_criticality":
                            cls._require_nonblank(
                                row,
                                "business_criticality",
                                row_number=row_number,
                            ),

                        "internet_exposed":
                            cls._parse_boolean(
                                row[
                                    "internet_exposed"
                                ],
                                row_number=row_number,
                            ),

                        "data_classification":
                            cls._require_nonblank(
                                row,
                                "data_classification",
                                row_number=row_number,
                            ),

                        "current_controls":
                            cls._parse_controls(
                                row[
                                    "current_controls"
                                ],
                                row_number=row_number,
                            ),
                    }
                )
            )

        except ValidationError as exc:

            raise CsvImportError(
                f"CSV row {row_number} failed "
                "asset context validation"
            ) from exc


    @classmethod
    def _build_threat_intel(
        cls,
        row: Mapping[str, str],
        *,
        row_number: int,
    ) -> ThreatIntel:

        try:

            return (
                ThreatIntel
                .model_validate(
                    {
                        "cve":
                            cls._require_nonblank(
                                row,
                                "cve",
                                row_number=row_number,
                            ),

                        "epss":
                            cls._parse_number(
                                row["epss"],
                                row_number=row_number,
                                allow_blank=True,
                            ),

                        "kev":
                            cls._parse_boolean(
                                row["kev"],
                                row_number=row_number,
                            ),

                        "data_source":
                            cls._require_nonblank(
                                row,
                                "data_source",
                                row_number=row_number,
                            ),
                    }
                )
            )

        except ValidationError as exc:

            raise CsvImportError(
                f"CSV row {row_number} failed "
                "threat intelligence validation"
            ) from exc


    # -------------------------------------------------
    # FINDING
    # -------------------------------------------------


    def get_finding(
        self,
        finding_id: str
    ) -> VulnerabilityFinding:

        finding = (
            self._findings.get(
                finding_id
            )
        )

        if finding is None:

            raise KeyError(
                "Requested finding was not found: "
                f"{finding_id}"
            )

        return finding.model_copy(
            deep=True
        )


    # -------------------------------------------------
    # ASSET CONTEXT
    # -------------------------------------------------


    def get_asset_context(
        self,
        asset_name: str
    ) -> AssetContext:

        asset = (
            self._assets.get(
                asset_name
            )
        )

        if asset is None:

            raise KeyError(
                "Requested asset was not found: "
                f"{asset_name}"
            )

        return asset.model_copy(
            deep=True
        )


    # -------------------------------------------------
    # THREAT INTELLIGENCE
    # -------------------------------------------------


    def get_threat_intel(
        self,
        cve: str
    ) -> ThreatIntel:

        threat = (
            self._threat_intel.get(
                cve
            )
        )

        if threat is None:

            raise KeyError(
                "Requested CVE was not found: "
                f"{cve}"
            )

        return threat.model_copy(
            deep=True
        )