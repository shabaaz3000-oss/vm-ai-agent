from __future__ import annotations

import re

from pathlib import Path
from typing import Mapping

from app.models import AssetContext
from app.models import ThreatIntel
from app.models import VulnerabilityFinding

from app.providers.base import VulnerabilityProvider
from app.providers.csv_import import SecureCsvReader
from app.providers.tenable import TenableProvider


# -------------------------------------------------
# TENABLE CSV IMPORT ERROR
# -------------------------------------------------


class TenableCsvImportError(ValueError):
    """
    Raised when a Tenable CSV export cannot be
    safely normalized.
    """


# -------------------------------------------------
# TENABLE CSV PROVIDER
# -------------------------------------------------


class TenableCsvProvider(
    VulnerabilityProvider
):

    """
    Vulnerability provider backed by Tenable
    Vulnerability Management CSV exports.

    This adapter converts Tenable's flat CSV export
    fields into the same raw record structure consumed
    by TenableProvider.

    TenableProvider remains authoritative for:

    - asset UUID correlation
    - CVSS precedence
    - EPSS normalization
    - KEV handling
    - current asset checks
    - enterprise context
    - Pydantic normalization

    CSV input is always treated as untrusted.
    """

    REQUIRED_FINDING_COLUMNS = {
        "id",
        "asset.id",
        "definition.cve",
        "definition.name",
        "definition.description",
        "definition.epss.score",
        "definition.vpr.drivers_on_cisa_kev",
    }

    REQUIRED_ASSET_COLUMNS = {
        "id",
        "terminated_at",
    }

    CVSS_COLUMNS = (
        (
            "definition.cvss4.base_score",
            "cvss4_base_score",
        ),
        (
            "definition.cvss3.base_score",
            "cvss3_base_score",
        ),
        (
            "definition.cvss2.base_score",
            "cvss_base_score",
        ),
    )

    CVE_PATTERN = re.compile(
        r"\bCVE-\d{4}-\d{4,}\b",
        re.IGNORECASE,
    )


    def __init__(
        self,
        vulnerability_csv_path: str | Path,
        asset_csv_path: str | Path,
        asset_context_by_uuid: dict,
        *,
        patch_available_by_finding_id:
            Mapping[str, bool] | None = None,
        max_rows: int = 10_000,
    ) -> None:

        self._patch_overrides = (
            self._validate_patch_overrides(
                patch_available_by_finding_id
            )
        )

        vulnerability_rows = (
            SecureCsvReader(
                vulnerability_csv_path,
                max_rows=max_rows,
                max_columns=250,
            )
            .read_rows()
        )

        asset_rows = (
            SecureCsvReader(
                asset_csv_path,
                max_rows=max_rows,
                max_columns=250,
            )
            .read_rows()
        )

        self._require_columns(
            vulnerability_rows,
            self.REQUIRED_FINDING_COLUMNS,
            source="Tenable vulnerability CSV",
        )

        self._require_columns(
            asset_rows,
            self.REQUIRED_ASSET_COLUMNS,
            source="Tenable asset CSV",
        )

        vulnerability_records = []

        known_finding_ids = set()

        for (
            row_number,
            row,
        ) in enumerate(
            vulnerability_rows,
            start=2,
        ):

            record = (
                self._map_vulnerability_row(
                    row,
                    row_number=row_number,
                )
            )

            finding_id = record[
                "finding_id"
            ]

            known_finding_ids.add(
                finding_id
            )

            vulnerability_records.append(
                record
            )

        unknown_overrides = (
            set(
                self._patch_overrides
            )
            - known_finding_ids
        )

        if unknown_overrides:

            raise TenableCsvImportError(
                "Patch availability override "
                "references an unknown finding."
            )

        asset_records = []

        for (
            row_number,
            row,
        ) in enumerate(
            asset_rows,
            start=2,
        ):

            asset_records.append(
                self._map_asset_row(
                    row,
                    row_number=row_number,
                )
            )

        self._delegate = TenableProvider(
            vulnerability_records=
                vulnerability_records,

            asset_records=
                asset_records,

            asset_context_by_uuid=
                asset_context_by_uuid,
        )


    # -------------------------------------------------
    # REQUIRED COLUMNS
    # -------------------------------------------------


    @staticmethod
    def _require_columns(
        rows: list[dict[str, str]],
        required_columns: set[str],
        *,
        source: str,
    ) -> None:

        actual_columns = set(
            rows[0].keys()
        )

        missing_columns = (
            required_columns
            - actual_columns
        )

        if missing_columns:

            raise TenableCsvImportError(
                f"{source} is missing required "
                "columns."
            )


    # -------------------------------------------------
    # PATCH OVERRIDES
    # -------------------------------------------------


    @staticmethod
    def _validate_patch_overrides(
        overrides:
            Mapping[str, bool] | None,
    ) -> dict[str, bool]:

        if overrides is None:

            return {}

        if not isinstance(
            overrides,
            Mapping,
        ):

            raise TenableCsvImportError(
                "Patch availability overrides "
                "must be a mapping."
            )

        normalized = {}

        for (
            finding_id,
            value,
        ) in overrides.items():

            if (
                not isinstance(
                    finding_id,
                    str,
                )
                or not finding_id.strip()
            ):

                raise TenableCsvImportError(
                    "Patch availability override "
                    "contains an invalid finding ID."
                )

            if not isinstance(
                value,
                bool,
            ):

                raise TenableCsvImportError(
                    "Patch availability override "
                    "must contain boolean values."
                )

            normalized[
                finding_id.strip()
            ] = value

        return normalized


    # -------------------------------------------------
    # REQUIRED TEXT
    # -------------------------------------------------


    @staticmethod
    def _require_text(
        row: Mapping[str, str],
        column: str,
        *,
        row_number: int,
    ) -> str:

        value = (
            row.get(
                column,
                ""
            )
            .strip()
        )

        if not value:

            raise TenableCsvImportError(
                f"Tenable CSV row {row_number} "
                "contains a blank required value."
            )

        return value


    # -------------------------------------------------
    # NUMBER
    # -------------------------------------------------


    @staticmethod
    def _parse_number(
        value: str,
        *,
        row_number: int,
        minimum: float,
        maximum: float,
        allow_blank: bool = False,
    ) -> float | None:

        normalized = (
            value.strip()
        )

        if not normalized:

            if allow_blank:

                return None

            raise TenableCsvImportError(
                f"Tenable CSV row {row_number} "
                "contains a blank numeric value."
            )

        try:

            result = float(
                normalized
            )

        except ValueError as exc:

            raise TenableCsvImportError(
                f"Tenable CSV row {row_number} "
                "contains invalid numeric data."
            ) from exc

        if not (
            minimum
            <= result
            <= maximum
        ):

            raise TenableCsvImportError(
                f"Tenable CSV row {row_number} "
                "contains numeric data outside "
                "the supported range."
            )

        return result


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

        raise TenableCsvImportError(
            f"Tenable CSV row {row_number} "
            "contains an invalid boolean value."
        )


    # -------------------------------------------------
    # CVE
    # -------------------------------------------------


    @classmethod
    def _parse_single_cve(
        cls,
        value: str,
        *,
        row_number: int,
    ) -> str:

        matches = [
            match.upper()
            for match
            in cls.CVE_PATTERN.findall(
                value
            )
        ]

        unique_matches = list(
            dict.fromkeys(
                matches
            )
        )

        if len(
            unique_matches
        ) != 1:

            raise TenableCsvImportError(
                f"Tenable CSV row {row_number} "
                "must contain exactly one CVE."
            )

        return unique_matches[0]


    # -------------------------------------------------
    # CVSS
    # -------------------------------------------------


    @classmethod
    def _map_cvss(
        cls,
        row: Mapping[str, str],
        *,
        row_number: int,
    ) -> dict:

        plugin_scores = {}

        for (
            csv_column,
            plugin_field,
        ) in cls.CVSS_COLUMNS:

            value = row.get(
                csv_column
            )

            if value is None:

                continue

            if not value.strip():

                continue

            score = cls._parse_number(
                value,
                row_number=row_number,
                minimum=0,
                maximum=10,
            )

            plugin_scores[
                plugin_field
            ] = score

        if not plugin_scores:

            raise TenableCsvImportError(
                f"Tenable CSV row {row_number} "
                "does not contain a supported "
                "CVSS base score."
            )

        return plugin_scores


    # -------------------------------------------------
    # PATCH AVAILABILITY
    # -------------------------------------------------


    def _get_patch_available(
        self,
        row: Mapping[str, str],
        finding_id: str,
        *,
        row_number: int,
    ) -> bool:

        override = (
            self._patch_overrides.get(
                finding_id
            )
        )

        if override is not None:

            return override

        patch_published = (
            row.get(
                "definition.patch_published",
                "",
            )
            .strip()
        )

        if patch_published:

            # Tenable defines Patch Published as
            # the date the vendor made a patch
            # available.

            return True

        # A blank Patch Published value cannot
        # safely prove that no patch exists.

        raise TenableCsvImportError(
            f"Tenable CSV row {row_number} "
            "does not contain explicit patch "
            "availability."
        )


    # -------------------------------------------------
    # VULNERABILITY ROW
    # -------------------------------------------------


    def _map_vulnerability_row(
        self,
        row: Mapping[str, str],
        *,
        row_number: int,
    ) -> dict:

        finding_id = (
            self._require_text(
                row,
                "id",
                row_number=row_number,
            )
        )

        asset_uuid = (
            self._require_text(
                row,
                "asset.id",
                row_number=row_number,
            )
        )

        cve = (
            self._parse_single_cve(
                self._require_text(
                    row,
                    "definition.cve",
                    row_number=row_number,
                ),
                row_number=row_number,
            )
        )

        name = (
            self._require_text(
                row,
                "definition.name",
                row_number=row_number,
            )
        )

        description = (
            self._require_text(
                row,
                "definition.description",
                row_number=row_number,
            )
        )

        epss = (
            self._parse_number(
                row.get(
                    "definition.epss.score",
                    "",
                ),
                row_number=row_number,
                minimum=0,
                maximum=100,
                allow_blank=True,
            )
        )

        kev = (
            self._parse_boolean(
                row.get(
                    "definition.vpr."
                    "drivers_on_cisa_kev",
                    "",
                ),
                row_number=row_number,
            )
        )

        patch_available = (
            self._get_patch_available(
                row,
                finding_id,
                row_number=row_number,
            )
        )

        plugin = {
            "cve": [
                cve
            ],

            "name":
                name,

            "description":
                description,

            "epss_score":
                epss,

            "has_patch":
                patch_available,

            "vpr": {
                "on_cisa_kev":
                    kev,
            },
        }

        plugin.update(
            self._map_cvss(
                row,
                row_number=row_number,
            )
        )

        return {
            "finding_id":
                finding_id,

            "asset": {
                "id":
                    asset_uuid,
            },

            "plugin":
                plugin,
        }


    # -------------------------------------------------
    # ASSET ROW
    # -------------------------------------------------


    @classmethod
    def _map_asset_row(
        cls,
        row: Mapping[str, str],
        *,
        row_number: int,
    ) -> dict:

        asset_uuid = (
            cls._require_text(
                row,
                "id",
                row_number=row_number,
            )
        )

        terminated_at = (
            row.get(
                "terminated_at",
                "",
            )
            .strip()
        )

        return {
            "id":
                asset_uuid,

            "timestamps": {
                "terminated_at":
                    (
                        terminated_at
                        if terminated_at
                        else None
                    ),

                "deleted_at":
                    None,
            },
        }


    # -------------------------------------------------
    # PROVIDER CONTRACT
    # -------------------------------------------------


    def get_finding(
        self,
        finding_id: str
    ) -> VulnerabilityFinding:

        return (
            self._delegate
            .get_finding(
                finding_id
            )
        )


    def get_asset_context(
        self,
        asset_name: str
    ) -> AssetContext:

        return (
            self._delegate
            .get_asset_context(
                asset_name
            )
        )


    def get_threat_intel(
        self,
        cve: str
    ) -> ThreatIntel:

        return (
            self._delegate
            .get_threat_intel(
                cve
            )
        )