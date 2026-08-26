from __future__ import annotations

import csv
from pathlib import Path
from typing import Mapping


class CsvImportError(ValueError):
    """Raised when a CSV import cannot be safely accepted."""


class SecureCsvReader:
    """
    Safely loads untrusted CSV input.

    This class performs structural validation only.

    It does NOT decide whether vulnerability data is trustworthy and does
    NOT bypass Pydantic/domain validation. Domain-model validation will be
    added by CsvImportProvider in the next layer.
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
        self.path = Path(path)

        if max_file_bytes <= 0:
            raise ValueError("max_file_bytes must be positive")

        if max_rows <= 0:
            raise ValueError("max_rows must be positive")

        if max_columns <= 0:
            raise ValueError("max_columns must be positive")

        self.max_file_bytes = max_file_bytes
        self.max_rows = max_rows
        self.max_columns = max_columns

    def read_rows(self) -> list[dict[str, str]]:
        self._validate_path()

        try:
            file_size = self.path.stat().st_size
        except OSError as exc:
            raise CsvImportError("CSV file metadata could not be read") from exc

        if file_size == 0:
            raise CsvImportError("CSV file is empty")

        if file_size > self.max_file_bytes:
            raise CsvImportError("CSV file exceeds the configured size limit")

        try:
            with self.path.open(
                "r",
                encoding="utf-8-sig",
                newline="",
            ) as handle:
                reader = csv.DictReader(handle)

                headers = self._validate_headers(reader.fieldnames)

                rows: list[dict[str, str]] = []

                try:
                    for row_number, raw_row in enumerate(reader, start=2):
                        if len(rows) >= self.max_rows:
                            raise CsvImportError(
                                "CSV file exceeds the configured row limit"
                            )

                        row = self._validate_row(
                            raw_row,
                            headers=headers,
                            row_number=row_number,
                        )

                        rows.append(row)

                except csv.Error as exc:
                    raise CsvImportError("CSV file is malformed") from exc

        except UnicodeDecodeError as exc:
            raise CsvImportError("CSV file must be valid UTF-8") from exc
        except OSError as exc:
            raise CsvImportError("CSV file could not be read") from exc

        if not rows:
            raise CsvImportError("CSV file contains no data rows")

        return rows

    def _validate_path(self) -> None:
        if self.path.suffix.lower() != ".csv":
            raise CsvImportError("Import file must use the .csv extension")

        if not self.path.exists():
            raise CsvImportError("CSV file does not exist")

        if not self.path.is_file():
            raise CsvImportError("CSV import path must reference a file")

    def _validate_headers(
        self,
        fieldnames: list[str] | None,
    ) -> list[str]:
        if not fieldnames:
            raise CsvImportError("CSV file does not contain a valid header row")

        if len(fieldnames) > self.max_columns:
            raise CsvImportError("CSV file exceeds the configured column limit")

        normalized_headers: list[str] = []

        for header in fieldnames:
            normalized = header.strip()

            if not normalized:
                raise CsvImportError("CSV file contains a blank column name")

            normalized_headers.append(normalized)

        if len(normalized_headers) != len(set(normalized_headers)):
            raise CsvImportError("CSV file contains duplicate column names")

        return normalized_headers

    @staticmethod
    def _validate_row(
        raw_row: Mapping[str | None, str | list[str] | None],
        *,
        headers: list[str],
        row_number: int,
    ) -> dict[str, str]:
        # csv.DictReader stores unexpected extra cells under the None key.
        if None in raw_row:
            raise CsvImportError(
                f"CSV row {row_number} contains more fields than the header"
            )

        validated_row: dict[str, str] = {}

        for original_header, normalized_header in zip(
            raw_row.keys(),
            headers,
            strict=True,
        ):
            if original_header is None:
                raise CsvImportError(
                    f"CSV row {row_number} contains an invalid column"
                )

            value = raw_row[original_header]

            if isinstance(value, list):
                raise CsvImportError(
                    f"CSV row {row_number} contains an invalid field"
                )

            if value is None:
                value = ""

            validated_row[normalized_header] = value.strip()

        if len(validated_row) != len(headers):
            raise CsvImportError(
                f"CSV row {row_number} does not match the header structure"
            )

        return validated_row