from pathlib import Path

import pytest

from app.providers.csv_import import CsvImportError, SecureCsvReader


def write_csv(
    path: Path,
    content: str,
    *,
    encoding: str = "utf-8",
) -> Path:
    path.write_text(content, encoding=encoding)
    return path


def test_reads_valid_csv(tmp_path: Path) -> None:
    csv_path = write_csv(
        tmp_path / "findings.csv",
        (
            "finding_id,asset_name,cve\n"
            "FIND-0001,server01,CVE-2026-12345\n"
        ),
    )

    rows = SecureCsvReader(csv_path).read_rows()

    assert rows == [
        {
            "finding_id": "FIND-0001",
            "asset_name": "server01",
            "cve": "CVE-2026-12345",
        }
    ]


def test_supports_utf8_bom(tmp_path: Path) -> None:
    csv_path = write_csv(
        tmp_path / "findings.csv",
        (
            "finding_id,asset_name,cve\n"
            "FIND-0001,server01,CVE-2026-12345\n"
        ),
        encoding="utf-8-sig",
    )

    rows = SecureCsvReader(csv_path).read_rows()

    assert rows[0]["finding_id"] == "FIND-0001"


def test_rejects_non_csv_extension(tmp_path: Path) -> None:
    file_path = write_csv(
        tmp_path / "findings.txt",
        "finding_id\nFIND-0001\n",
    )

    with pytest.raises(
        CsvImportError,
        match=r"must use the \.csv extension",
    ):
        SecureCsvReader(file_path).read_rows()


def test_rejects_empty_file(tmp_path: Path) -> None:
    csv_path = write_csv(
        tmp_path / "findings.csv",
        "",
    )

    with pytest.raises(
        CsvImportError,
        match="CSV file is empty",
    ):
        SecureCsvReader(csv_path).read_rows()


def test_rejects_duplicate_headers(tmp_path: Path) -> None:
    csv_path = write_csv(
        tmp_path / "findings.csv",
        (
            "finding_id,asset_name,asset_name\n"
            "FIND-0001,server01,server02\n"
        ),
    )

    with pytest.raises(
        CsvImportError,
        match="duplicate column names",
    ):
        SecureCsvReader(csv_path).read_rows()


def test_rejects_blank_header(tmp_path: Path) -> None:
    csv_path = write_csv(
        tmp_path / "findings.csv",
        (
            "finding_id,,cve\n"
            "FIND-0001,server01,CVE-2026-12345\n"
        ),
    )

    with pytest.raises(
        CsvImportError,
        match="blank column name",
    ):
        SecureCsvReader(csv_path).read_rows()


def test_rejects_row_with_extra_fields(tmp_path: Path) -> None:
    csv_path = write_csv(
        tmp_path / "findings.csv",
        (
            "finding_id,asset_name\n"
            "FIND-0001,server01,unexpected-value\n"
        ),
    )

    with pytest.raises(
        CsvImportError,
        match="contains more fields than the header",
    ):
        SecureCsvReader(csv_path).read_rows()


def test_rejects_row_limit_exceeded(tmp_path: Path) -> None:
    csv_path = write_csv(
        tmp_path / "findings.csv",
        (
            "finding_id\n"
            "FIND-0001\n"
            "FIND-0002\n"
        ),
    )

    reader = SecureCsvReader(
        csv_path,
        max_rows=1,
    )

    with pytest.raises(
        CsvImportError,
        match="row limit",
    ):
        reader.read_rows()


def test_rejects_column_limit_exceeded(tmp_path: Path) -> None:
    csv_path = write_csv(
        tmp_path / "findings.csv",
        (
            "one,two,three\n"
            "1,2,3\n"
        ),
    )

    reader = SecureCsvReader(
        csv_path,
        max_columns=2,
    )

    with pytest.raises(
        CsvImportError,
        match="column limit",
    ):
        reader.read_rows()


def test_rejects_file_size_limit_exceeded(tmp_path: Path) -> None:
    csv_path = write_csv(
        tmp_path / "findings.csv",
        (
            "finding_id\n"
            "FIND-0001\n"
        ),
    )

    reader = SecureCsvReader(
        csv_path,
        max_file_bytes=5,
    )

    with pytest.raises(
        CsvImportError,
        match="size limit",
    ):
        reader.read_rows()


def test_error_does_not_disclose_untrusted_extra_value(
    tmp_path: Path,
) -> None:
    secret_marker = "DO_NOT_LEAK_THIS_VALUE"

    csv_path = write_csv(
        tmp_path / "findings.csv",
        (
            "finding_id,asset_name\n"
            f"FIND-0001,server01,{secret_marker}\n"
        ),
    )

    with pytest.raises(CsvImportError) as exc_info:
        SecureCsvReader(csv_path).read_rows()

    assert secret_marker not in str(exc_info.value)


def test_rejects_missing_file(tmp_path: Path) -> None:
    csv_path = tmp_path / "does-not-exist.csv"

    with pytest.raises(
        CsvImportError,
        match="does not exist",
    ):
        SecureCsvReader(csv_path).read_rows()