from pathlib import Path

import pytest

from app.rag_ingestion import (
    KnowledgeIngestionError,
    build_knowledge_chunks,
    load_trusted_documents,
)


def test_loads_trusted_markdown(
    tmp_path: Path
):

    root = (
        tmp_path / "trusted"
    )

    root.mkdir()

    document = (
        root / "policy.md"
    )

    document.write_text(
        "# Remediation\n"
        "Apply approved security patches.",
        encoding="utf-8"
    )

    documents = (
        load_trusted_documents(
            root
        )
    )

    assert len(documents) == 1

    assert (
        documents[0].source_name
        == "policy.md"
    )

    assert (
        documents[0].trust_tier
        == "trusted_reference"
    )

    assert (
        len(
            documents[0]
            .content_sha256
        )
        == 64
    )


def test_chunks_large_document(
    tmp_path: Path
):

    root = (
        tmp_path / "trusted"
    )

    root.mkdir()

    document = (
        root / "large.md"
    )

    document.write_text(
        "security remediation " * 200,
        encoding="utf-8"
    )

    chunks = (
        build_knowledge_chunks(
            root
        )
    )

    assert len(chunks) > 1

    assert (
        chunks[0].chunk_number
        == 0
    )

    assert (
        chunks[0].source_name
        == "large.md"
    )


def test_rejects_empty_document(
    tmp_path: Path
):

    root = (
        tmp_path / "trusted"
    )

    root.mkdir()

    document = (
        root / "empty.md"
    )

    document.write_text(
        "",
        encoding="utf-8"
    )

    with pytest.raises(
        KnowledgeIngestionError
    ):

        load_trusted_documents(
            root
        )