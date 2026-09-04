import json
from pathlib import Path

import pytest

from app.models import RetrievedEvidence
from app.rag_security import secure_retrieved_evidence


# -------------------------------------------------
# EVALUATION CORPUS
# -------------------------------------------------


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)

RAG_EVAL_CORPUS_PATH = (
    PROJECT_ROOT
    / "evals"
    / "rag_security_cases.json"
)


def load_rag_security_cases() -> list[dict]:

    return json.loads(
        RAG_EVAL_CORPUS_PATH.read_text(
            encoding="utf-8"
        )
    )


RAG_SECURITY_CASES = (
    load_rag_security_cases()
)


# -------------------------------------------------
# EVIDENCE BUILDER
# -------------------------------------------------


def build_evidence(
    case: dict,
) -> RetrievedEvidence:

    return RetrievedEvidence(
        source_id=
            case["id"].lower(),

        source_name=
            f"{case['id'].lower()}.md",

        chunk_id=
            f"{case['id'].lower()}:0:test",

        chunk_number=
            0,

        content=
            case["payload"],

        similarity=
            0.99,

        source_sha256=
            "a" * 64,

        trust_tier=
            "trusted_reference",

        access_level=
            "standard",
    )


# -------------------------------------------------
# CORPUS INTEGRITY
# -------------------------------------------------


def test_rag_security_corpus_metadata_is_valid() -> None:

    required_fields = {
        "id",
        "name",
        "payload",
        "expected_quarantine",
        "expected_categories",
    }

    assert RAG_SECURITY_CASES

    ids = []

    for case in RAG_SECURITY_CASES:

        assert (
            required_fields
            <= case.keys()
        )

        assert isinstance(
            case["id"],
            str
        )

        assert case["id"].strip()

        assert isinstance(
            case["name"],
            str
        )

        assert case["name"].strip()

        assert isinstance(
            case["payload"],
            str
        )

        assert case["payload"].strip()

        assert isinstance(
            case["expected_quarantine"],
            bool
        )

        assert isinstance(
            case["expected_categories"],
            list
        )

        for category in (
            case["expected_categories"]
        ):

            assert isinstance(
                category,
                str
            )

            assert category.strip()

        ids.append(
            case["id"]
        )

    assert (
        len(ids)
        == len(set(ids))
    )


# -------------------------------------------------
# RAG SECURITY EVALUATION
# -------------------------------------------------


@pytest.mark.parametrize(
    "case",
    RAG_SECURITY_CASES,
    ids=[
        case["id"]
        for case in RAG_SECURITY_CASES
    ],
)
def test_rag_security_evaluation_corpus(
    case,
) -> None:

    evidence = build_evidence(
        case
    )

    result = (
        secure_retrieved_evidence(
            [
                evidence
            ]
        )
    )

    quarantined = (
        evidence.chunk_id
        in result.quarantined_chunk_ids
    )

    assert (
        quarantined
        is case["expected_quarantine"]
    ), (
        f"{case['id']} ({case['name']}) "
        f"quarantine mismatch: "
        f"expected "
        f"{case['expected_quarantine']}, "
        f"got {quarantined}; "
        f"categories={result.categories}"
    )

    for expected_category in (
        case["expected_categories"]
    ):

        assert (
            expected_category
            in result.categories
        ), (
            f"{case['id']} ({case['name']}) "
            f"expected category "
            f"{expected_category!r} "
            f"was not returned; "
            f"categories={result.categories}"
        )

    if case["expected_quarantine"]:

        assert (
            result.safe_evidence
            == []
        )

    else:

        assert len(
            result.safe_evidence
        ) == 1

        assert (
            result.safe_evidence[0]
            .chunk_id
            == evidence.chunk_id
        )

        assert (
            result.categories
            == []
        )