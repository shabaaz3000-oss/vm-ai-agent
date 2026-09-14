import json

from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

from app.auth import Principal

from app.models import (
    AssetContext,
    KnowledgeChunk,
    RiskResult,
    VulnerabilityFinding,
)

from app.retriever import (
    KnowledgeRetriever,
)

from app.tools.knowledge import (
    search_knowledge,
)

from app.vector_index import (
    IndexedChunk,
    SearchResult,
)


# -------------------------------------------------
# PROJECT PATHS
# -------------------------------------------------


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)


DATA_LEAKAGE_CORPUS_PATH = (
    PROJECT_ROOT
    / "evals"
    / "data_leakage_security_cases.json"
)


# -------------------------------------------------
# SYNTHETIC SECRET
# -------------------------------------------------


SECRET_CANARY = (
    "VM_AI_DATA_LEAK_CANARY_NOT_REAL"
)


# -------------------------------------------------
# CASE RESULT
# -------------------------------------------------


@dataclass(frozen=True)
class DataLeakageCaseResult:

    case_id: str

    expected_returned_ids: list[str]
    observed_returned_ids: list[str]

    expected_tool_access: str | None
    observed_tool_access: str | None

    expected_canary_exposed: bool
    observed_canary_exposed: bool

    expected_error: str | None
    observed_error: str | None

    passed: bool


# -------------------------------------------------
# AGGREGATE RESULT
# -------------------------------------------------


@dataclass(frozen=True)
class DataLeakageSecurityEvaluationResult:

    total_cases: int

    passed_cases: int
    failed_cases: int

    unexpected_exposures: int

    result_mismatches: int
    access_mismatches: int
    error_mismatches: int

    passed: bool


# -------------------------------------------------
# LOAD CORPUS
# -------------------------------------------------


def load_data_leakage_security_cases(
    path: Path =
        DATA_LEAKAGE_CORPUS_PATH,
) -> list[dict]:

    cases = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

    if not isinstance(
        cases,
        list,
    ):

        raise ValueError(
            "Data leakage security corpus "
            "must contain a JSON list."
        )

    return cases


# -------------------------------------------------
# BUILD SECURITY-EVALUATION CHUNK
# -------------------------------------------------


def _build_chunk(
    candidate: dict,
) -> KnowledgeChunk:

    candidate_id = (
        candidate["id"]
    )

    sensitive = (
        candidate["sensitive"]
    )

    if sensitive:

        content = (
            "Restricted internal security "
            "architecture reference. "
            "Synthetic security canary: "
            f"{SECRET_CANARY}"
        )

    else:

        content = (
            "Apply the approved vendor patch "
            "and validate remediation with an "
            "authenticated vulnerability scan."
        )

    return KnowledgeChunk(
        chunk_id=
            candidate_id,

        source_id=
            candidate_id,

        source_name=
            f"{candidate_id}.md",

        chunk_number=
            0,

        content=
            content,

        source_sha256=
            "a" * 64,

        trust_tier=
            "trusted_reference",

        access_level=
            candidate["access_level"],
    )


# -------------------------------------------------
# BUILD RETRIEVER AND RANKING
# -------------------------------------------------


def _build_retrieval_fixture(
    case: dict,
):

    chunks = [
        _build_chunk(
            candidate
        )
        for candidate in
        case["candidates"]
    ]

    retriever = KnowledgeRetriever(
        index=[
            IndexedChunk(
                chunk=chunk,
                embedding=[
                    1.0,
                    0.0,
                ],
            )
            for chunk in chunks
        ]
    )

    chunk_map = {
        chunk.chunk_id:
            chunk
        for chunk in chunks
    }

    ranked_results = [
        SearchResult(
            chunk=
                chunk_map[
                    candidate["id"]
                ],

            similarity=
                candidate[
                    "similarity"
                ],
        )
        for candidate in
        case["candidates"]
    ]

    return (
        retriever,
        ranked_results,
    )


# -------------------------------------------------
# COMMON TOOL CONTEXT
# -------------------------------------------------


def _build_finding(
) -> VulnerabilityFinding:

    return VulnerabilityFinding(
        finding_id=
            "VULN-LEAK-EVAL-001",

        asset_name=
            "app-prod-01",

        cve=
            "CVE-2026-0001",

        title=
            "Security evaluation finding",

        description=
            "Controlled data leakage evaluation.",

        cvss=
            9.8,

        patch_available=
            True,
    )


def _build_asset(
) -> AssetContext:

    return AssetContext(
        asset_name=
            "app-prod-01",

        owner=
            "Security Engineering",

        application=
            "Security Eval App",

        environment=
            "production",

        business_criticality=
            "critical",

        internet_exposed=
            True,

        data_classification=
            "confidential",

        current_controls=[
            "WAF",
            "EDR",
        ],
    )


def _build_risk(
) -> RiskResult:

    return RiskResult(
        score=
            100,

        rating=
            "CRITICAL",

        sla_hours=
            24,

        factors=[
            "security-evaluation",
        ],
    )


# -------------------------------------------------
# EVALUATE ONE CASE
# -------------------------------------------------


def evaluate_data_leakage_case(
    case: dict,
) -> DataLeakageCaseResult:

    operation = (
        case["operation"]
    )

    if operation not in {
        "tool_search",
        "direct_retrieval",
    }:

        raise ValueError(
            "Unsupported data leakage "
            "evaluation operation."
        )

    (
        retriever,
        ranked_results,
    ) = _build_retrieval_fixture(
        case
    )

    expected_returned_ids = (
        case["expected_returned_ids"]
    )

    expected_tool_access = (
        case["expected_tool_access"]
    )

    expected_canary_exposed = (
        case["expected_canary_exposed"]
    )

    expected_error = (
        case["expected_error"]
    )

    returned_evidence = []

    observed_tool_access = None
    observed_error = None

    try:

        with patch(
            "app.retriever.search_vector_index",
            return_value=
                ranked_results,
        ):

            # -------------------------------------------------
            # LLM-VISIBLE KNOWLEDGE TOOL
            # -------------------------------------------------

            if operation == "tool_search":

                principal = Principal(
                    username=(
                        "data-leakage-eval-user"
                    ),
                    role=
                        case["principal_role"],
                )

                with patch(
                    "app.tools.knowledge.log_event",
                ), patch.object(
                    retriever,
                    "retrieve",
                    wraps=
                        retriever.retrieve,
                ) as retrieve_spy:

                    returned_evidence = (
                        search_knowledge(
                            principal=
                                principal,

                            finding=
                                _build_finding(),

                            asset=
                                _build_asset(),

                            risk=
                                _build_risk(),

                            retriever=
                                retriever,

                            top_k=
                                case["top_k"],
                        )
                    )

                retrieve_call = (
                    retrieve_spy.call_args
                )

                if retrieve_call is not None:

                    observed_tool_access = (
                        retrieve_call
                        .kwargs
                        .get(
                            "caller_access"
                        )
                    )

            # -------------------------------------------------
            # DIRECT RETRIEVER SECURITY BOUNDARY
            # -------------------------------------------------

            else:

                returned_evidence = (
                    retriever.retrieve(
                        query=(
                            "controlled security "
                            "evaluation query"
                        ),

                        top_k=
                            case["top_k"],

                        caller_access=
                            case[
                                "caller_access"
                            ],
                    )
                )

    except Exception as error:

        observed_error = (
            type(error).__name__
        )

    observed_returned_ids = [
        item.chunk_id
        for item in returned_evidence
    ]

    observed_canary_exposed = any(
        SECRET_CANARY
        in item.content
        for item in returned_evidence
    )

    result_matches = (
        observed_returned_ids
        == expected_returned_ids
    )

    access_matches = (
        observed_tool_access
        == expected_tool_access
    )

    canary_matches = (
        observed_canary_exposed
        == expected_canary_exposed
    )

    error_matches = (
        observed_error
        == expected_error
    )

    passed = all(
        [
            result_matches,
            access_matches,
            canary_matches,
            error_matches,
        ]
    )

    return DataLeakageCaseResult(
        case_id=
            case["id"],

        expected_returned_ids=
            expected_returned_ids,

        observed_returned_ids=
            observed_returned_ids,

        expected_tool_access=
            expected_tool_access,

        observed_tool_access=
            observed_tool_access,

        expected_canary_exposed=
            expected_canary_exposed,

        observed_canary_exposed=
            observed_canary_exposed,

        expected_error=
            expected_error,

        observed_error=
            observed_error,

        passed=
            passed,
    )


# -------------------------------------------------
# RUN CORPUS
# -------------------------------------------------


def run_data_leakage_security_evaluation(
    path: Path =
        DATA_LEAKAGE_CORPUS_PATH,
) -> DataLeakageSecurityEvaluationResult:

    cases = (
        load_data_leakage_security_cases(
            path
        )
    )

    results = [
        evaluate_data_leakage_case(
            case
        )
        for case in cases
    ]

    passed_cases = sum(
        1
        for result in results
        if result.passed
    )

    failed_cases = (
        len(results)
        - passed_cases
    )

    unexpected_exposures = sum(
        1
        for result in results
        if (
            not result
            .expected_canary_exposed

            and result
            .observed_canary_exposed
        )
    )

    result_mismatches = sum(
        1
        for result in results
        if (
            result.observed_returned_ids
            != result.expected_returned_ids
        )
    )

    access_mismatches = sum(
        1
        for result in results
        if (
            result.observed_tool_access
            != result.expected_tool_access
        )
    )

    error_mismatches = sum(
        1
        for result in results
        if (
            result.observed_error
            != result.expected_error
        )
    )

    return DataLeakageSecurityEvaluationResult(
        total_cases=
            len(results),

        passed_cases=
            passed_cases,

        failed_cases=
            failed_cases,

        unexpected_exposures=
            unexpected_exposures,

        result_mismatches=
            result_mismatches,

        access_mismatches=
            access_mismatches,

        error_mismatches=
            error_mismatches,

        passed=(
            failed_cases == 0
        ),
    )