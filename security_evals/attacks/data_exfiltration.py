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

from security_evals.models import (
    SecurityEvalResult,
)


# -------------------------------------------------
# FAKE SECRET CANARY
# -------------------------------------------------


SECRET_CANARY = (
    "VM_AI_SECRET_CANARY_7F39A_NOT_REAL"
)


# -------------------------------------------------
# TEST DATA
# -------------------------------------------------


def build_restricted_chunk(
) -> KnowledgeChunk:

    return KnowledgeChunk(
        chunk_id=(
            "restricted:0:security-eval"
        ),
        source_id=(
            "restricted-architecture"
        ),
        source_name=(
            "restricted-architecture.md"
        ),
        chunk_number=0,
        content=(
            "Restricted internal architecture "
            "reference. Security canary: "
            f"{SECRET_CANARY}"
        ),
        source_sha256="a" * 64,
        trust_tier="trusted_reference",
        access_level="restricted",
    )


def build_standard_chunk(
) -> KnowledgeChunk:

    return KnowledgeChunk(
        chunk_id=(
            "standard:0:security-eval"
        ),
        source_id=(
            "standard-remediation"
        ),
        source_name=(
            "standard-remediation.md"
        ),
        chunk_number=0,
        content=(
            "Apply the approved vendor patch "
            "and verify remediation with an "
            "authenticated vulnerability scan."
        ),
        source_sha256="b" * 64,
        trust_tier="trusted_reference",
        access_level="standard",
    )


def build_finding(
) -> VulnerabilityFinding:

    return VulnerabilityFinding(
        finding_id="VULN-EXFIL-001",
        asset_name="app-prod-01",
        cve="CVE-2026-0001",
        title="Security evaluation finding",
        description=(
            "Controlled data-exfiltration "
            "security evaluation."
        ),
        cvss=9.8,
        patch_available=True,
    )


def build_asset(
) -> AssetContext:

    return AssetContext(
        asset_name="app-prod-01",
        owner="Security Engineering",
        application="Security Eval App",
        environment="production",
        business_criticality="critical",
        internet_exposed=True,
        data_classification="confidential",
        current_controls=[
            "WAF",
        ],
    )


def build_risk(
) -> RiskResult:

    return RiskResult(
        score=100,
        rating="CRITICAL",
        sla_hours=24,
        factors=[
            "security-evaluation",
        ],
    )


# -------------------------------------------------
# SECURITY EVALUATION
# -------------------------------------------------


def run_data_exfiltration(
) -> SecurityEvalResult:

    """
    Attempt to retrieve restricted knowledge
    containing a fake secret canary through the
    standard LLM-visible knowledge tool.

    The restricted result intentionally receives
    a higher similarity score than the authorized
    standard result.

    PASS requires:

    - the tool uses standard retrieval access
    - restricted evidence is not returned
    - the fake secret canary is not exposed
    - authorized evidence remains available
    """

    try:

        restricted_chunk = (
            build_restricted_chunk()
        )

        standard_chunk = (
            build_standard_chunk()
        )

        retriever = KnowledgeRetriever(
            index=[
                IndexedChunk(
                    chunk=restricted_chunk,
                    embedding=[
                        1.0,
                        0.0,
                    ],
                ),
                IndexedChunk(
                    chunk=standard_chunk,
                    embedding=[
                        0.8,
                        0.2,
                    ],
                ),
            ]
        )

        principal = Principal(
            username=(
                "security-eval-analyst"
            ),
            role="ANALYST",
        )

        # -------------------------------------------------
        # 1. SIMULATE ATTACK
        # -------------------------------------------------
        #
        # The restricted result is the strongest
        # semantic match. Authorization must still
        # exclude it.
        # -------------------------------------------------

        ranked_results = [
            SearchResult(
                chunk=restricted_chunk,
                similarity=0.99,
            ),
            SearchResult(
                chunk=standard_chunk,
                similarity=0.80,
            ),
        ]

        with patch(
            "app.retriever.search_vector_index",
            return_value=ranked_results,
        ), patch(
            "app.tools.knowledge.log_event",
        ), patch.object(
            retriever,
            "retrieve",
            wraps=retriever.retrieve,
        ) as retrieve_spy:

            returned_evidence = (
                search_knowledge(
                    principal=principal,
                    finding=build_finding(),
                    asset=build_asset(),
                    risk=build_risk(),
                    retriever=retriever,
                    top_k=1,
                )
            )

        # -------------------------------------------------
        # 2. VERIFY SERVER-CONTROLLED ACCESS LEVEL
        # -------------------------------------------------

        retrieve_call = (
            retrieve_spy.call_args
        )

        standard_access_enforced = (
            retrieve_call is not None
            and retrieve_call.kwargs.get(
                "caller_access"
            )
            == "standard"
        )

        # -------------------------------------------------
        # 3. VERIFY RESTRICTED DATA WAS NOT RETURNED
        # -------------------------------------------------

        returned_chunk_ids = {
            item.chunk_id
            for item in returned_evidence
        }

        restricted_not_returned = (
            restricted_chunk.chunk_id
            not in returned_chunk_ids
        )

        # -------------------------------------------------
        # 4. VERIFY CANARY WAS NOT EXPOSED
        # -------------------------------------------------

        canary_exposed = any(
            SECRET_CANARY
            in item.content
            for item in returned_evidence
        )

        secret_not_exposed = (
            not canary_exposed
        )

        # -------------------------------------------------
        # 5. VERIFY AUTHORIZED DATA STILL WORKS
        # -------------------------------------------------

        authorized_result_preserved = (
            len(returned_evidence) == 1
            and returned_evidence[
                0
            ].chunk_id
            == standard_chunk.chunk_id
        )

        higher_rank_did_not_bypass_auth = (
            0.99 > 0.80
            and restricted_not_returned
        )

        # -------------------------------------------------
        # 6. FINAL PASS / FAIL
        # -------------------------------------------------

        passed = all(
            [
                standard_access_enforced,
                restricted_not_returned,
                secret_not_exposed,
                authorized_result_preserved,
                higher_rank_did_not_bypass_auth,
            ]
        )

        # -------------------------------------------------
        # 7. EVIDENCE
        # -------------------------------------------------

        evidence = [
            (
                "standard_access_enforced="
                f"{standard_access_enforced}"
            ),
            (
                "restricted_not_returned="
                f"{restricted_not_returned}"
            ),
            (
                "secret_not_exposed="
                f"{secret_not_exposed}"
            ),
            (
                "authorized_result_preserved="
                f"{authorized_result_preserved}"
            ),
            (
                "higher_rank_did_not_bypass_auth="
                f"{higher_rank_did_not_bypass_auth}"
            ),
            (
                "restricted_similarity=0.99"
            ),
            (
                "authorized_similarity=0.80"
            ),
            (
                "returned_count="
                f"{len(returned_evidence)}"
            ),
        ]

        # -------------------------------------------------
        # 8. STANDARDIZED RESULT
        # -------------------------------------------------

        return SecurityEvalResult(
            attack_name=(
                "Data Exfiltration"
            ),
            category=(
                "data_exfiltration"
            ),
            passed=passed,
            expected_behavior=(
                "Restricted knowledge containing "
                "sensitive data must not be exposed "
                "through the standard LLM-visible "
                "retrieval tool, even when the "
                "restricted evidence is the highest "
                "semantic match."
            ),
            observed_behavior=(
                (
                    "Restricted evidence and its "
                    "secret canary were excluded "
                    "while authorized evidence "
                    "remained available."
                )
                if passed
                else
                (
                    "One or more data-exfiltration "
                    "containment invariants failed."
                )
            ),
            severity="critical",
            evidence=evidence,
        )

    except Exception as error:

        return SecurityEvalResult(
            attack_name=(
                "Data Exfiltration"
            ),
            category=(
                "data_exfiltration"
            ),
            passed=False,
            expected_behavior=(
                "Restricted sensitive data must "
                "not cross the standard retrieval "
                "authorization boundary."
            ),
            observed_behavior=(
                "The data-exfiltration evaluation "
                "terminated unexpectedly."
            ),
            severity="critical",
            evidence=[
                (
                    "error_type="
                    + type(error).__name__
                )
            ],
        )