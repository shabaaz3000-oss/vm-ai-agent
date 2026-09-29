from __future__ import annotations

from dataclasses import dataclass

from app.models import (
    KnowledgeChunk,
)

from app.retrieval_authorization import (
    RetrievalPrincipal,
)

from app.retriever import (
    KnowledgeRetriever,
)

from app.vector_index import (
    IndexedChunk,
    SearchResult,
)

import app.retriever as retriever_module


# -------------------------------------------------
# RESULT TYPES
# -------------------------------------------------


@dataclass(frozen=True)
class IdentityAwareRAGCaseObservation:

    case_name: str

    passed: bool

    unauthorized_exposed: bool

    pre_search_boundary_failed: bool

    audit_failed: bool


@dataclass(frozen=True)
class IdentityAwareRAGSecurityEvaluationResult:

    total_cases: int

    authorized_cases: int
    blocked_cases: int

    cross_tenant_cases: int
    cross_user_acl_cases: int
    classification_cases: int
    fail_closed_cases: int
    backend_injection_cases: int

    passed_cases: int
    failed_cases: int

    unauthorized_exposures: int
    pre_search_boundary_failures: int
    audit_failures: int

    passed: bool


# -------------------------------------------------
# EVALUATION CASES
# -------------------------------------------------


IDENTITY_AWARE_RAG_CASES = (
    "authorized_control",
    "cross_tenant",
    "cross_user_acl",
    "restricted_classification",
    "unscoped_fail_closed",
    "backend_injection",
)


# -------------------------------------------------
# HELPERS
# -------------------------------------------------


def _principal(
    *,
    principal_id: str = "alice",
    tenant_id: str = "tenant-a",
    retrieval_access: str = "standard",
) -> RetrievalPrincipal:

    return RetrievalPrincipal(
        principal_id=principal_id,
        tenant_id=tenant_id,
        retrieval_access=retrieval_access,
    )


def _chunk(
    *,
    source_id: str,
    tenant_id: str | None,
    content: str,
    access_level: str = "standard",
    allowed_principal_ids: tuple[str, ...] | None = None,
) -> KnowledgeChunk:

    return KnowledgeChunk(
        chunk_id=f"{source_id}:0:security-eval",
        source_id=source_id,
        source_name=f"{source_id}.md",
        chunk_number=0,
        content=content,
        source_sha256="c" * 64,
        trust_tier="trusted_reference",
        access_level=access_level,
        tenant_id=tenant_id,
        allowed_principal_ids=
            allowed_principal_ids,
    )


def _indexed(
    value: KnowledgeChunk,
) -> IndexedChunk:

    return IndexedChunk(
        chunk=value,
        embedding=[
            1.0,
            0.0,
        ],
    )


def _has_authorization_event(
    events: list[dict],
    *,
    event_type: str,
    reason: str,
) -> bool:

    return any(
        (
            event.get("event_type")
            == event_type
        )
        and
        (
            event.get(
                "details",
                {},
            ).get("reason")
            == reason
        )
        for event in events
    )


# -------------------------------------------------
# CASE EXECUTION
# -------------------------------------------------


def observe_identity_aware_rag_case(
    case_name: str,
) -> IdentityAwareRAGCaseObservation:

    original_search = (
        retriever_module
        .search_vector_index
    )

    original_log_event = (
        retriever_module
        .log_event
    )

    events: list[dict] = []

    def capture_log_event(
        event_type,
        details=None,
    ):

        events.append(
            {
                "event_type":
                    event_type,

                "details":
                    details or {},
            }
        )

    retriever_module.log_event = (
        capture_log_event
    )

    try:

        # -------------------------------------------------
        # AUTHORIZED CONTROL
        # -------------------------------------------------

        if case_name == "authorized_control":

            allowed = _indexed(
                _chunk(
                    source_id=
                        "alice-authorized",

                    tenant_id=
                        "tenant-a",

                    content=
                        "authorized control content",

                    allowed_principal_ids=(
                        "alice",
                    ),
                )
            )

            received_index = []

            def authorized_search(
                *,
                query,
                index,
                top_k,
            ):

                received_index.extend(
                    index
                )

                return []

            retriever_module.search_vector_index = (
                authorized_search
            )

            retriever = KnowledgeRetriever(
                index=[
                    allowed
                ]
            )

            result = retriever.retrieve(
                query="authorized control",
                retrieval_principal=
                    _principal(),
            )

            audit_ok = (
                _has_authorization_event(
                    events,
                    event_type=
                        "RAG_AUTHORIZATION_ALLOWED",
                    reason="allowed",
                )
            )

            passed = (
                result == []
                and received_index
                == [allowed]
                and audit_ok
            )

            return IdentityAwareRAGCaseObservation(
                case_name=case_name,
                passed=passed,
                unauthorized_exposed=False,
                pre_search_boundary_failed=False,
                audit_failed=not audit_ok,
            )

        # -------------------------------------------------
        # PRE-SEARCH DENIAL CASES
        # -------------------------------------------------

        if case_name in {
            "cross_tenant",
            "cross_user_acl",
            "restricted_classification",
            "unscoped_fail_closed",
        }:

            principal = _principal()

            expected_reason = ""

            if case_name == "cross_tenant":

                target = _indexed(
                    _chunk(
                        source_id=
                            "tenant-b-secret",

                        tenant_id=
                            "tenant-b",

                        content=
                            "CROSS-TENANT-SECRET",
                    )
                )

                expected_reason = (
                    "tenant_mismatch"
                )

            elif case_name == "cross_user_acl":

                target = _indexed(
                    _chunk(
                        source_id=
                            "alice-private",

                        tenant_id=
                            "tenant-a",

                        content=
                            "ALICE-PRIVATE-SECRET",

                        allowed_principal_ids=(
                            "alice",
                        ),
                    )
                )

                principal = _principal(
                    principal_id="bob",
                )

                expected_reason = (
                    "principal_acl_denied"
                )

            elif case_name == "restricted_classification":

                target = _indexed(
                    _chunk(
                        source_id=
                            "restricted-doc",

                        tenant_id=
                            "tenant-a",

                        content=
                            "RESTRICTED-SECRET",

                        access_level=
                            "restricted",
                    )
                )

                expected_reason = (
                    "classification_denied"
                )

            else:

                target = _indexed(
                    _chunk(
                        source_id=
                            "unscoped-doc",

                        tenant_id=None,

                        content=
                            "UNSCOPED-SECRET",
                    )
                )

                expected_reason = (
                    "missing_tenant_scope"
                )

            search_called = False

            def denied_search(
                **kwargs,
            ):

                nonlocal search_called

                search_called = True

                return []

            retriever_module.search_vector_index = (
                denied_search
            )

            retriever = KnowledgeRetriever(
                index=[
                    target
                ]
            )

            result = retriever.retrieve(
                query="adversarial retrieval",
                retrieval_principal=
                    principal,
            )

            audit_ok = (
                _has_authorization_event(
                    events,
                    event_type=
                        "RAG_AUTHORIZATION_DENIED",
                    reason=
                        expected_reason,
                )
            )

            unauthorized_exposed = (
                bool(result)
            )

            boundary_failed = (
                search_called
            )

            passed = (
                not unauthorized_exposed
                and not boundary_failed
                and audit_ok
            )

            return IdentityAwareRAGCaseObservation(
                case_name=case_name,
                passed=passed,
                unauthorized_exposed=
                    unauthorized_exposed,
                pre_search_boundary_failed=
                    boundary_failed,
                audit_failed=
                    not audit_ok,
            )

        # -------------------------------------------------
        # MALICIOUS / BUGGY VECTOR BACKEND
        # -------------------------------------------------

        if case_name == "backend_injection":

            allowed_chunk = _chunk(
                source_id="allowed",
                tenant_id="tenant-a",
                content="allowed content",
            )

            forbidden_chunk = _chunk(
                source_id="tenant-b-secret",
                tenant_id="tenant-b",
                content="BACKEND-INJECTED-SECRET",
            )

            allowed = _indexed(
                allowed_chunk
            )

            forbidden = _indexed(
                forbidden_chunk
            )

            received_index = []

            def malicious_search(
                *,
                query,
                index,
                top_k,
            ):

                received_index.extend(
                    index
                )

                return [
                    SearchResult(
                        chunk=
                            forbidden_chunk,

                        similarity=
                            1.0,
                    )
                ]

            retriever_module.search_vector_index = (
                malicious_search
            )

            retriever = KnowledgeRetriever(
                index=[
                    allowed,
                    forbidden,
                ]
            )

            result = retriever.retrieve(
                query=
                    "BACKEND-INJECTED-SECRET",

                retrieval_principal=
                    _principal(),
            )

            unauthorized_entered_search = (
                forbidden
                in received_index
            )

            unauthorized_exposed = (
                bool(result)
            )

            audit_ok = (
                _has_authorization_event(
                    events,
                    event_type=
                        "RAG_AUTHORIZATION_DENIED",
                    reason=
                        "tenant_mismatch",
                )
            )

            passed = (
                received_index
                == [allowed]
                and not unauthorized_exposed
                and audit_ok
            )

            return IdentityAwareRAGCaseObservation(
                case_name=case_name,
                passed=passed,
                unauthorized_exposed=
                    unauthorized_exposed,
                pre_search_boundary_failed=
                    unauthorized_entered_search,
                audit_failed=
                    not audit_ok,
            )

        raise ValueError(
            "Unknown identity-aware RAG "
            f"security case: {case_name}"
        )

    finally:

        retriever_module.search_vector_index = (
            original_search
        )

        retriever_module.log_event = (
            original_log_event
        )


# -------------------------------------------------
# COMPLETE EVALUATION
# -------------------------------------------------


def run_identity_aware_rag_security_evaluation(
) -> IdentityAwareRAGSecurityEvaluationResult:

    observations = [
        observe_identity_aware_rag_case(
            case_name
        )
        for case_name
        in IDENTITY_AWARE_RAG_CASES
    ]

    passed_cases = sum(
        observation.passed
        for observation
        in observations
    )

    failed_cases = (
        len(observations)
        - passed_cases
    )

    unauthorized_exposures = sum(
        observation.unauthorized_exposed
        for observation
        in observations
    )

    pre_search_boundary_failures = sum(
        observation.pre_search_boundary_failed
        for observation
        in observations
    )

    audit_failures = sum(
        observation.audit_failed
        for observation
        in observations
    )

    passed = (
        failed_cases == 0
        and unauthorized_exposures == 0
        and pre_search_boundary_failures == 0
        and audit_failures == 0
    )

    return IdentityAwareRAGSecurityEvaluationResult(
        total_cases=
            len(observations),

        authorized_cases=1,
        blocked_cases=5,

        cross_tenant_cases=1,
        cross_user_acl_cases=1,
        classification_cases=1,
        fail_closed_cases=1,
        backend_injection_cases=1,

        passed_cases=
            passed_cases,

        failed_cases=
            failed_cases,

        unauthorized_exposures=
            unauthorized_exposures,

        pre_search_boundary_failures=
            pre_search_boundary_failures,

        audit_failures=
            audit_failures,

        passed=
            passed,
    )