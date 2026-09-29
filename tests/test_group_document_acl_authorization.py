from __future__ import annotations

import pytest

from pydantic import ValidationError

import app.retriever as retriever_module

from app.auth import Principal

from app.enterprise_authorization_evidence import (
    EnterpriseAuthorizationEvidence,
    ValidatedEnterpriseToken,
)

from app.enterprise_identity import (
    EnterpriseIdentity,
)

from app.enterprise_principal_binding import (
    EnterprisePrincipalBinding,
)

from app.enterprise_security_context import (
    build_enterprise_retrieval_principal_from_validated_token,
)

from app.enterprise_tenant_binding import (
    EnterpriseTenantBinding,
)

from app.models import (
    KnowledgeChunk,
)

from app.rag_ingestion import (
    build_knowledge_chunks,
)

from app.retrieval_authorization import (
    RetrievalPrincipal,
    build_retrieval_principal,
    evaluate_knowledge_chunk_authorization,
    is_knowledge_chunk_authorized,
)

from app.retriever import (
    KnowledgeRetriever,
)

from app.security_context import (
    SecurityContext,
)

from app.vector_index import (
    IndexedChunk,
    SearchResult,
)


GROUP_A = (
    "11111111-1111-1111-1111-111111111111"
)

GROUP_B = (
    "22222222-2222-2222-2222-222222222222"
)

GROUP_C = (
    "33333333-3333-3333-3333-333333333333"
)

ISSUER = (
    "https://login.microsoftonline.com/"
    "44444444-4444-4444-4444-444444444444/"
    "v2.0"
)

IDP_TENANT = (
    "44444444-4444-4444-4444-444444444444"
)


# -------------------------------------------------
# HELPERS
# -------------------------------------------------


def retrieval_principal(
    *,
    principal_id="alice",
    tenant_id="tenant-a",
    retrieval_access="standard",
    group_ids=None,
):

    return RetrievalPrincipal(
        principal_id=principal_id,
        tenant_id=tenant_id,
        retrieval_access=retrieval_access,
        group_ids=group_ids,
    )


def chunk(
    *,
    source_id="document",
    tenant_id="tenant-a",
    access_level="standard",
    allowed_principal_ids=None,
    allowed_group_ids=None,
):

    return KnowledgeChunk(
        chunk_id=f"{source_id}:0:test",
        source_id=source_id,
        source_name=f"{source_id}.md",
        chunk_number=0,
        content=f"{source_id} security guidance",
        source_sha256="a" * 64,
        trust_tier="trusted_reference",
        access_level=access_level,
        tenant_id=tenant_id,
        allowed_principal_ids=
            allowed_principal_ids,
        allowed_group_ids=
            allowed_group_ids,
    )


def indexed(
    value,
):

    return IndexedChunk(
        chunk=value,
        embedding=[
            1.0,
            0.0,
        ],
    )


# -------------------------------------------------
# SECURITY CONTEXT → RETRIEVAL PRINCIPAL
# -------------------------------------------------


def test_retrieval_principal_snapshots_authoritative_group_ids():

    retrieval = (
        build_enterprise_retrieval_principal_from_validated_token(
            enterprise_token(
                group_state=
                    "complete",
                group_ids=(
                    GROUP_B,
                    GROUP_A.upper(),
                ),
            ),
            session_id=
                "server-session",
            principal_bindings=(
                principal_binding(),
            ),
            tenant_bindings=(
                tenant_binding(),
            ),
        )
    )

    assert retrieval.group_ids == (
        GROUP_A,
        GROUP_B,
    )


def test_retrieval_principal_distinguishes_unavailable_groups():

    retrieval = (
        build_enterprise_retrieval_principal_from_validated_token(
            enterprise_token(
                group_state=
                    "not_present",
                group_ids=(),
            ),
            session_id=
                "server-session",
            principal_bindings=(
                principal_binding(),
            ),
            tenant_bindings=(
                tenant_binding(),
            ),
        )
    )

    assert retrieval.group_ids is None


def test_retrieval_principal_rejects_invalid_group_authority():

    with pytest.raises(
        ValidationError
    ):

        retrieval_principal(
            group_ids=(
                "not-a-guid",
            )
        )


# -------------------------------------------------
# GROUP-ONLY ACL
# -------------------------------------------------


def test_group_acl_allows_authoritative_member():

    decision = (
        evaluate_knowledge_chunk_authorization(
            chunk=chunk(
                allowed_group_ids=(
                    GROUP_A,
                ),
            ),
            retrieval_principal=
                retrieval_principal(
                    group_ids=(
                        GROUP_A,
                    )
                ),
        )
    )

    assert decision.allowed is True
    assert decision.reason == "allowed"


def test_group_acl_denies_authoritative_non_member():

    decision = (
        evaluate_knowledge_chunk_authorization(
            chunk=chunk(
                allowed_group_ids=(
                    GROUP_A,
                ),
            ),
            retrieval_principal=
                retrieval_principal(
                    group_ids=(
                        GROUP_B,
                    )
                ),
        )
    )

    assert decision.allowed is False

    assert (
        decision.reason
        == "group_acl_denied"
    )


def test_group_acl_fails_closed_when_membership_unavailable():

    decision = (
        evaluate_knowledge_chunk_authorization(
            chunk=chunk(
                allowed_group_ids=(
                    GROUP_A,
                ),
            ),
            retrieval_principal=
                retrieval_principal(
                    group_ids=None
                ),
        )
    )

    assert decision.allowed is False

    assert (
        decision.reason
        == "group_membership_unavailable"
    )


def test_authoritative_empty_membership_is_not_unavailable():

    decision = (
        evaluate_knowledge_chunk_authorization(
            chunk=chunk(
                allowed_group_ids=(
                    GROUP_A,
                ),
            ),
            retrieval_principal=
                retrieval_principal(
                    group_ids=()
                ),
        )
    )

    assert decision.allowed is False

    assert (
        decision.reason
        == "group_acl_denied"
    )


def test_explicit_empty_group_acl_denies_without_group_resolution():

    decision = (
        evaluate_knowledge_chunk_authorization(
            chunk=chunk(
                allowed_group_ids=(),
            ),
            retrieval_principal=
                retrieval_principal(
                    group_ids=None
                ),
        )
    )

    assert decision.allowed is False

    assert (
        decision.reason
        == "group_acl_denied"
    )


# -------------------------------------------------
# PRINCIPAL + GROUP ACL UNION
# -------------------------------------------------


def test_principal_match_allows_when_group_authority_unavailable():

    decision = (
        evaluate_knowledge_chunk_authorization(
            chunk=chunk(
                allowed_principal_ids=(
                    "alice",
                ),
                allowed_group_ids=(
                    GROUP_A,
                ),
            ),
            retrieval_principal=
                retrieval_principal(
                    principal_id="alice",
                    group_ids=None,
                ),
        )
    )

    assert decision.allowed is True


def test_group_match_allows_when_principal_does_not_match():

    decision = (
        evaluate_knowledge_chunk_authorization(
            chunk=chunk(
                allowed_principal_ids=(
                    "bob",
                ),
                allowed_group_ids=(
                    GROUP_A,
                ),
            ),
            retrieval_principal=
                retrieval_principal(
                    principal_id="alice",
                    group_ids=(
                        GROUP_A,
                    ),
                ),
        )
    )

    assert decision.allowed is True


def test_principal_and_group_mismatch_denies():

    decision = (
        evaluate_knowledge_chunk_authorization(
            chunk=chunk(
                allowed_principal_ids=(
                    "bob",
                ),
                allowed_group_ids=(
                    GROUP_A,
                ),
            ),
            retrieval_principal=
                retrieval_principal(
                    principal_id="alice",
                    group_ids=(
                        GROUP_B,
                    ),
                ),
        )
    )

    assert decision.allowed is False

    assert (
        decision.reason
        == "group_acl_denied"
    )


# -------------------------------------------------
# TENANT + CLASSIFICATION STILL DOMINATE
# -------------------------------------------------


def test_group_membership_cannot_cross_tenant_boundary():

    decision = (
        evaluate_knowledge_chunk_authorization(
            chunk=chunk(
                tenant_id="tenant-b",
                allowed_group_ids=(
                    GROUP_A,
                ),
            ),
            retrieval_principal=
                retrieval_principal(
                    tenant_id="tenant-a",
                    group_ids=(
                        GROUP_A,
                    ),
                ),
        )
    )

    assert decision.allowed is False

    assert (
        decision.reason
        == "tenant_mismatch"
    )


def test_group_membership_does_not_bypass_classification():

    decision = (
        evaluate_knowledge_chunk_authorization(
            chunk=chunk(
                access_level="restricted",
                allowed_group_ids=(
                    GROUP_A,
                ),
            ),
            retrieval_principal=
                retrieval_principal(
                    retrieval_access=
                        "standard",
                    group_ids=(
                        GROUP_A,
                    ),
                ),
        )
    )

    assert decision.allowed is False

    assert (
        decision.reason
        == "classification_denied"
    )


# -------------------------------------------------
# MALFORMED AUTHORIZATION METADATA
# -------------------------------------------------


def test_malformed_document_group_acl_fails_closed():

    valid = chunk(
        allowed_group_ids=(
            GROUP_A,
        )
    )

    corrupted = valid.model_copy(
        update={
            "allowed_group_ids": (
                "not-a-guid",
            )
        }
    )

    decision = (
        evaluate_knowledge_chunk_authorization(
            chunk=corrupted,
            retrieval_principal=
                retrieval_principal(
                    group_ids=(
                        GROUP_A,
                    )
                ),
        )
    )

    assert decision.allowed is False

    assert (
        decision.reason
        == "invalid_authorization_metadata"
    )


def test_tampered_retrieval_group_authority_fails_closed():

    tampered = RetrievalPrincipal.model_construct(
        principal_id="alice",
        tenant_id="tenant-a",
        retrieval_access="standard",
        group_ids=(
            "not-a-guid",
        ),
    )

    decision = (
        evaluate_knowledge_chunk_authorization(
            chunk=chunk(
                allowed_group_ids=(
                    GROUP_A,
                ),
            ),
            retrieval_principal=
                tampered,
        )
    )

    assert decision.allowed is False

    assert (
        decision.reason
        == "invalid_group_authority"
    )


# -------------------------------------------------
# PRE-SEARCH AUTHORIZATION
# -------------------------------------------------


def test_group_denied_chunk_never_reaches_vector_search(
    monkeypatch,
):

    allowed = indexed(
        chunk(
            source_id="allowed",
            allowed_group_ids=(
                GROUP_A,
            ),
        )
    )

    denied = indexed(
        chunk(
            source_id="denied",
            allowed_group_ids=(
                GROUP_B,
            ),
        )
    )

    received_index = None

    def fake_search_vector_index(
        *,
        query,
        index,
        top_k,
    ):

        nonlocal received_index

        received_index = list(
            index
        )

        return []

    monkeypatch.setattr(
        retriever_module,
        "search_vector_index",
        fake_search_vector_index,
    )

    retriever = KnowledgeRetriever(
        index=[
            allowed,
            denied,
        ]
    )

    result = retriever.retrieve(
        query="security guidance",
        retrieval_principal=
            retrieval_principal(
                group_ids=(
                    GROUP_A,
                )
            ),
    )

    assert result == []

    assert received_index == [
        allowed
    ]


def test_group_unavailable_document_skips_search_entirely(
    monkeypatch,
):

    search_called = False

    def fake_search_vector_index(
        **kwargs,
    ):

        nonlocal search_called
        search_called = True

        return []

    monkeypatch.setattr(
        retriever_module,
        "search_vector_index",
        fake_search_vector_index,
    )

    retriever = KnowledgeRetriever(
        index=[
            indexed(
                chunk(
                    allowed_group_ids=(
                        GROUP_A,
                    ),
                )
            )
        ]
    )

    result = retriever.retrieve(
        query="security guidance",
        retrieval_principal=
            retrieval_principal(
                group_ids=None
            ),
    )

    assert result == []
    assert search_called is False


# -------------------------------------------------
# DEFENSE-IN-DEPTH POST-SEARCH RECHECK
# -------------------------------------------------


def test_adversarial_backend_cannot_return_group_denied_chunk(
    monkeypatch,
):

    allowed_chunk = chunk(
        source_id="allowed",
        allowed_group_ids=(
            GROUP_A,
        ),
    )

    denied_chunk = chunk(
        source_id="denied",
        allowed_group_ids=(
            GROUP_B,
        ),
    )

    retriever = KnowledgeRetriever(
        index=[
            indexed(
                allowed_chunk
            )
        ]
    )

    monkeypatch.setattr(
        retriever_module,
        "search_vector_index",
        lambda **kwargs: [
            SearchResult(
                chunk=
                    denied_chunk,
                similarity=0.99,
            ),
            SearchResult(
                chunk=
                    allowed_chunk,
                similarity=0.80,
            ),
        ],
    )

    evidence = retriever.retrieve(
        query="security guidance",
        retrieval_principal=
            retrieval_principal(
                group_ids=(
                    GROUP_A,
                )
            ),
    )

    assert len(evidence) == 1

    assert (
        evidence[0].source_id
        == "allowed"
    )


# -------------------------------------------------
# TRUSTED INGESTION
# -------------------------------------------------


def test_trusted_ingestion_assigns_group_acl(
    tmp_path,
):

    standard = (
        tmp_path
        / "standard"
    )

    standard.mkdir()

    (
        standard
        / "alpha.md"
    ).write_text(
        "Trusted alpha guidance.",
        encoding="utf-8",
    )

    chunks = build_knowledge_chunks(
        tmp_path,
        tenant_id="tenant-a",
        document_group_acl={
            "alpha": (
                GROUP_A,
                GROUP_B,
            )
        },
    )

    assert chunks

    for value in chunks:

        assert (
            value.allowed_group_ids
            == (
                GROUP_A,
                GROUP_B,
            )
        )


def test_group_acl_requires_explicit_tenant(
    tmp_path,
):

    (
        tmp_path
        / "alpha.md"
    ).write_text(
        "Trusted alpha guidance.",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError
    ):

        build_knowledge_chunks(
            tmp_path,
            document_group_acl={
                "alpha": (
                    GROUP_A,
                )
            },
        )


# -------------------------------------------------
# VALIDATED ENTERPRISE TOKEN → SECURITY CONTEXT
# -------------------------------------------------


def enterprise_token(
    *,
    group_state,
    group_ids,
):

    identity = EnterpriseIdentity(
        issuer=ISSUER,
        subject="subject-123",
        identity_provider_tenant_id=
            IDP_TENANT,
    )

    evidence = EnterpriseAuthorizationEvidence(
        app_roles=(
            "VM.Reader",
        ),
        group_ids=
            group_ids,
        group_membership_state=
            group_state,
    )

    return ValidatedEnterpriseToken(
        identity=identity,
        authorization=evidence,
    )


def principal_binding():

    return EnterprisePrincipalBinding(
        issuer=ISSUER,
        identity_provider_tenant_id=
            IDP_TENANT,
        subject="subject-123",
        principal_id="alice",
        role="ANALYST",
        retrieval_access="standard",
        session_revocation_access="self",
    )


def tenant_binding():

    return EnterpriseTenantBinding(
        issuer=ISSUER,
        identity_provider_tenant_id=
            IDP_TENANT,
        tenant_id="tenant-a",
    )


@pytest.mark.parametrize(
    "state",
    [
        "complete",
        "resolved",
    ],
)
def test_validated_token_snapshots_complete_group_authority(
    state,
):

    retrieval = (
        build_enterprise_retrieval_principal_from_validated_token(
            enterprise_token(
                group_state=state,
                group_ids=(
                    GROUP_B,
                    GROUP_A,
                ),
            ),
            session_id=
                "server-session",
            principal_bindings=(
                principal_binding(),
            ),
            tenant_bindings=(
                tenant_binding(),
            ),
        )
    )

    assert retrieval.group_ids == (
        GROUP_A,
        GROUP_B,
    )


def test_missing_group_claim_snapshots_unavailable_authority():

    retrieval = (
        build_enterprise_retrieval_principal_from_validated_token(
            enterprise_token(
                group_state=
                    "not_present",
                group_ids=(),
            ),
            session_id=
                "server-session",
            principal_bindings=(
                principal_binding(),
            ),
            tenant_bindings=(
                tenant_binding(),
            ),
        )
    )

    assert retrieval.group_ids is None


# -------------------------------------------------
# LEGACY COMPATIBILITY
# -------------------------------------------------


def test_existing_tenant_wide_principal_retrieval_remains_allowed():

    assert is_knowledge_chunk_authorized(
        chunk=chunk(
            allowed_principal_ids=None,
            allowed_group_ids=None,
        ),
        retrieval_principal=
            retrieval_principal(
                group_ids=None
            ),
    )
