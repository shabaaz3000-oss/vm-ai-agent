from app.models import (
    KnowledgeChunk,
)

from app.rag_ingestion import (
    build_knowledge_chunks,
)

from app.retrieval_authorization import (
    RetrievalPrincipal,
    is_knowledge_chunk_authorized,
)

from app.retriever import (
    KnowledgeRetriever,
)

from app.vector_index import (
    IndexedChunk,
)

import app.retriever as retriever_module


def principal(
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


def chunk(
    *,
    tenant_id: str | None,
    access_level: str = "standard",
    allowed_principal_ids=None,
    source_id: str = "doc",
) -> KnowledgeChunk:

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
    )


def indexed(value: KnowledgeChunk) -> IndexedChunk:

    return IndexedChunk(
        chunk=value,
        embedding=[
            1.0,
            0.0,
        ],
    )


def test_same_tenant_tenant_wide_document_is_allowed():

    assert is_knowledge_chunk_authorized(
        chunk=chunk(
            tenant_id="tenant-a",
        ),
        retrieval_principal=principal(),
    )


def test_cross_tenant_document_is_denied():

    assert not is_knowledge_chunk_authorized(
        chunk=chunk(
            tenant_id="tenant-b",
        ),
        retrieval_principal=principal(
            tenant_id="tenant-a",
        ),
    )


def test_unscoped_document_is_denied_in_principal_aware_retrieval():

    assert not is_knowledge_chunk_authorized(
        chunk=chunk(
            tenant_id=None,
        ),
        retrieval_principal=principal(),
    )


def test_document_acl_allows_named_principal():

    assert is_knowledge_chunk_authorized(
        chunk=chunk(
            tenant_id="tenant-a",
            allowed_principal_ids=(
                "alice",
            ),
        ),
        retrieval_principal=principal(
            principal_id="alice",
        ),
    )


def test_document_acl_denies_other_principal():

    assert not is_knowledge_chunk_authorized(
        chunk=chunk(
            tenant_id="tenant-a",
            allowed_principal_ids=(
                "alice",
            ),
        ),
        retrieval_principal=principal(
            principal_id="bob",
        ),
    )


def test_empty_document_acl_denies_everyone():

    assert not is_knowledge_chunk_authorized(
        chunk=chunk(
            tenant_id="tenant-a",
            allowed_principal_ids=(),
        ),
        retrieval_principal=principal(),
    )


def test_restricted_document_still_requires_restricted_access():

    restricted = chunk(
        tenant_id="tenant-a",
        access_level="restricted",
    )

    assert not is_knowledge_chunk_authorized(
        chunk=restricted,
        retrieval_principal=principal(
            retrieval_access="standard",
        ),
    )

    assert is_knowledge_chunk_authorized(
        chunk=restricted,
        retrieval_principal=principal(
            retrieval_access="restricted",
        ),
    )


def test_cross_tenant_and_acl_denied_chunks_never_reach_search(
    monkeypatch,
):

    allowed = indexed(
        chunk(
            tenant_id="tenant-a",
            source_id="allowed",
        )
    )

    wrong_tenant = indexed(
        chunk(
            tenant_id="tenant-b",
            source_id="wrong-tenant",
        )
    )

    wrong_principal = indexed(
        chunk(
            tenant_id="tenant-a",
            source_id="wrong-principal",
            allowed_principal_ids=(
                "bob",
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

        received_index = list(index)

        return []

    monkeypatch.setattr(
        retriever_module,
        "search_vector_index",
        fake_search_vector_index,
    )

    retriever = KnowledgeRetriever(
        index=[
            allowed,
            wrong_tenant,
            wrong_principal,
        ]
    )

    result = retriever.retrieve(
        query="security guidance",
        retrieval_principal=principal(
            principal_id="alice",
            tenant_id="tenant-a",
        ),
    )

    assert result == []

    assert received_index == [
        allowed
    ]


def test_trusted_ingestion_assigns_tenant_and_document_acl(
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
        document_acl={
            "alpha": (
                "alice",
            ),
        },
    )

    assert chunks

    for value in chunks:

        assert (
            value.tenant_id
            == "tenant-a"
        )

        assert (
            value.allowed_principal_ids
            == ("alice",)
        )


def test_legacy_unscoped_access_level_path_remains_compatible():

    assert is_knowledge_chunk_authorized(
        chunk=chunk(
            tenant_id=None,
            access_level="standard",
        ),
        caller_access="standard",
    )
