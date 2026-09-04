from hashlib import sha256
from pathlib import Path
from typing import Literal

from app.models import KnowledgeChunk
from app.models import KnowledgeDocument


TRUSTED_KNOWLEDGE_DIR = Path(
    "data/knowledge/trusted"
)

MAX_DOCUMENT_BYTES = (
    128 * 1024
)

CHUNK_SIZE = 1200

CHUNK_OVERLAP = 200


KnowledgeAccessLevel = Literal[
    "standard",
    "restricted",
]


class KnowledgeIngestionError(
    ValueError
):
    pass


# -------------------------------------------------
# HASHING
# -------------------------------------------------


def _sha256_text(
    text: str
) -> str:

    return sha256(
        text.encode("utf-8")
    ).hexdigest()


# -------------------------------------------------
# LOAD ONE ACCESS-CLASSIFIED DIRECTORY
# -------------------------------------------------


def _load_documents_from_directory(
    directory: Path,
    trusted_root: Path,
    access_level: KnowledgeAccessLevel,
    seen_source_ids: set[str],
) -> list[KnowledgeDocument]:

    documents = []

    if not directory.exists():
        return documents

    if directory.is_symlink():
        raise KnowledgeIngestionError(
            "Knowledge access directories "
            "cannot be symbolic links."
        )

    if not directory.is_dir():
        raise KnowledgeIngestionError(
            "Knowledge access path "
            "must be a directory."
        )

    resolved_directory = (
        directory.resolve()
    )

    if (
        trusted_root
        != resolved_directory
        and trusted_root
        not in resolved_directory.parents
    ):
        raise KnowledgeIngestionError(
            "Knowledge access directory "
            "escaped the trusted root."
        )

    for path in sorted(
        directory.glob("*.md")
    ):

        if path.is_symlink():
            raise KnowledgeIngestionError(
                "Symbolic links are not "
                "allowed in the trusted "
                "knowledge directory."
            )

        resolved_path = (
            path.resolve()
        )

        if (
            resolved_directory
            not in resolved_path.parents
        ):
            raise KnowledgeIngestionError(
                "Knowledge document escaped "
                "its authorized directory."
            )

        if (
            resolved_path.stat().st_size
            > MAX_DOCUMENT_BYTES
        ):
            raise KnowledgeIngestionError(
                "Knowledge document exceeds "
                "the maximum allowed size."
            )

        text = (
            resolved_path
            .read_text(
                encoding="utf-8"
            )
            .strip()
        )

        if not text:
            raise KnowledgeIngestionError(
                "Knowledge document cannot "
                "be empty."
            )

        source_id = (
            resolved_path.stem
        )

        if source_id in seen_source_ids:
            raise KnowledgeIngestionError(
                "Duplicate knowledge source_id "
                "detected."
            )

        seen_source_ids.add(
            source_id
        )

        documents.append(
            KnowledgeDocument(
                source_id=
                    source_id,

                source_name=
                    resolved_path.name,

                content=
                    text,

                content_sha256=
                    _sha256_text(
                        text
                    ),

                trust_tier=
                    "trusted_reference",

                access_level=
                    access_level,
            )
        )

    return documents


# -------------------------------------------------
# LOAD TRUSTED DOCUMENTS
# -------------------------------------------------


def load_trusted_documents(
    root: Path = TRUSTED_KNOWLEDGE_DIR
) -> list[KnowledgeDocument]:

    root = root.resolve()

    if not root.exists():
        raise KnowledgeIngestionError(
            "Trusted knowledge directory "
            "does not exist."
        )

    if not root.is_dir():
        raise KnowledgeIngestionError(
            "Trusted knowledge path "
            "must be a directory."
        )

    documents = []

    seen_source_ids: set[str] = set()

    standard_directory = (
        root / "standard"
    )

    restricted_directory = (
        root / "restricted"
    )

    classified_directories_exist = (
        standard_directory.exists()
        or restricted_directory.exists()
    )

    # -------------------------------------------------
    # CLASSIFIED DIRECTORY MODE
    # -------------------------------------------------
    #
    # The directory selected by server-controlled
    # application structure determines access level.
    #
    # Document content cannot promote or downgrade
    # its own authorization classification.
    # -------------------------------------------------

    if classified_directories_exist:

        documents.extend(
            _load_documents_from_directory(
                directory=
                    standard_directory,

                trusted_root=
                    root,

                access_level=
                    "standard",

                seen_source_ids=
                    seen_source_ids,
            )
        )

        documents.extend(
            _load_documents_from_directory(
                directory=
                    restricted_directory,

                trusted_root=
                    root,

                access_level=
                    "restricted",

                seen_source_ids=
                    seen_source_ids,
            )
        )

    # -------------------------------------------------
    # LEGACY / TEST COMPATIBILITY MODE
    # -------------------------------------------------
    #
    # Existing tests create Markdown documents directly
    # under a temporary trusted root.
    #
    # When no classified directories exist, those
    # documents are treated as standard access.
    #
    # In the real application, standard/ and restricted/
    # directories exist, so root-level documents are
    # not loaded.
    # -------------------------------------------------

    else:

        documents.extend(
            _load_documents_from_directory(
                directory=
                    root,

                trusted_root=
                    root,

                access_level=
                    "standard",

                seen_source_ids=
                    seen_source_ids,
            )
        )

    return documents


# -------------------------------------------------
# SPLIT OVERSIZED PARAGRAPHS
# -------------------------------------------------


def _split_oversized_paragraph(
    paragraph: str,
    chunk_size: int,
) -> list[str]:

    if len(paragraph) <= chunk_size:
        return [paragraph]

    words = paragraph.split()

    parts = []
    current_words = []
    current_length = 0

    for word in words:

        # Extremely long single token fallback.
        if len(word) > chunk_size:

            if current_words:

                parts.append(
                    " ".join(
                        current_words
                    )
                )

                current_words = []
                current_length = 0

            for start in range(
                0,
                len(word),
                chunk_size,
            ):

                parts.append(
                    word[
                        start:
                        start + chunk_size
                    ]
                )

            continue

        separator_length = (
            1
            if current_words
            else 0
        )

        proposed_length = (
            current_length
            + separator_length
            + len(word)
        )

        if (
            current_words
            and proposed_length
            > chunk_size
        ):

            parts.append(
                " ".join(
                    current_words
                )
            )

            current_words = [
                word
            ]

            current_length = (
                len(word)
            )

        else:

            current_words.append(
                word
            )

            current_length = (
                proposed_length
            )

    if current_words:

        parts.append(
            " ".join(
                current_words
            )
        )

    return parts


# -------------------------------------------------
# CHUNK DOCUMENT
# -------------------------------------------------


def chunk_document(
    document: KnowledgeDocument,
    chunk_size: int = CHUNK_SIZE,
    overlap: int = CHUNK_OVERLAP,
) -> list[KnowledgeChunk]:

    if chunk_size <= 0:
        raise ValueError(
            "chunk_size must be positive"
        )

    if overlap < 0:
        raise ValueError(
            "overlap cannot be negative"
        )

    if overlap >= chunk_size:
        raise ValueError(
            "overlap must be smaller "
            "than chunk_size"
        )

    raw_paragraphs = [
        paragraph.strip()
        for paragraph
        in document.content.split(
            "\n\n"
        )
        if paragraph.strip()
    ]

    # Prefer paragraph boundaries.
    # Fall back to word boundaries when
    # a single paragraph is too large.

    paragraphs = []

    for paragraph in raw_paragraphs:

        paragraphs.extend(
            _split_oversized_paragraph(
                paragraph,
                chunk_size,
            )
        )

    chunks = []
    current_parts = []
    chunk_number = 0

    # -------------------------------------------------
    # CREATE ONE CHUNK
    # -------------------------------------------------

    def emit_chunk(
        parts: list[str],
        number: int,
    ) -> KnowledgeChunk:

        content = "\n\n".join(
            parts
        )

        chunk_hash = (
            _sha256_text(
                content
            )[:12]
        )

        chunk_id = (
            f"{document.source_id}:"
            f"{number}:"
            f"{chunk_hash}"
        )

        return KnowledgeChunk(
            chunk_id=
                chunk_id,

            source_id=
                document.source_id,

            source_name=
                document.source_name,

            chunk_number=
                number,

            content=
                content,

            source_sha256=
                document.content_sha256,

            trust_tier=
                document.trust_tier,

            access_level=
                document.access_level,
        )

    # -------------------------------------------------
    # BUILD CHUNKS
    # -------------------------------------------------

    for paragraph in paragraphs:

        candidate_parts = (
            current_parts
            + [paragraph]
        )

        candidate_content = (
            "\n\n".join(
                candidate_parts
            )
        )

        if (
            current_parts
            and len(
                candidate_content
            )
            > chunk_size
        ):

            chunks.append(
                emit_chunk(
                    current_parts,
                    chunk_number,
                )
            )

            chunk_number += 1

            # Preserve whole semantic units
            # for overlap when possible.

            overlap_parts = []

            for previous_part in reversed(
                current_parts
            ):

                proposed_overlap = (
                    [previous_part]
                    + overlap_parts
                )

                overlap_content = (
                    "\n\n".join(
                        proposed_overlap
                    )
                )

                if (
                    len(
                        overlap_content
                    )
                    > overlap
                ):
                    break

                overlap_parts = (
                    proposed_overlap
                )

            current_parts = (
                overlap_parts
            )

            # Never allow overlap itself
            # to force the next chunk over
            # the configured maximum.

            while (
                current_parts
                and len(
                    "\n\n".join(
                        current_parts
                        + [paragraph]
                    )
                )
                > chunk_size
            ):

                current_parts.pop(0)

        current_parts.append(
            paragraph
        )

    if current_parts:

        chunks.append(
            emit_chunk(
                current_parts,
                chunk_number,
            )
        )

    return chunks


# -------------------------------------------------
# BUILD ALL KNOWLEDGE CHUNKS
# -------------------------------------------------


def build_knowledge_chunks(
    root: Path = TRUSTED_KNOWLEDGE_DIR
) -> list[KnowledgeChunk]:

    documents = (
        load_trusted_documents(
            root
        )
    )

    chunks = []

    for document in documents:

        chunks.extend(
            chunk_document(
                document
            )
        )

    return chunks