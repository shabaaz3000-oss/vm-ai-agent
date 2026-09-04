import math
import os

from dotenv import load_dotenv
from openai import OpenAI


load_dotenv()


EMBEDDING_MODEL = os.getenv(
    "OPENAI_EMBEDDING_MODEL",
    "text-embedding-3-small",
)


class EmbeddingError(RuntimeError):
    pass


def get_embedding(
    text: str,
) -> list[float]:

    cleaned_text = text.strip()

    if not cleaned_text:
        raise ValueError(
            "Embedding input cannot be empty."
        )

    try:
        client = OpenAI()

        response = client.embeddings.create(
            model=EMBEDDING_MODEL,
            input=cleaned_text,
        )

        embedding = response.data[0].embedding

    except Exception as exc:
        raise EmbeddingError(
            "Failed to generate embedding."
        ) from exc

    if not embedding:
        raise EmbeddingError(
            "Embedding response was empty."
        )

    return embedding


def get_embeddings(
    texts: list[str],
) -> list[list[float]]:

    if not texts:
        raise ValueError(
            "Embedding input list cannot be empty."
        )

    cleaned_texts = [
        text.strip()
        for text in texts
    ]

    if any(
        not text
        for text in cleaned_texts
    ):
        raise ValueError(
            "Embedding inputs cannot be empty."
        )

    try:
        client = OpenAI()

        response = client.embeddings.create(
            model=EMBEDDING_MODEL,
            input=cleaned_texts,
        )

        embeddings = [
            item.embedding
            for item in response.data
        ]

    except Exception as exc:
        raise EmbeddingError(
            "Failed to generate embeddings."
        ) from exc

    if len(embeddings) != len(cleaned_texts):
        raise EmbeddingError(
            "Embedding response count "
            "did not match input count."
        )

    return embeddings


def cosine_similarity(
    vector_a: list[float],
    vector_b: list[float],
) -> float:

    if len(vector_a) != len(vector_b):
        raise ValueError(
            "Vectors must have the same length."
        )

    if not vector_a:
        raise ValueError(
            "Vectors cannot be empty."
        )

    dot_product = sum(
        a * b
        for a, b in zip(
            vector_a,
            vector_b,
        )
    )

    magnitude_a = math.sqrt(
        sum(
            value * value
            for value in vector_a
        )
    )

    magnitude_b = math.sqrt(
        sum(
            value * value
            for value in vector_b
        )
    )

    if (
        magnitude_a == 0
        or magnitude_b == 0
    ):
        raise ValueError(
            "Vectors cannot have zero magnitude."
        )

    return (
        dot_product
        / (
            magnitude_a
            * magnitude_b
        )
    )