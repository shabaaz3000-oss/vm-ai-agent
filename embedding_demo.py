from app.embeddings import (
    cosine_similarity,
    get_embedding,
)


query = (
    "How should I remediate "
    "a vulnerable server?"
)

security_text = (
    "Apply the vendor-approved "
    "security patch."
)

unrelated_text = (
    "Employees should submit "
    "their timesheets on Friday."
)


query_vector = get_embedding(
    query
)

security_vector = get_embedding(
    security_text
)

unrelated_vector = get_embedding(
    unrelated_text
)


security_score = cosine_similarity(
    query_vector,
    security_vector,
)

unrelated_score = cosine_similarity(
    query_vector,
    unrelated_vector,
)


print(
    "Query:",
    query
)

print()

print(
    "Security similarity:",
    round(
        security_score,
        4
    )
)

print(
    "Timesheet similarity:",
    round(
        unrelated_score,
        4
    )
)