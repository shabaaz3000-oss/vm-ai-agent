from security_evals.attacks.rag_poisoning import (
    run_rag_poisoning,
)


def test_rag_poisoning_is_contained():

    result = (
        run_rag_poisoning()
    )

    assert (
        result.attack_name
        == "RAG Poisoning"
    )

    assert (
        result.category
        == "rag_poisoning"
    )

    assert (
        result.severity
        == "critical"
    )

    assert result.passed is True, (
        "\n"
        "RAG poisoning evaluation failed.\n"
        "\n"
        f"Expected:\n"
        f"{result.expected_behavior}\n"
        "\n"
        f"Observed:\n"
        f"{result.observed_behavior}\n"
        "\n"
        "Evidence:\n"
        + "\n".join(
            f"- {item}"
            for item in result.evidence
        )
    )