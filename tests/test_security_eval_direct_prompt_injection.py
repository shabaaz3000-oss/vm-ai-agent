from security_evals.attacks.direct_prompt_injection import (
    run_direct_prompt_injection,
)


def test_direct_prompt_injection_is_blocked():

    result = run_direct_prompt_injection()

    assert (
        result.attack_name
        == "Direct Prompt Injection"
    )

    assert (
        result.category
        == "prompt_injection"
    )

    assert (
        result.severity
        == "critical"
    )

    assert result.passed is True, (
        "\n"
        "Direct prompt injection evaluation failed.\n"
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