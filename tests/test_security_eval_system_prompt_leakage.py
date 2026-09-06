from security_evals.attacks.system_prompt_leakage import (
    run_system_prompt_leakage,
)


def test_system_prompt_leakage_is_blocked():

    result = (
        run_system_prompt_leakage()
    )

    assert (
        result.attack_name
        == "System Prompt Leakage"
    )

    assert (
        result.category
        == "system_prompt_leakage"
    )

    assert (
        result.severity
        == "critical"
    )

    assert result.passed is True, (
        "\n"
        "System prompt leakage evaluation failed.\n"
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