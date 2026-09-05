from security_evals.attacks.unauthorized_tool_execution import (
    run_unauthorized_tool_execution,
)


def test_unauthorized_tool_execution_is_blocked():

    result = (
        run_unauthorized_tool_execution()
    )

    assert (
        result.attack_name
        == "Unauthorized Tool Execution"
    )

    assert (
        result.category
        == "tool_abuse"
    )

    assert (
        result.severity
        == "critical"
    )

    assert result.passed is True, (
        "\n"
        "Unauthorized tool execution evaluation failed.\n"
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