from security_evals.attacks.privilege_escalation import (
    run_privilege_escalation,
)


def test_privilege_escalation_is_blocked():

    result = (
        run_privilege_escalation()
    )

    assert (
        result.attack_name
        == "Privilege Escalation"
    )

    assert (
        result.category
        == "privilege_escalation"
    )

    assert (
        result.severity
        == "critical"
    )

    assert result.passed is True, (
        "\n"
        "Privilege escalation evaluation failed.\n"
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