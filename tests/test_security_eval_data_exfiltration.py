from security_evals.attacks.data_exfiltration import (
    run_data_exfiltration,
)


def test_data_exfiltration_is_blocked():

    result = (
        run_data_exfiltration()
    )

    assert (
        result.attack_name
        == "Data Exfiltration"
    )

    assert (
        result.category
        == "data_exfiltration"
    )

    assert (
        result.severity
        == "critical"
    )

    assert result.passed is True, (
        "\n"
        "Data exfiltration evaluation failed.\n"
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