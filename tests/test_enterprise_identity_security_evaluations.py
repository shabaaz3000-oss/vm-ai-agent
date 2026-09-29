import pytest

from app.enterprise_identity_security_evaluator import (
    evaluate_enterprise_identity_case,
    load_enterprise_identity_security_cases,
    run_enterprise_identity_security_evaluation,
)


CASES = (
    load_enterprise_identity_security_cases()
)


def test_enterprise_identity_security_corpus_metadata():

    required = {
        "id",
        "name",
        "category",
        "attack",
        "expected_behavior",
        "severity",
    }

    valid_behaviors = {
        "allow",
        "block",
        "protect_authority",
    }

    valid_severities = {
        "low",
        "medium",
        "high",
        "critical",
    }

    assert len(CASES) == 16

    ids = []

    for case in CASES:

        assert required <= case.keys()

        assert isinstance(
            case["id"],
            str,
        )

        assert case["id"].strip()

        assert isinstance(
            case["name"],
            str,
        )

        assert case["name"].strip()

        assert isinstance(
            case["category"],
            str,
        )

        assert case["category"].strip()

        assert isinstance(
            case["attack"],
            str,
        )

        assert case["attack"].strip()

        assert (
            case["expected_behavior"]
            in valid_behaviors
        )

        assert (
            case["severity"]
            in valid_severities
        )

        ids.append(
            case["id"]
        )

    assert (
        len(ids)
        == len(set(ids))
    )


def test_enterprise_identity_security_loader():

    cases = (
        load_enterprise_identity_security_cases()
    )

    assert len(cases) == 16


@pytest.mark.parametrize(
    "case",
    CASES,
    ids=[
        case["id"]
        for case in CASES
    ],
)
def test_enterprise_identity_security_case(
    case,
):

    result = (
        evaluate_enterprise_identity_case(
            case
        )
    )

    assert result.passed is True, (
        f"{case['id']} failed: "
        f"expected_behavior="
        f"{result.expected_behavior}, "
        f"observed_achieved="
        f"{result.observed_achieved}, "
        f"execution_error="
        f"{result.execution_error}"
    )


def test_enterprise_identity_security_evaluator_passes():

    result = (
        run_enterprise_identity_security_evaluation()
    )

    assert result.total_cases == 16

    assert result.allowed_cases == 2
    assert result.blocked_cases == 8

    assert (
        result.authority_protection_cases
        == 6
    )

    assert result.passed_cases == 16
    assert result.failed_cases == 0

    assert result.unexpected_allows == 0
    assert result.unexpected_blocks == 0

    assert result.authority_failures == 0
    assert result.execution_errors == 0

    assert result.passed is True
