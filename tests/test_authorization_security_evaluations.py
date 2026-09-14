import pytest

from app.authorization_security_evaluator import (
    evaluate_authorization_case,
    load_authorization_security_cases,
    run_authorization_security_evaluation,
)


CASES = (
    load_authorization_security_cases()
)


# -------------------------------------------------
# CORPUS INTEGRITY
# -------------------------------------------------


def test_authorization_security_corpus_metadata_is_valid():

    required_fields = {
        "id",
        "name",
        "category",
        "operation",
        "input",
        "expected",
        "severity",
    }

    valid_operations = {
        "authenticate",
        "require_approver",
        "tool_permission",
        "construct_principal",
    }

    valid_severities = {
        "low",
        "medium",
        "high",
        "critical",
    }

    assert CASES

    ids = []

    for case in CASES:

        assert required_fields <= case.keys()

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

        assert (
            case["operation"]
            in valid_operations
        )

        assert isinstance(
            case["input"],
            dict,
        )

        assert isinstance(
            case["expected"],
            dict,
        )

        assert isinstance(
            case["expected"]["allowed"],
            bool,
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


# -------------------------------------------------
# INDIVIDUAL CASES
# -------------------------------------------------


@pytest.mark.parametrize(
    "case",
    CASES,
    ids=[
        case["id"]
        for case in CASES
    ],
)
def test_authorization_security_case(
    case,
):

    result = (
        evaluate_authorization_case(
            case
        )
    )

    assert result.passed is True, (
        f"{case['id']} failed: "
        f"expected_allowed="
        f"{result.expected_allowed}, "
        f"observed_allowed="
        f"{result.observed_allowed}, "
        f"expected_status="
        f"{result.expected_status}, "
        f"observed_status="
        f"{result.observed_status}, "
        f"expected_role="
        f"{result.expected_role}, "
        f"observed_role="
        f"{result.observed_role}, "
        f"expected_exception="
        f"{result.expected_exception}, "
        f"observed_exception="
        f"{result.observed_exception}"
    )


# -------------------------------------------------
# AGGREGATE RESULT
# -------------------------------------------------


def test_authorization_security_evaluator_passes():

    result = (
        run_authorization_security_evaluation()
    )

    assert result.total_cases == 8

    assert result.allowed_cases == 4
    assert result.blocked_cases == 4

    assert result.passed_cases == 8
    assert result.failed_cases == 0

    assert result.unexpected_allows == 0
    assert result.unexpected_blocks == 0

    assert result.status_mismatches == 0
    assert result.role_mismatches == 0
    assert result.exception_mismatches == 0

    assert result.passed is True