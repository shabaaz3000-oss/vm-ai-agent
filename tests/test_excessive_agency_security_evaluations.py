import pytest

from app.excessive_agency_security_evaluator import (
    evaluate_excessive_agency_case,
    load_excessive_agency_security_cases,
    run_excessive_agency_security_evaluation,
)


CASES = (
    load_excessive_agency_security_cases()
)


# -------------------------------------------------
# CORPUS INTEGRITY
# -------------------------------------------------


def test_excessive_agency_security_corpus_metadata_is_valid():

    required_fields = {
        "id",
        "name",
        "category",
        "operation",
        "expected_tool_names",
        "expected_blocked",
        "expected_error",
        "expected_message_contains",
        "severity",
    }

    valid_operations = {
        "inspect_tool_scope",
        "validate_arguments",
        "run_agent",
    }

    valid_severities = {
        "low",
        "medium",
        "high",
        "critical",
    }

    assert len(CASES) == 12

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

        assert isinstance(
            case["category"],
            str,
        )

        assert case["category"].strip()

        assert (
            case["operation"]
            in valid_operations
        )

        assert isinstance(
            case["expected_blocked"],
            bool,
        )

        assert (
            case["severity"]
            in valid_severities
        )

        if (
            case["expected_tool_names"]
            is not None
        ):

            assert isinstance(
                case["expected_tool_names"],
                list,
            )

        if (
            case["expected_error"]
            is not None
        ):

            assert isinstance(
                case["expected_error"],
                str,
            )

        if (
            case["expected_message_contains"]
            is not None
        ):

            assert isinstance(
                case[
                    "expected_message_contains"
                ],
                str,
            )

        if (
            case["operation"]
            == "inspect_tool_scope"
        ):

            assert "state" in case

        if (
            case["operation"]
            == "validate_arguments"
        ):

            assert "arguments" in case

        if (
            case["operation"]
            == "run_agent"
        ):

            assert "responses" in case

            assert isinstance(
                case["responses"],
                list,
            )

            assert case["responses"]

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
def test_excessive_agency_security_case(
    case,
):

    result = (
        evaluate_excessive_agency_case(
            case
        )
    )

    assert result.passed is True, (
        f"{case['id']} failed: "
        f"expected_blocked="
        f"{result.expected_blocked}, "
        f"observed_blocked="
        f"{result.observed_blocked}, "
        f"expected_error="
        f"{result.expected_error}, "
        f"observed_error="
        f"{result.observed_error}, "
        f"expected_tool_names="
        f"{result.expected_tool_names}, "
        f"observed_tool_names="
        f"{result.observed_tool_names}, "
        f"message_matched="
        f"{result.message_matched}"
    )


# -------------------------------------------------
# AGGREGATE RESULT
# -------------------------------------------------


def test_excessive_agency_security_evaluator_passes():

    result = (
        run_excessive_agency_security_evaluation()
    )

    assert result.total_cases == 12

    assert result.permitted_cases == 3
    assert result.blocked_cases == 9

    assert result.passed_cases == 12
    assert result.failed_cases == 0

    assert result.unexpected_allows == 0
    assert result.unexpected_blocks == 0

    assert result.error_mismatches == 0
    assert result.message_mismatches == 0
    assert result.scope_mismatches == 0

    assert result.passed is True