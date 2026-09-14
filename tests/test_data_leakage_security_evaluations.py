import pytest

from app.data_leakage_security_evaluator import (
    evaluate_data_leakage_case,
    load_data_leakage_security_cases,
    run_data_leakage_security_evaluation,
)


CASES = (
    load_data_leakage_security_cases()
)


# -------------------------------------------------
# CORPUS INTEGRITY
# -------------------------------------------------


def test_data_leakage_security_corpus_metadata_is_valid():

    required_fields = {
        "id",
        "name",
        "category",
        "operation",
        "principal_role",
        "principal_retrieval_access",
        "caller_access",
        "top_k",
        "candidates",
        "expected_returned_ids",
        "expected_tool_access",
        "expected_canary_exposed",
        "expected_error",
        "severity",
    }

    valid_operations = {
        "tool_search",
        "direct_retrieval",
    }

    valid_roles = {
        "ANALYST",
        "APPROVER",
    }

    valid_retrieval_access = {
        "standard",
        "restricted",
    }

    valid_severities = {
        "low",
        "medium",
        "high",
        "critical",
    }

    ids = []

    assert len(CASES) == 8

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
            case["top_k"],
            int,
        )

        assert case["top_k"] > 0

        assert isinstance(
            case["candidates"],
            list,
        )

        assert case["candidates"]

        assert isinstance(
            case["expected_returned_ids"],
            list,
        )

        assert isinstance(
            case["expected_canary_exposed"],
            bool,
        )

        assert (
            case["severity"]
            in valid_severities
        )

        # -------------------------------------------------
        # TOOL-SEARCH IDENTITY CONTRACT
        # -------------------------------------------------

        if (
            case["operation"]
            == "tool_search"
        ):

            assert (
                case["principal_role"]
                in valid_roles
            )

            assert (
                case[
                    "principal_retrieval_access"
                ]
                in valid_retrieval_access
            )

            # The LLM-visible tool does not accept a
            # caller_access argument.
            assert (
                case["caller_access"]
                is None
            )

            # The access passed to the retriever must be
            # derived from the authenticated principal.
            assert (
                case["expected_tool_access"]
                == case[
                    "principal_retrieval_access"
                ]
            )

        # -------------------------------------------------
        # DIRECT RETRIEVER CONTRACT
        # -------------------------------------------------

        else:

            assert (
                case["principal_role"]
                is None
            )

            assert (
                case[
                    "principal_retrieval_access"
                ]
                is None
            )

            assert isinstance(
                case["caller_access"],
                str,
            )

            assert (
                case["expected_tool_access"]
                is None
            )

        candidate_ids = []

        for candidate in (
            case["candidates"]
        ):

            assert {
                "id",
                "access_level",
                "similarity",
                "sensitive",
            } <= candidate.keys()

            assert (
                candidate["access_level"]
                in {
                    "standard",
                    "restricted",
                }
            )

            assert (
                -1.0
                <= candidate["similarity"]
                <= 1.0
            )

            assert isinstance(
                candidate["sensitive"],
                bool,
            )

            candidate_ids.append(
                candidate["id"]
            )

        assert (
            len(candidate_ids)
            == len(set(candidate_ids))
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
def test_data_leakage_security_case(
    case,
):

    result = (
        evaluate_data_leakage_case(
            case
        )
    )

    assert result.passed is True, (
        f"{case['id']} failed: "
        f"expected_returned_ids="
        f"{result.expected_returned_ids}, "
        f"observed_returned_ids="
        f"{result.observed_returned_ids}, "
        f"expected_tool_access="
        f"{result.expected_tool_access}, "
        f"observed_tool_access="
        f"{result.observed_tool_access}, "
        f"expected_canary_exposed="
        f"{result.expected_canary_exposed}, "
        f"observed_canary_exposed="
        f"{result.observed_canary_exposed}, "
        f"expected_error="
        f"{result.expected_error}, "
        f"observed_error="
        f"{result.observed_error}"
    )


# -------------------------------------------------
# AGGREGATE RESULT
# -------------------------------------------------


def test_data_leakage_security_evaluator_passes():

    result = (
        run_data_leakage_security_evaluation()
    )

    assert result.total_cases == 8

    assert result.passed_cases == 8
    assert result.failed_cases == 0

    assert result.unexpected_exposures == 0

    assert result.result_mismatches == 0
    assert result.access_mismatches == 0
    assert result.error_mismatches == 0

    assert result.passed is True