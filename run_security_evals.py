from security_evals.attacks.unauthorized_tool_execution import (
    run_unauthorized_tool_execution,
)

from collections.abc import Callable

from security_evals.attacks.indirect_prompt_injection import (
    run_indirect_prompt_injection,
)

from security_evals.models import (
    SecurityEvalResult,
)


# -------------------------------------------------
# REGISTERED SECURITY EVALUATIONS
# -------------------------------------------------


SecurityEvaluation = Callable[
    [],
    SecurityEvalResult,
]


SECURITY_EVALUATIONS: list[
    SecurityEvaluation
] = [
    run_indirect_prompt_injection,
    run_unauthorized_tool_execution,
]


# -------------------------------------------------
# RUN EVALUATIONS
# -------------------------------------------------


def run_security_evaluations(
) -> list[SecurityEvalResult]:

    """
    Run every registered security evaluation.

    Each attack returns a standardized
    SecurityEvalResult so the harness can report
    results consistently across different attack
    categories.
    """

    results = []

    for evaluation in (
        SECURITY_EVALUATIONS
    ):

        result = evaluation()

        results.append(
            result
        )

    return results


# -------------------------------------------------
# CALCULATE SECURITY SCORE
# -------------------------------------------------


def calculate_security_score(
    results: list[SecurityEvalResult],
) -> float:

    if not results:

        return 0.0

    passed_count = sum(
        1
        for result in results
        if result.passed
    )

    return (
        passed_count
        / len(results)
        * 100
    )


# -------------------------------------------------
# PRINT EVALUATION DETAILS
# -------------------------------------------------


def print_result_details(
    result: SecurityEvalResult,
) -> None:

    status = (
        "PASS"
        if result.passed
        else "FAIL"
    )

    print(
        f"\n[{status}] "
        f"{result.attack_name}"
    )

    print(
        f"Category: {result.category}"
    )

    print(
        f"Severity: {result.severity}"
    )

    print("\nExpected:")

    print(
        result.expected_behavior
    )

    print("\nObserved:")

    print(
        result.observed_behavior
    )

    print("\nEvidence:")

    for item in result.evidence:

        print(
            f"  - {item}"
        )


# -------------------------------------------------
# PRINT SUMMARY REPORT
# -------------------------------------------------


def print_security_report(
    results: list[SecurityEvalResult],
) -> None:

    total = len(
        results
    )

    passed = sum(
        1
        for result in results
        if result.passed
    )

    failed = (
        total
        - passed
    )

    score = (
        calculate_security_score(
            results
        )
    )

    print(
        "=" * 68
    )

    print(
        "VM AI AGENT SECURITY EVALUATION"
    )

    print(
        "=" * 68
    )

    print()

    print(
        f"{'Attack':<38}"
        f"{'Severity':<12}"
        f"{'Result':<10}"
    )

    print(
        "-" * 68
    )

    for result in results:

        status = (
            "PASS"
            if result.passed
            else "FAIL"
        )

        print(
            f"{result.attack_name:<38}"
            f"{result.severity.upper():<12}"
            f"{status:<10}"
        )

    print(
        "-" * 68
    )

    print(
        f"Passed: {passed}"
    )

    print(
        f"Failed: {failed}"
    )

    print(
        f"Total:  {total}"
    )

    print(
        f"Security Score: {score:.1f}%"
    )

    print(
        "=" * 68
    )

    # -------------------------------------------------
    # SHOW FAILURE DETAILS
    # -------------------------------------------------

    failed_results = [
        result
        for result in results
        if not result.passed
    ]

    if failed_results:

        print(
            "\nFAILED EVALUATION DETAILS"
        )

        print(
            "=" * 68
        )

        for result in (
            failed_results
        ):

            print_result_details(
                result
            )


# -------------------------------------------------
# MAIN
# -------------------------------------------------


def main() -> None:

    results = (
        run_security_evaluations()
    )

    print_security_report(
        results
    )

    failed = any(
        not result.passed
        for result in results
    )

    # Return a non-zero process exit code if any
    # security evaluation fails. This makes the
    # harness suitable for future CI/CD integration.
    raise SystemExit(
        1
        if failed
        else 0
    )


if __name__ == "__main__":

    main()