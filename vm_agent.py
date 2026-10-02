from __future__ import annotations

import argparse

from pathlib import Path

from pydantic import ValidationError

from app.demo_analyzer import (
    analyze_demo_vulnerability,
)

from app.security_evaluator import (
    run_rag_security_evaluation,
    run_security_evaluation,
)

from app.tool_security_evaluator import (
    run_tool_security_evaluation,
)

from app.authorization_security_evaluator import (
    run_authorization_security_evaluation,
)

from app.data_leakage_security_evaluator import (
    run_data_leakage_security_evaluation,
)

from app.excessive_agency_security_evaluator import (
    run_excessive_agency_security_evaluation,
)

from app.mcp_identity_security_evaluator import (
    run_mcp_identity_security_evaluation,
)

from app.enterprise_identity_security_evaluator import (
    run_enterprise_identity_security_evaluation,
)

from app.identity_aware_rag_security_evaluator import (
    run_identity_aware_rag_security_evaluation,
)

from app.workflow_authority_security_evaluator import (
    run_workflow_authority_security_evaluation,
)


from run_security_evals import (
    calculate_security_score,
    run_security_evaluations,
)

from app.providers.asset_context_csv import (
    AssetContextCsvError,
)

from app.providers.csv_import import (
    CsvImportError,
)

from app.providers.tenable_csv import (
    TenableCsvImportError,
    TenableCsvProvider,
)

from app.workflow import prepare_workflow


# -------------------------------------------------
# PROJECT PATHS
# -------------------------------------------------


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parent
)


DEMO_DATA_DIR = (
    PROJECT_ROOT
    / "data"
    / "demo"
)


DEMO_FINDINGS_PATH = (
    DEMO_DATA_DIR
    / "tenable-findings.csv"
)


DEMO_ASSETS_PATH = (
    DEMO_DATA_DIR
    / "tenable-assets.csv"
)


DEMO_CONTEXT_PATH = (
    DEMO_DATA_DIR
    / "asset-context.csv"
)


DEMO_FINDING_ID = (
    "FIND-DEMO-0001"
)


# -------------------------------------------------
# CLI ERROR
# -------------------------------------------------


class VmAgentCliError(ValueError):
    """
    Raised when command-line input cannot be safely
    accepted.
    """


# -------------------------------------------------
# SAFE TERMINAL TEXT
# -------------------------------------------------


def _safe_text(
    value: object,
) -> str:

    """
    Remove non-printable terminal control characters
    before displaying externally influenced content.

    Newlines and tabs are preserved for readability.
    """

    text = str(
        value
    )

    return "".join(
        character
        for character
        in text
        if (
            character in "\n\t"
            or character.isprintable()
        )
    )


# -------------------------------------------------
# ARGUMENT PARSER
# -------------------------------------------------


def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        prog="vm_agent.py",
        description=(
            "Secure AI-assisted vulnerability "
            "management workflow."
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # -------------------------------------------------
    # PORTFOLIO DEMO
    # -------------------------------------------------

    subparsers.add_parser(
        "demo",
        help=(
            "Run the credential-free portfolio "
            "demonstration using sanitized sample "
            "data and a deterministic local analyzer."
        ),
    )

    # -------------------------------------------------
    # SECURITY EVALUATION
    # -------------------------------------------------

    subparsers.add_parser(
        "security-eval",
        help=(
            "Run the complete credential-free "
            "AI security evaluation framework."
        ),
    )

    # -------------------------------------------------
    # TENABLE CSV ANALYSIS
    # -------------------------------------------------

    tenable_csv_parser = (
        subparsers.add_parser(
            "analyze-tenable-csv",
            help=(
                "Analyze a Tenable finding using "
                "file-based inputs."
            ),
        )
    )

    tenable_csv_parser.add_argument(
        "--findings",
        required=True,
        type=Path,
        help=(
            "Path to the Tenable vulnerability "
            "findings CSV."
        ),
    )

    tenable_csv_parser.add_argument(
        "--assets",
        required=True,
        type=Path,
        help=(
            "Path to the Tenable asset inventory "
            "CSV."
        ),
    )

    tenable_csv_parser.add_argument(
        "--context",
        required=True,
        type=Path,
        help=(
            "Path to the enterprise asset-context "
            "CSV."
        ),
    )

    tenable_csv_parser.add_argument(
        "--finding-id",
        required=True,
        help=(
            "Tenable finding ID to analyze."
        ),
    )

    return parser


# -------------------------------------------------
# DISPLAY PORTFOLIO DEMO NOTICE
# -------------------------------------------------


def display_demo_notice() -> None:

    print()

    print("=" * 70)

    print(
        "VM AI AGENT - PORTFOLIO DEMO"
    )

    print("=" * 70)

    print()

    print(
        "This demonstration uses synthetic, "
        "sanitized vulnerability data."
    )

    print(
        "No Tenable account or Tenable API "
        "credentials are required."
    )

    print(
        "No OpenAI API credentials are required."
    )

    print()

    print(
        "The demo analyzer is deterministic and "
        "runs locally."
    )

    print(
        "The deterministic Python risk engine "
        "remains authoritative."
    )

    print(
        "No approval or external execution occurs "
        "in this command."
    )


# -------------------------------------------------
# DISPLAY RESULT
# -------------------------------------------------


def display_analysis_result(
    result,
    *,
    title: str = (
        "VM AI AGENT - TENABLE CSV ANALYSIS"
    ),
) -> None:

    print()

    print("=" * 70)

    print(
        _safe_text(
            title
        )
    )

    print("=" * 70)

    print()

    print(
        "Workflow ID:",
        _safe_text(
            result.workflow_id
        ),
    )

    print(
        "Finding ID:",
        _safe_text(
            result.finding_id
        ),
    )

    print(
        "Asset:",
        _safe_text(
            result.asset_name
        ),
    )

    print(
        "CVE:",
        _safe_text(
            result.cve
        ),
    )

    # -------------------------------------------------
    # AUTHORITATIVE RISK
    # -------------------------------------------------

    print()

    print("=" * 70)

    print(
        "AUTHORITATIVE RISK"
    )

    print("=" * 70)

    print()

    print(
        "Score:",
        result.risk.score,
    )

    print(
        "Rating:",
        _safe_text(
            result.risk.rating
        ),
    )

    print(
        "SLA:",
        result.risk.sla_hours,
        "hours",
    )

    # -------------------------------------------------
    # SECURITY
    # -------------------------------------------------

    print()

    print("=" * 70)

    print(
        "SECURITY"
    )

    print("=" * 70)

    print()

    print(
        "Prompt Injection Detected:",
        result.security
        .prompt_injection_detected,
    )

    print(
        "Human Review Required:",
        result.security
        .human_review_required,
    )

    if (
        result.security
        .prompt_injection_detected
    ):

        print()

        print(
            "SECURITY WARNING:"
        )

        print(
            "Potential prompt injection was "
            "detected in vulnerability data."
        )

        print()

        print(
            "Matched Indicators:"
        )

        for match in (
            result.security
            .prompt_injection_matches
        ):

            print(
                "-",
                _safe_text(
                    match
                ),
            )

        print()

        print(
            "Authoritative risk remains controlled "
            "by deterministic policy."
        )

    # -------------------------------------------------
    # AI / ADVISORY ANALYSIS
    # -------------------------------------------------

    print()

    print("=" * 70)

    print(
        "AI / ADVISORY ANALYSIS"
    )

    print("=" * 70)

    print()

    print(
        "Executive Summary:"
    )

    print(
        _safe_text(
            result.analysis
            .executive_summary
        )
    )

    print()

    print(
        "Recommended Remediation:"
    )

    print(
        _safe_text(
            result.analysis
            .remediation
        )
    )

    print()

    print(
        "AI Confidence:",
        _safe_text(
            result.analysis
            .confidence
        ),
    )

    # -------------------------------------------------
    # PROPOSED TICKET
    # -------------------------------------------------

    print()

    print("=" * 70)

    print(
        "PROPOSED TICKET"
    )

    print("=" * 70)

    print()

    print(
        "Priority:",
        _safe_text(
            result.ticket.priority
        ),
    )

    print(
        "Risk Rating:",
        _safe_text(
            result.ticket.risk_rating
        ),
    )

    print(
        "Risk Score:",
        result.ticket.risk_score,
    )

    print(
        "SLA:",
        result.ticket.sla_hours,
        "hours",
    )

    # -------------------------------------------------
    # APPROVAL BOUNDARY
    # -------------------------------------------------

    print()

    print("=" * 70)

    print(
        "WORKFLOW STATUS"
    )

    print("=" * 70)

    print()

    print(
        "Status:",
        _safe_text(
            result.status
        ),
    )

    print()

    print(
        "No ticket has been approved or created."
    )

    print(
        "A separate authorized approval action "
        "is required before execution."
    )


# -------------------------------------------------
# DISPLAY MCP IDENTITY / SESSION SECURITY
# -------------------------------------------------


def display_mcp_identity_security_evaluation(
    result,
) -> None:

    print()

    print(
        "MCP IDENTITY / SESSION ISOLATION"
    )

    print("-" * 70)

    print()

    print(
        "Total Cases:",
        result.total_cases,
    )

    print(
        "Allowed Cases:",
        result.allowed_cases,
    )

    print(
        "Blocked Cases:",
        result.blocked_cases,
    )

    print(
        "Authority Protection Cases:",
        result.authority_protection_cases,
    )

    print()

    print(
        "Passed Cases:",
        result.passed_cases,
    )

    print(
        "Failed Cases:",
        result.failed_cases,
    )

    print()

    print(
        "Unexpected Allows:",
        result.unexpected_allows,
    )

    print(
        "Unexpected Blocks:",
        result.unexpected_blocks,
    )

    print()

    if result.passed:

        print(
            "MCP Identity / Session "
            "Isolation Result: PASS"
        )

    else:

        print(
            "MCP Identity / Session "
            "Isolation Result: FAIL"
        )


# -------------------------------------------------
# DISPLAY ENTERPRISE IDENTITY AUTHORITY
# -------------------------------------------------


def display_enterprise_identity_security_evaluation(
    result,
) -> None:

    print()

    print(
        "ENTERPRISE IDENTITY AUTHORITY"
    )

    print("-" * 70)

    print()

    print(
        "Total Cases:",
        result.total_cases,
    )

    print(
        "Allowed Cases:",
        result.allowed_cases,
    )

    print(
        "Blocked Cases:",
        result.blocked_cases,
    )

    print(
        "Authority Protection Cases:",
        result.authority_protection_cases,
    )

    print()

    print(
        "Passed Cases:",
        result.passed_cases,
    )

    print(
        "Failed Cases:",
        result.failed_cases,
    )

    print()

    print(
        "Unexpected Allows:",
        result.unexpected_allows,
    )

    print(
        "Unexpected Blocks:",
        result.unexpected_blocks,
    )

    print(
        "Authority Failures:",
        result.authority_failures,
    )

    print(
        "Execution Errors:",
        result.execution_errors,
    )

    print()

    print(
        "Enterprise Identity Authority "
        "Result: "
        + (
            "PASS"
            if result.passed
            else "FAIL"
        )
    )


# -------------------------------------------------
# IDENTITY-AWARE RAG SECURITY DISPLAY
# -------------------------------------------------


def display_identity_aware_rag_security_evaluation(
    result,
) -> None:

    print(
        "\nIDENTITY-AWARE RAG AUTHORIZATION"
    )

    print(
        "-" * 70
    )

    print(
        f"Total Cases: {result.total_cases}"
    )

    print(
        f"Authorized Cases: "
        f"{result.authorized_cases}"
    )

    print(
        f"Blocked Cases: {result.blocked_cases}"
    )

    print(
        f"Cross-Tenant Cases: "
        f"{result.cross_tenant_cases}"
    )

    print(
        f"Cross-User ACL Cases: "
        f"{result.cross_user_acl_cases}"
    )

    print(
        f"Classification Cases: "
        f"{result.classification_cases}"
    )

    print(
        f"Fail-Closed Cases: "
        f"{result.fail_closed_cases}"
    )

    print(
        f"Backend Injection Cases: "
        f"{result.backend_injection_cases}"
    )

    print(
        f"Passed Cases: {result.passed_cases}"
    )

    print(
        f"Failed Cases: {result.failed_cases}"
    )

    print(
        f"Unauthorized Exposures: "
        f"{result.unauthorized_exposures}"
    )

    print(
        f"Pre-Search Boundary Failures: "
        f"{result.pre_search_boundary_failures}"
    )

    print(
        f"Audit Failures: "
        f"{result.audit_failures}"
    )

    print(
        "Identity-Aware RAG Authorization "
        "Result: "
        + (
            "PASS"
            if result.passed
            else "FAIL"
        )
    )

# -------------------------------------------------
# DISPLAY WORKFLOW EXECUTION AUTHORITY
# -------------------------------------------------


def display_workflow_authority_security_evaluation(
    result,
) -> None:

    print()

    print(
        "WORKFLOW EXECUTION AUTHORITY"
    )

    print(
        "-" * 70
    )

    print()

    print(
        "Total Cases:",
        result.total_cases,
    )

    print(
        "Authority Protection Cases:",
        result.authority_protection_cases,
    )

    print(
        "State Transition / Recovery Cases:",
        result.transition_cases,
    )

    print()

    print(
        "Passed Cases:",
        result.passed_cases,
    )

    print(
        "Failed Cases:",
        result.failed_cases,
    )

    print(
        "Authority Failures:",
        result.authority_failures,
    )

    print(
        "Execution Errors:",
        result.execution_errors,
    )

    print()

    if result.passed:

        print(
            "Workflow Execution Authority "
            "Result: PASS"
        )

    else:

        print(
            "Workflow Execution Authority "
            "Result: FAIL"
        )





# -------------------------------------------------
# DISPLAY SECURITY EVALUATION
# -------------------------------------------------


def display_security_evaluation(
    prompt_result,
    rag_result,
    tool_result,
    authorization_result,
    leakage_result,
    agency_result,
    mcp_identity_result,
    attack_results,
    identity_rag_result=None,
    enterprise_identity_result=None,
    workflow_authority_result=None,
) -> None:

    print()

    print("=" * 70)

    print(
        "VM AI AGENT - SECURITY EVALUATION"
    )

    print("=" * 70)

    # -------------------------------------------------
    # PROMPT-INJECTION DETECTION
    # -------------------------------------------------

    print()

    print(
        "PROMPT-INJECTION DETECTION"
    )

    print("-" * 70)

    print()

    print(
        "Total Cases:",
        prompt_result.total_cases,
    )

    print(
        "Adversarial Cases:",
        prompt_result.adversarial_cases,
    )

    print(
        "Benign Cases:",
        prompt_result.benign_cases,
    )

    print()

    print(
        "Passed Cases:",
        prompt_result.passed_cases,
    )

    print(
        "Failed Cases:",
        prompt_result.failed_cases,
    )

    print()

    print(
        "False Negatives:",
        prompt_result.false_negatives,
    )

    print(
        "False Positives:",
        prompt_result.false_positives,
    )

    print(
        "Category Mismatches:",
        prompt_result.category_mismatches,
    )

    print()

    if prompt_result.passed:

        print(
            "Prompt-Injection Result: PASS"
        )

    else:

        print(
            "Prompt-Injection Result: FAIL"
        )

    # -------------------------------------------------
    # RAG QUARANTINE ENFORCEMENT
    # -------------------------------------------------

    print()

    print(
        "RAG QUARANTINE ENFORCEMENT"
    )

    print("-" * 70)

    print()

    print(
        "Total Cases:",
        rag_result.total_cases,
    )

    print(
        "Malicious Cases:",
        rag_result.malicious_cases,
    )

    print(
        "Benign Cases:",
        rag_result.benign_cases,
    )

    print()

    print(
        "Passed Cases:",
        rag_result.passed_cases,
    )

    print(
        "Failed Cases:",
        rag_result.failed_cases,
    )

    print()

    print(
        "Missed Quarantines:",
        rag_result.missed_quarantines,
    )

    print(
        "False Quarantines:",
        rag_result.false_quarantines,
    )

    print(
        "Category Mismatches:",
        rag_result.category_mismatches,
    )

    print()

    if rag_result.passed:

        print(
            "RAG Quarantine Result: PASS"
        )

    else:

        print(
            "RAG Quarantine Result: FAIL"
        )

    # -------------------------------------------------
    # TOOL SECURITY
    # -------------------------------------------------

    print()

    print(
        "TOOL SECURITY"
    )

    print("-" * 70)

    print()

    print(
        "Total Cases:",
        tool_result.total_cases,
    )

    print(
        "Allowed Cases:",
        tool_result.allowed_cases,
    )

    print(
        "Blocked Cases:",
        tool_result.blocked_cases,
    )

    print()

    print(
        "Passed Cases:",
        tool_result.passed_cases,
    )

    print(
        "Failed Cases:",
        tool_result.failed_cases,
    )

    print()

    print(
        "Unexpected Allows:",
        tool_result.unexpected_allows,
    )

    print(
        "Unexpected Blocks:",
        tool_result.unexpected_blocks,
    )

    print(
        "Error Mismatches:",
        tool_result.error_mismatches,
    )

    print()

    if tool_result.passed:

        print(
            "Tool Security Result: PASS"
        )

    else:

        print(
            "Tool Security Result: FAIL"
        )

    # -------------------------------------------------
    # AUTHORIZATION SECURITY
    # -------------------------------------------------

    print()

    print(
        "AUTHORIZATION SECURITY"
    )

    print("-" * 70)

    print()

    print(
        "Total Cases:",
        authorization_result.total_cases,
    )

    print(
        "Allowed Cases:",
        authorization_result.allowed_cases,
    )

    print(
        "Blocked Cases:",
        authorization_result.blocked_cases,
    )

    print()

    print(
        "Passed Cases:",
        authorization_result.passed_cases,
    )

    print(
        "Failed Cases:",
        authorization_result.failed_cases,
    )

    print()

    print(
        "Unexpected Allows:",
        authorization_result.unexpected_allows,
    )

    print(
        "Unexpected Blocks:",
        authorization_result.unexpected_blocks,
    )

    print(
        "Status Mismatches:",
        authorization_result.status_mismatches,
    )

    print(
        "Role Mismatches:",
        authorization_result.role_mismatches,
    )

    print(
        "Exception Mismatches:",
        authorization_result.exception_mismatches,
    )

    print()

    if authorization_result.passed:

        print(
            "Authorization Security Result: PASS"
        )

    else:

        print(
            "Authorization Security Result: FAIL"
        )

    # -------------------------------------------------
    # DATA LEAKAGE SECURITY
    # -------------------------------------------------

    print()

    print(
        "DATA LEAKAGE SECURITY"
    )

    print("-" * 70)

    print()

    print(
        "Total Cases:",
        leakage_result.total_cases,
    )

    print(
        "Passed Cases:",
        leakage_result.passed_cases,
    )

    print(
        "Failed Cases:",
        leakage_result.failed_cases,
    )

    print()

    print(
        "Unexpected Exposures:",
        leakage_result.unexpected_exposures,
    )

    print(
        "Result Mismatches:",
        leakage_result.result_mismatches,
    )

    print(
        "Access Mismatches:",
        leakage_result.access_mismatches,
    )

    print(
        "Error Mismatches:",
        leakage_result.error_mismatches,
    )

    print()

    if leakage_result.passed:

        print(
            "Data Leakage Security Result: PASS"
        )

    else:

        print(
            "Data Leakage Security Result: FAIL"
        )

    # -------------------------------------------------
    # EXCESSIVE AGENCY
    # -------------------------------------------------

    print()

    print(
        "EXCESSIVE AGENCY"
    )

    print("-" * 70)

    print()

    print(
        "Total Cases:",
        agency_result.total_cases,
    )

    print(
        "Permitted Cases:",
        agency_result.permitted_cases,
    )

    print(
        "Blocked Cases:",
        agency_result.blocked_cases,
    )

    print()

    print(
        "Passed Cases:",
        agency_result.passed_cases,
    )

    print(
        "Failed Cases:",
        agency_result.failed_cases,
    )

    print()

    print(
        "Unexpected Allows:",
        agency_result.unexpected_allows,
    )

    print(
        "Unexpected Blocks:",
        agency_result.unexpected_blocks,
    )

    print(
        "Error Mismatches:",
        agency_result.error_mismatches,
    )

    print(
        "Message Mismatches:",
        agency_result.message_mismatches,
    )

    print(
        "Scope Mismatches:",
        agency_result.scope_mismatches,
    )

    print()

    if agency_result.passed:

        print(
            "Excessive Agency Result: PASS"
        )

    else:

        print(
            "Excessive Agency Result: FAIL"
        )

    # -------------------------------------------------
    # MCP IDENTITY / SESSION ISOLATION
    # -------------------------------------------------

    display_mcp_identity_security_evaluation(
        mcp_identity_result
    )

    if enterprise_identity_result is not None:

        display_enterprise_identity_security_evaluation(
            enterprise_identity_result
        )

    if identity_rag_result is not None:

        display_identity_aware_rag_security_evaluation(
            identity_rag_result
        )

    # -------------------------------------------------
    # -------------------------------------------------
    # WORKFLOW EXECUTION AUTHORITY
    # -------------------------------------------------

    if workflow_authority_result is not None:

        display_workflow_authority_security_evaluation(
            workflow_authority_result
        )

    # STANDARDIZED ATTACK HARNESS
    # -------------------------------------------------

    print()

    print(
        "STANDARDIZED ATTACK HARNESS"
    )

    print("-" * 70)

    print()

    print(
        f"{'Attack':<38}"
        f"{'Severity':<12}"
        f"{'Result':<10}"
    )

    print(
        "-" * 70
    )

    for result in attack_results:

        status = (
            "PASS"
            if result.passed
            else "FAIL"
        )

        print(
            f"{_safe_text(result.attack_name):<38}"
            f"{_safe_text(result.severity).upper():<12}"
            f"{status:<10}"
        )

    attack_total = len(
        attack_results
    )

    attack_passed = sum(
        1
        for result in attack_results
        if result.passed
    )

    attack_failed = (
        attack_total
        - attack_passed
    )

    attack_score = (
        calculate_security_score(
            attack_results
        )
    )

    print(
        "-" * 70
    )

    print(
        f"Passed: {attack_passed}"
    )

    print(
        f"Failed: {attack_failed}"
    )

    print(
        f"Total:  {attack_total}"
    )

    print(
        f"Security Score: "
        f"{attack_score:.1f}%"
    )

    # -------------------------------------------------
    # FAILED ATTACK DETAILS
    # -------------------------------------------------

    failed_attacks = [
        result
        for result in attack_results
        if not result.passed
    ]

    if failed_attacks:

        print()

        print(
            "FAILED ATTACK DETAILS"
        )

        print("-" * 70)

        for result in failed_attacks:

            print()

            print(
                _safe_text(
                    result.attack_name
                )
            )

            print(
                "Observed:",
                _safe_text(
                    result.observed_behavior
                ),
            )

    # -------------------------------------------------
    # OVERALL RESULT
    # -------------------------------------------------

    attack_harness_passed = (
        bool(
            attack_results
        )
        and all(
            result.passed
            for result in attack_results
        )
    )

    overall_passed = (
        prompt_result.passed
        and rag_result.passed
        and tool_result.passed
        and authorization_result.passed
        and leakage_result.passed
        and agency_result.passed
        and mcp_identity_result.passed
        and (
            enterprise_identity_result
            is None
            or enterprise_identity_result.passed
        )
        and (
            identity_rag_result is None
            or identity_rag_result.passed
        )
        and (
            workflow_authority_result is None
            or workflow_authority_result.passed
        )
        and attack_harness_passed
    )

    print()

    print("=" * 70)

    if overall_passed:

        print(
            "OVERALL SECURITY EVALUATION: PASS"
        )

    else:

        print(
            "OVERALL SECURITY EVALUATION: FAIL"
        )

    print("=" * 70)

    print()

    print(
        "This evaluation performs "
        "no approval, ticket creation, "
        "or external execution."
    )


# -------------------------------------------------
# PORTFOLIO DEMO
# -------------------------------------------------


def run_demo() -> int:

    """
    Run the fully reproducible credential-free
    portfolio demonstration.

    The demonstration uses:

    - sanitized sample Tenable vulnerability CSV
    - sanitized sample Tenable asset CSV
    - sanitized enterprise asset-context CSV
    - deterministic local advisory analyzer

    It deliberately does not:

    - use Tenable API credentials
    - call the Tenable cloud API
    - call OpenAI
    - approve the workflow
    - create a ticket
    - execute remediation
    """

    display_demo_notice()

    provider = (
        TenableCsvProvider
        .from_files(
            vulnerability_csv_path=
                DEMO_FINDINGS_PATH,

            asset_csv_path=
                DEMO_ASSETS_PATH,

            asset_context_csv_path=
                DEMO_CONTEXT_PATH,
        )
    )

    result = prepare_workflow(
        provider=provider,
        finding_id=DEMO_FINDING_ID,
        analyzer=
            analyze_demo_vulnerability,
    )

    display_analysis_result(
        result,
        title=(
            "VM AI AGENT - DEMO RESULT"
        ),
    )

    return 0


# -------------------------------------------------
# SECURITY EVALUATION
# -------------------------------------------------


def run_security_eval() -> int:

    """
    Run the complete local adversarial security
    evaluation framework.

    This command:

    - evaluates prompt-injection detection
    - evaluates RAG quarantine enforcement
    - evaluates LLM tool authorization and dispatch
    - evaluates authentication and authorization boundaries
    - evaluates sensitive-data leakage controls
    - evaluates excessive-agency controls
    - evaluates MCP identity and session isolation
    - evaluates enterprise identity authority boundaries
    - evaluates workflow execution authority and recovery
    - runs the standardized attack harness
    - reports false negatives
    - reports false positives
    - reports missed quarantines
    - reports false quarantines
    - reports category mismatches
    - reports attack pass/fail status
    - calculates a standardized security score
    - requires no external credentials
    - performs no approval or ticket execution
    """

    prompt_result = (
        run_security_evaluation()
    )

    rag_result = (
        run_rag_security_evaluation()
    )

    tool_result = (
        run_tool_security_evaluation()
    )

    authorization_result = (
        run_authorization_security_evaluation()
    )

    leakage_result = (
        run_data_leakage_security_evaluation()
    )

    agency_result = (
        run_excessive_agency_security_evaluation()
    )

    mcp_identity_result = (
        run_mcp_identity_security_evaluation()
    )

    enterprise_identity_result = (
        run_enterprise_identity_security_evaluation()
    )

    identity_rag_result = (
        run_identity_aware_rag_security_evaluation()
    )

    workflow_authority_result = (
        run_workflow_authority_security_evaluation()
    )

    attack_results = (
        run_security_evaluations()
    )

    display_security_evaluation(
        prompt_result,
        rag_result,
        tool_result,
        authorization_result,
        leakage_result,
        agency_result,
        mcp_identity_result,
        attack_results,
        identity_rag_result=
            identity_rag_result,
        enterprise_identity_result=
            enterprise_identity_result,
        workflow_authority_result=
            workflow_authority_result,
    )

    attack_harness_passed = (
        bool(
            attack_results
        )
        and all(
            result.passed
            for result in attack_results
        )
    )

    if (
        prompt_result.passed
        and rag_result.passed
        and tool_result.passed
        and authorization_result.passed
        and leakage_result.passed
        and agency_result.passed
        and mcp_identity_result.passed
        and enterprise_identity_result.passed
        and identity_rag_result.passed
        and workflow_authority_result.passed
        and attack_harness_passed
    ):

        return 0

    return 1


# -------------------------------------------------
# TENABLE CSV ANALYSIS
# -------------------------------------------------


def run_tenable_csv_analysis(
    args: argparse.Namespace,
) -> int:

    finding_id = (
        args.finding_id
        .strip()
    )

    if not finding_id:

        raise VmAgentCliError(
            "finding_id cannot be blank"
        )

    provider = (
        TenableCsvProvider
        .from_files(
            vulnerability_csv_path=
                args.findings,

            asset_csv_path=
                args.assets,

            asset_context_csv_path=
                args.context,
        )
    )

    result = prepare_workflow(
        provider=provider,
        finding_id=finding_id,
    )

    display_analysis_result(
        result
    )

    return 0


# -------------------------------------------------
# SAFE ENTRY POINT
# -------------------------------------------------


def main(
    argv: list[str] | None = None,
) -> int:

    parser = build_parser()

    args = parser.parse_args(
        argv
    )

    try:

        if (
            args.command
            == "demo"
        ):

            return run_demo()

        if (
            args.command
            == "security-eval"
        ):

            return run_security_eval()

        if (
            args.command
            == "analyze-tenable-csv"
        ):

            return (
                run_tenable_csv_analysis(
                    args
                )
            )

        print(
            "VM AGENT FAILED"
        )

        print(
            "Unsupported command."
        )

        return 2

    except KeyError:

        # Do not print the underlying KeyError.
        #
        # Provider errors may include externally
        # controlled identifiers.

        print(
            "VM AGENT ANALYSIS FAILED"
        )

        print(
            "The requested vulnerability finding "
            "was not found."
        )

        return 3

    except (
        CsvImportError,
        AssetContextCsvError,
        TenableCsvImportError,
        ValidationError,
        VmAgentCliError,
        ValueError,
    ):

        # Deliberately avoid printing the underlying
        # exception. CSV values are untrusted and
        # should not be reflected into the terminal.

        print(
            "VM AGENT ANALYSIS FAILED"
        )

        print(
            "The vulnerability input data failed "
            "security validation."
        )

        print(
            "Review the input files and try again."
        )

        return 2

    except Exception:

        # Unexpected exceptions may contain API
        # details, secrets, file contents, or other
        # internal implementation information.

        print(
            "VM AGENT ANALYSIS FAILED"
        )

        print(
            "An unexpected error occurred."
        )

        print(
            "No ticket was approved or created."
        )

        return 4


# -------------------------------------------------
# COMMAND-LINE ENTRY POINT
# -------------------------------------------------


if __name__ == "__main__":

    raise SystemExit(
        main()
    )
