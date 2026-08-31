from __future__ import annotations

import argparse

from pathlib import Path

from pydantic import ValidationError

from app.demo_analyzer import (
    analyze_demo_vulnerability,
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
    print("VM AI AGENT - PORTFOLIO DEMO")
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
    print("AUTHORITATIVE RISK")
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
    print("SECURITY")
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
    print("AI / ADVISORY ANALYSIS")
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
    print("PROPOSED TICKET")
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
    print("WORKFLOW STATUS")
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