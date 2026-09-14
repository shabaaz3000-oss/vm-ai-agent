import json

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pydantic import BaseModel

from app.auth import Principal

from app import agent


# -------------------------------------------------
# PROJECT PATHS
# -------------------------------------------------


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)


EXCESSIVE_AGENCY_CORPUS_PATH = (
    PROJECT_ROOT
    / "evals"
    / "excessive_agency_security_cases.json"
)


# -------------------------------------------------
# CONTROLLED EVALUATION RISK
# -------------------------------------------------


class EvaluationRisk(BaseModel):

    score: int
    rating: str
    sla_hours: int


# -------------------------------------------------
# SYNTHETIC RESPONSES API CLIENT
# -------------------------------------------------


class EvaluationResponses:

    def __init__(
        self,
        responses,
    ):

        self.responses = list(
            responses
        )

        self.calls = []


    def create(
        self,
        **kwargs,
    ):

        self.calls.append(
            kwargs
        )

        if not self.responses:

            raise AssertionError(
                "Unexpected model call in "
                "excessive-agency evaluation."
            )

        return self.responses.pop(
            0
        )


class EvaluationClient:

    def __init__(
        self,
        responses,
    ):

        self.responses = (
            EvaluationResponses(
                responses
            )
        )


# -------------------------------------------------
# CASE RESULT
# -------------------------------------------------


@dataclass(frozen=True)
class ExcessiveAgencyCaseResult:

    case_id: str

    expected_blocked: bool
    observed_blocked: bool

    expected_error: str | None
    observed_error: str | None

    expected_tool_names: list[str] | None
    observed_tool_names: list[str] | None

    message_matched: bool

    passed: bool


# -------------------------------------------------
# AGGREGATE RESULT
# -------------------------------------------------


@dataclass(frozen=True)
class ExcessiveAgencySecurityEvaluationResult:

    total_cases: int

    permitted_cases: int
    blocked_cases: int

    passed_cases: int
    failed_cases: int

    unexpected_allows: int
    unexpected_blocks: int

    error_mismatches: int
    message_mismatches: int
    scope_mismatches: int

    passed: bool


# -------------------------------------------------
# LOAD CORPUS
# -------------------------------------------------


def load_excessive_agency_security_cases(
    path: Path =
        EXCESSIVE_AGENCY_CORPUS_PATH,
) -> list[dict]:

    cases = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

    if not isinstance(
        cases,
        list,
    ):

        raise ValueError(
            "Excessive agency security corpus "
            "must contain a JSON list."
        )

    return cases


# -------------------------------------------------
# BUILD MODEL RESPONSE
# -------------------------------------------------


def _build_model_response(
    response_spec: dict,
):

    response_type = (
        response_spec["type"]
    )

    if response_type == "final":

        return SimpleNamespace(
            output=[],
            output_text=
                response_spec["text"],
        )

    if response_type == "function_call":

        call = SimpleNamespace(
            type="function_call",
            name=
                response_spec["name"],
            call_id=
                response_spec["call_id"],
            arguments=
                response_spec["arguments"],
        )

        return SimpleNamespace(
            output=[
                call
            ],
            output_text="",
        )

    if response_type == "function_calls":

        calls = [
            SimpleNamespace(
                type="function_call",
                name=
                    call_spec["name"],
                call_id=
                    call_spec["call_id"],
                arguments=
                    call_spec["arguments"],
            )
            for call_spec
            in response_spec["calls"]
        ]

        return SimpleNamespace(
            output=
                calls,

            output_text="",
        )

    raise ValueError(
        "Unsupported excessive-agency "
        "response type."
    )


# -------------------------------------------------
# BUILD RESPONSE SEQUENCE
# -------------------------------------------------


def _build_response_sequence(
    case: dict,
):

    return [
        _build_model_response(
            response_spec
        )
        for response_spec
        in case["responses"]
    ]


# -------------------------------------------------
# CONTROLLED TOOL DISPATCH
# -------------------------------------------------


def _evaluation_dispatch(
    tool_name,
    context,
):

    if tool_name == "get_finding":

        return {
            "finding":
                "controlled-evaluation-finding"
        }

    if tool_name == "get_asset_details":

        return {
            "asset":
                "controlled-evaluation-asset"
        }

    if tool_name == "get_threat_intel":

        return {
            "threat":
                "controlled-evaluation-threat"
        }

    if tool_name == "search_knowledge":

        return []

    raise AssertionError(
        "Unexpected tool reached evaluation "
        f"dispatcher: {tool_name}"
    )


# -------------------------------------------------
# RUN CONTROLLED AGENT CASE
# -------------------------------------------------


def _run_agent_case(
    case: dict,
) -> None:

    client = EvaluationClient(
        _build_response_sequence(
            case
        )
    )

    principal = Principal(
        username=
            "excessive-agency-eval-user",

        role=
            "ANALYST",
    )

    risk = EvaluationRisk(
        score=
            100,

        rating=
            "CRITICAL",

        sla_hours=
            24,
    )

    with patch.object(
        agent,
        "dispatch_llm_tool",
        side_effect=
            _evaluation_dispatch,
    ), patch.object(
        agent,
        "validate_provider_relationships",
        return_value=None,
    ), patch.object(
        agent,
        "calculate_risk",
        return_value=
            risk,
    ), patch.object(
        agent,
        "log_event",
        return_value=None,
    ), patch.object(
        agent.KnowledgeRetriever,
        "from_trusted_knowledge",
        return_value=
            object(),
    ):

        agent.run_agent(
            principal=
                principal,

            user_request=(
                "Investigate the current "
                "vulnerability."
            ),

            openai_client=
                client,

            model=
                "evaluation-model",
        )


# -------------------------------------------------
# EVALUATE ONE CASE
# -------------------------------------------------


def evaluate_excessive_agency_case(
    case: dict,
) -> ExcessiveAgencyCaseResult:

    operation = (
        case["operation"]
    )

    valid_operations = {
        "inspect_tool_scope",
        "validate_arguments",
        "run_agent",
    }

    if operation not in valid_operations:

        raise ValueError(
            "Unsupported excessive-agency "
            "evaluation operation."
        )

    expected_blocked = (
        case["expected_blocked"]
    )

    expected_error = (
        case["expected_error"]
    )

    expected_tool_names = (
        case["expected_tool_names"]
    )

    expected_message = (
        case[
            "expected_message_contains"
        ]
    )

    observed_blocked = False
    observed_error = None
    observed_message = None
    observed_tool_names = None

    try:

        # -------------------------------------------------
        # STATE-DEPENDENT TOOL SCOPE
        # -------------------------------------------------

        if operation == "inspect_tool_scope":

            state = (
                case["state"]
            )

            finding = (
                object()
                if state[
                    "finding_present"
                ]
                else None
            )

            asset = (
                object()
                if state[
                    "asset_present"
                ]
                else None
            )

            threat = (
                object()
                if state[
                    "threat_present"
                ]
                else None
            )

            tools = agent._build_turn_tools(
                finding=
                    finding,

                asset=
                    asset,

                threat=
                    threat,

                knowledge_used=
                    state[
                        "knowledge_used"
                    ],
            )

            observed_tool_names = sorted(
                tool["name"]
                for tool in tools
            )

        # -------------------------------------------------
        # MODEL ARGUMENT CONTROL
        # -------------------------------------------------

        elif operation == "validate_arguments":

            agent._validate_empty_tool_arguments(
                case["arguments"]
            )

        # -------------------------------------------------
        # FULL AGENT CONTROL LOOP
        # -------------------------------------------------

        else:

            _run_agent_case(
                case
            )

    except Exception as error:

        observed_blocked = True

        observed_error = (
            type(error).__name__
        )

        observed_message = (
            str(error)
        )

    # -------------------------------------------------
    # COMPARE EXPECTED / OBSERVED
    # -------------------------------------------------

    blocking_matches = (
        observed_blocked
        == expected_blocked
    )

    error_matches = (
        observed_error
        == expected_error
    )

    if expected_tool_names is None:

        scope_matches = True

    else:

        scope_matches = (
            observed_tool_names
            == sorted(
                expected_tool_names
            )
        )

    if expected_message is None:

        message_matches = True

    else:

        message_matches = (
            observed_message is not None
            and expected_message.lower()
            in observed_message.lower()
        )

    passed = all(
        [
            blocking_matches,
            error_matches,
            scope_matches,
            message_matches,
        ]
    )

    return ExcessiveAgencyCaseResult(
        case_id=
            case["id"],

        expected_blocked=
            expected_blocked,

        observed_blocked=
            observed_blocked,

        expected_error=
            expected_error,

        observed_error=
            observed_error,

        expected_tool_names=
            expected_tool_names,

        observed_tool_names=
            observed_tool_names,

        message_matched=
            message_matches,

        passed=
            passed,
    )


# -------------------------------------------------
# RUN CORPUS
# -------------------------------------------------


def run_excessive_agency_security_evaluation(
    path: Path =
        EXCESSIVE_AGENCY_CORPUS_PATH,
) -> ExcessiveAgencySecurityEvaluationResult:

    cases = (
        load_excessive_agency_security_cases(
            path
        )
    )

    results = [
        evaluate_excessive_agency_case(
            case
        )
        for case in cases
    ]

    permitted_cases = sum(
        1
        for result in results
        if not result.expected_blocked
    )

    blocked_cases = sum(
        1
        for result in results
        if result.expected_blocked
    )

    passed_cases = sum(
        1
        for result in results
        if result.passed
    )

    failed_cases = (
        len(results)
        - passed_cases
    )

    unexpected_allows = sum(
        1
        for result in results
        if (
            result.expected_blocked
            and not result.observed_blocked
        )
    )

    unexpected_blocks = sum(
        1
        for result in results
        if (
            not result.expected_blocked
            and result.observed_blocked
        )
    )

    error_mismatches = sum(
        1
        for result in results
        if (
            result.observed_error
            != result.expected_error
        )
    )

    message_mismatches = sum(
        1
        for result in results
        if not result.message_matched
    )

    scope_mismatches = sum(
        1
        for result in results
        if (
            result.expected_tool_names
            is not None

            and result.observed_tool_names
            != sorted(
                result.expected_tool_names
            )
        )
    )

    return ExcessiveAgencySecurityEvaluationResult(
        total_cases=
            len(results),

        permitted_cases=
            permitted_cases,

        blocked_cases=
            blocked_cases,

        passed_cases=
            passed_cases,

        failed_cases=
            failed_cases,

        unexpected_allows=
            unexpected_allows,

        unexpected_blocks=
            unexpected_blocks,

        error_mismatches=
            error_mismatches,

        message_mismatches=
            message_mismatches,

        scope_mismatches=
            scope_mismatches,

        passed=(
            failed_cases == 0
        ),
    )