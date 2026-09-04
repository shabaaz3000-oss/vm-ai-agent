import json
from dataclasses import dataclass
from pathlib import Path

from app.input_security import detect_prompt_injection
from app.models import RetrievedEvidence
from app.rag_security import secure_retrieved_evidence


# -------------------------------------------------
# PROJECT PATHS
# -------------------------------------------------


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)


EVAL_CORPUS_PATH = (
    PROJECT_ROOT
    / "evals"
    / "adversarial_cases.json"
)


RAG_EVAL_CORPUS_PATH = (
    PROJECT_ROOT
    / "evals"
    / "rag_security_cases.json"
)


# -------------------------------------------------
# PROMPT-INJECTION EVALUATION RESULT
# -------------------------------------------------


@dataclass(frozen=True)
class SecurityEvaluationResult:

    total_cases: int

    adversarial_cases: int
    benign_cases: int

    passed_cases: int
    failed_cases: int

    false_negatives: int
    false_positives: int
    category_mismatches: int

    passed: bool


# -------------------------------------------------
# RAG SECURITY EVALUATION RESULT
# -------------------------------------------------


@dataclass(frozen=True)
class RAGSecurityEvaluationResult:

    total_cases: int

    malicious_cases: int
    benign_cases: int

    passed_cases: int
    failed_cases: int

    missed_quarantines: int
    false_quarantines: int
    category_mismatches: int

    passed: bool


# -------------------------------------------------
# PROMPT-INJECTION CORPUS LOADING
# -------------------------------------------------


def load_security_evaluation_cases(
    path: Path = EVAL_CORPUS_PATH,
) -> list[dict]:

    raw_data = path.read_text(
        encoding="utf-8"
    )

    cases = json.loads(
        raw_data
    )

    if not isinstance(
        cases,
        list
    ):

        raise ValueError(
            "Security evaluation corpus "
            "must contain a JSON list."
        )

    return cases


# -------------------------------------------------
# PROMPT-INJECTION SECURITY EVALUATION
# -------------------------------------------------


def run_security_evaluation(
    path: Path = EVAL_CORPUS_PATH,
) -> SecurityEvaluationResult:

    cases = (
        load_security_evaluation_cases(
            path
        )
    )

    total_cases = len(
        cases
    )

    adversarial_cases = 0
    benign_cases = 0

    passed_cases = 0
    failed_cases = 0

    false_negatives = 0
    false_positives = 0
    category_mismatches = 0

    for case in cases:

        payload = case[
            "payload"
        ]

        expected_detection = case[
            "expected_detection"
        ]

        expected_category = case[
            "category"
        ]

        if not isinstance(
            payload,
            str
        ):

            raise ValueError(
                "Security evaluation payload "
                "must be a string."
            )

        if not isinstance(
            expected_detection,
            bool
        ):

            raise ValueError(
                "expected_detection must "
                "be a boolean."
            )

        matches = (
            detect_prompt_injection(
                payload
            )
        )

        detected = bool(
            matches
        )

        case_passed = False

        # -------------------------------------------------
        # ADVERSARIAL CASE
        # -------------------------------------------------

        if expected_detection:

            adversarial_cases += 1

            if not detected:

                false_negatives += 1

            elif (
                expected_category
                not in matches
            ):

                category_mismatches += 1

            else:

                case_passed = True

        # -------------------------------------------------
        # BENIGN CASE
        # -------------------------------------------------

        else:

            benign_cases += 1

            if detected:

                false_positives += 1

            else:

                case_passed = True

        # -------------------------------------------------
        # CASE RESULT
        # -------------------------------------------------

        if case_passed:

            passed_cases += 1

        else:

            failed_cases += 1

    passed = (
        failed_cases == 0
    )

    return SecurityEvaluationResult(
        total_cases=
            total_cases,

        adversarial_cases=
            adversarial_cases,

        benign_cases=
            benign_cases,

        passed_cases=
            passed_cases,

        failed_cases=
            failed_cases,

        false_negatives=
            false_negatives,

        false_positives=
            false_positives,

        category_mismatches=
            category_mismatches,

        passed=
            passed,
    )


# -------------------------------------------------
# RAG SECURITY CORPUS LOADING
# -------------------------------------------------


def load_rag_security_evaluation_cases(
    path: Path = RAG_EVAL_CORPUS_PATH,
) -> list[dict]:

    raw_data = path.read_text(
        encoding="utf-8"
    )

    cases = json.loads(
        raw_data
    )

    if not isinstance(
        cases,
        list
    ):

        raise ValueError(
            "RAG security evaluation corpus "
            "must contain a JSON list."
        )

    return cases


# -------------------------------------------------
# RAG SECURITY EVALUATION
# -------------------------------------------------


def run_rag_security_evaluation(
    path: Path = RAG_EVAL_CORPUS_PATH,
) -> RAGSecurityEvaluationResult:

    cases = (
        load_rag_security_evaluation_cases(
            path
        )
    )

    total_cases = len(
        cases
    )

    malicious_cases = 0
    benign_cases = 0

    passed_cases = 0
    failed_cases = 0

    missed_quarantines = 0
    false_quarantines = 0
    category_mismatches = 0

    for case in cases:

        payload = case[
            "payload"
        ]

        expected_quarantine = case[
            "expected_quarantine"
        ]

        expected_categories = case[
            "expected_categories"
        ]

        # -------------------------------------------------
        # VALIDATE EVALUATION CASE
        # -------------------------------------------------

        if not isinstance(
            payload,
            str
        ):

            raise ValueError(
                "RAG security evaluation payload "
                "must be a string."
            )

        if not isinstance(
            expected_quarantine,
            bool
        ):

            raise ValueError(
                "expected_quarantine must "
                "be a boolean."
            )

        if not isinstance(
            expected_categories,
            list
        ):

            raise ValueError(
                "expected_categories must "
                "be a list."
            )

        # -------------------------------------------------
        # BUILD SYNTHETIC RETRIEVED EVIDENCE
        # -------------------------------------------------

        evidence = RetrievedEvidence(
            source_id=
                case["id"].lower(),

            source_name=
                f"{case['id'].lower()}.md",

            chunk_id=
                f"{case['id'].lower()}:0:evaluation",

            chunk_number=
                0,

            content=
                payload,

            # Deliberately high semantic relevance.
            #
            # The security control must still win
            # over retrieval relevance.
            similarity=
                0.99,

            source_sha256=
                "a" * 64,

            trust_tier=
                "trusted_reference",

            access_level=
                "standard",
        )

        # -------------------------------------------------
        # APPLY REAL RAG SECURITY CONTROL
        # -------------------------------------------------

        result = (
            secure_retrieved_evidence(
                [
                    evidence
                ]
            )
        )

        quarantined = (
            evidence.chunk_id
            in result.quarantined_chunk_ids
        )

        case_passed = False

        # -------------------------------------------------
        # MALICIOUS RAG CASE
        # -------------------------------------------------

        if expected_quarantine:

            malicious_cases += 1

            # Malicious evidence escaped quarantine.
            if not quarantined:

                missed_quarantines += 1

            # Evidence was quarantined, but the
            # expected attack category was not
            # correctly identified.
            elif not all(
                category
                in result.categories

                for category in
                expected_categories
            ):

                category_mismatches += 1

            else:

                case_passed = True

        # -------------------------------------------------
        # BENIGN RAG CASE
        # -------------------------------------------------

        else:

            benign_cases += 1

            # Legitimate evidence was incorrectly
            # blocked by the RAG security layer.
            if quarantined:

                false_quarantines += 1

            else:

                case_passed = True

        # -------------------------------------------------
        # CASE RESULT
        # -------------------------------------------------

        if case_passed:

            passed_cases += 1

        else:

            failed_cases += 1

    passed = (
        failed_cases == 0
    )

    return RAGSecurityEvaluationResult(
        total_cases=
            total_cases,

        malicious_cases=
            malicious_cases,

        benign_cases=
            benign_cases,

        passed_cases=
            passed_cases,

        failed_cases=
            failed_cases,

        missed_quarantines=
            missed_quarantines,

        false_quarantines=
            false_quarantines,

        category_mismatches=
            category_mismatches,

        passed=
            passed,
    )