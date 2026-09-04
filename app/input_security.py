import re

from app.models import RetrievedEvidence


# -------------------------------------------------
# SUSPICIOUS PROMPT-INJECTION PATTERNS
# -------------------------------------------------


SUSPICIOUS_PATTERNS = {
    "instruction_override": [
        r"\bignore\b.{0,40}\b(previous|prior|earlier)\b.{0,30}\binstructions?\b",
        r"\bdisregard\b.{0,40}\b(previous|prior|earlier)\b.{0,30}\binstructions?\b",
        r"\boverride\b.{0,40}\b(instructions?|rules?|policy|policies)\b",
        r"\bsystem\s+override\b",
    ],

    "authority_impersonation": [
        r"\byou are now authorized\b",
        r"\byou have been authorized\b",
        r"\bassume\b.{0,30}\bauthorization\b",
        r"\bpretend\b.{0,30}\bauthori[sz]ed\b",
    ],

    "approval_bypass": [
        r"\bbypass\b.{0,50}\bhuman\b.{0,30}\bapproval\b",
        r"\bskip\b.{0,50}\bhuman\b.{0,30}\bapproval\b",
        r"\bproceed\b.{0,50}\bwithout\b.{0,30}\bapproval\b",
        r"\bno\b.{0,20}\bhuman\b.{0,30}\bapproval\b.{0,20}\brequired\b",
        r"\bapproval\b.{0,30}\balready\b.{0,30}\b(granted|given|approved)\b",
        r"\bdo\s+not\b.{0,30}\brequire\b.{0,30}\bhuman\b.{0,30}\bapproval\b",
    ],

    "risk_manipulation": [
        r"\bchange\b.{0,40}\brisk\b.{0,20}\brating\b",
        r"\bset\b.{0,40}\brisk\b.{0,20}\brating\b",
        r"\bdowngrade\b.{0,40}\brisk\b",
        r"\bmark\b.{0,30}\b(low|medium|safe)\b",

        # Direct risk-value manipulation.
        r"\bchange\b.{0,30}\brisk\b.{0,20}\bto\b.{0,10}\b(low|medium|high|critical)\b",
        r"\bset\b.{0,30}\brisk\b.{0,20}\bto\b.{0,10}\b(low|medium|high|critical)\b",
    ],

    "sla_manipulation": [
        r"\bchange\b.{0,40}\b(remediation\s+)?sla\b",
        r"\bset\b.{0,40}\b(remediation\s+)?sla\b",
        r"\bextend\b.{0,40}\b(remediation\s+)?sla\b",
    ],

    "priority_manipulation": [
        r"\bset\b.{0,40}\bticket\b.{0,20}\bpriority\b",
        r"\bchange\b.{0,40}\bticket\b.{0,20}\bpriority\b",
        r"\bpriority\b.{0,20}\bto\b.{0,10}\bp[1-4]\b",
    ],

    "system_prompt_request": [
        r"\bsystem\s+prompt\b",
        r"\bdeveloper\s+(message|instructions?)\b",
        r"\breveal\b.{0,30}\b(hidden|system|developer)\b.{0,30}\b(instructions?|prompt)\b",
    ],
}


# -------------------------------------------------
# TEXT NORMALIZATION
# -------------------------------------------------


def normalize_text(
    text: str
) -> str:

    normalized = text.lower()

    normalized = re.sub(
        r"\s+",
        " ",
        normalized
    )

    return normalized.strip()


# -------------------------------------------------
# DETECT PROMPT INJECTION IN ONE STRING
# -------------------------------------------------


def detect_prompt_injection(
    text: str
) -> list[str]:

    normalized_text = (
        normalize_text(
            text
        )
    )

    matches = []

    for category, patterns in (
        SUSPICIOUS_PATTERNS.items()
    ):

        for pattern in patterns:

            if re.search(
                pattern,
                normalized_text,
                flags=re.IGNORECASE
            ):

                if category not in matches:

                    matches.append(
                        category
                    )

                break

    return matches


# -------------------------------------------------
# STRUCTURED UNTRUSTED-DATA INSPECTION
# -------------------------------------------------


def inspect_prompt_injection_data(
    data: object,
    path: str = "",
) -> dict[str, list[str]]:

    """
    Recursively inspect strings contained in
    untrusted structured data.

    Returns a mapping of field paths to detected
    prompt-injection categories.

    Non-string scalar values are ignored.
    """

    field_matches = {}

    if isinstance(
        data,
        str
    ):

        matches = (
            detect_prompt_injection(
                data
            )
        )

        if matches:

            field_matches[
                path or "$"
            ] = matches

        return field_matches

    if isinstance(
        data,
        dict
    ):

        for key, value in data.items():

            child_path = (
                f"{path}.{key}"
                if path
                else str(key)
            )

            field_matches.update(
                inspect_prompt_injection_data(
                    data=value,
                    path=child_path,
                )
            )

        return field_matches

    if isinstance(
        data,
        (list, tuple)
    ):

        for index, value in enumerate(
            data
        ):

            child_path = (
                f"{path}[{index}]"
                if path
                else f"[{index}]"
            )

            field_matches.update(
                inspect_prompt_injection_data(
                    data=value,
                    path=child_path,
                )
            )

        return field_matches

    return field_matches


# -------------------------------------------------
# RETRIEVED RAG EVIDENCE INSPECTION
# -------------------------------------------------


def inspect_retrieved_evidence(
    evidence: list[RetrievedEvidence],
) -> dict[str, list[str]]:

    """
    Inspect retrieved RAG chunk content for
    prompt-injection indicators.

    Only retrieved CONTENT is inspected.

    Source metadata such as source_name,
    chunk_id, trust_tier, similarity, and
    access_level is not treated as instruction
    content.

    Returns a mapping:

        chunk_id -> detected categories
    """

    chunk_matches = {}

    for item in evidence:

        matches = (
            detect_prompt_injection(
                item.content
            )
        )

        if matches:

            chunk_matches[
                item.chunk_id
            ] = matches

    return chunk_matches


# -------------------------------------------------
# AGGREGATE DETECTION CATEGORIES
# -------------------------------------------------


def aggregate_prompt_injection_matches(
    field_matches: dict[str, list[str]],
) -> list[str]:

    """
    Convert field-level or chunk-level
    prompt-injection findings into one
    de-duplicated category list.
    """

    matches = []

    for categories in (
        field_matches.values()
    ):

        for category in categories:

            if category not in matches:

                matches.append(
                    category
                )

    return matches