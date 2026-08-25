import re


SUSPICIOUS_PATTERNS = {
    "instruction_override": [
        r"\bignore\b.{0,40}\b(previous|prior|earlier)\b.{0,30}\binstructions?\b",
        r"\bdisregard\b.{0,40}\b(previous|prior|earlier)\b.{0,30}\binstructions?\b",
        r"\boverride\b.{0,40}\b(instructions?|rules?|policy|policies)\b",
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
    ],

    "risk_manipulation": [
        r"\bchange\b.{0,40}\brisk\b.{0,20}\brating\b",
        r"\bset\b.{0,40}\brisk\b.{0,20}\brating\b",
        r"\bdowngrade\b.{0,40}\brisk\b",
        r"\bmark\b.{0,30}\b(low|medium|safe)\b",
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


def normalize_text(text: str) -> str:

    normalized = text.lower()

    normalized = re.sub(
        r"\s+",
        " ",
        normalized
    )

    return normalized.strip()


def detect_prompt_injection(text: str) -> list[str]:

    normalized_text = normalize_text(text)

    matches = []

    for category, patterns in SUSPICIOUS_PATTERNS.items():

        for pattern in patterns:

            if re.search(
                pattern,
                normalized_text,
                flags=re.IGNORECASE
            ):

                if category not in matches:
                    matches.append(category)

                break

    return matches