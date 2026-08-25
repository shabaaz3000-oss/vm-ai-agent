SUSPICIOUS_PATTERNS = [
    "ignore all previous instructions",
    "ignore previous instructions",
    "ignore your instructions",
    "disregard previous instructions",
    "disregard your instructions",
    "system prompt",
    "developer message",
    "you are now authorized",
    "bypass human approval",
    "bypass approval",
    "override security",
    "change the risk rating",
    "change risk rating",
    "change the remediation sla",
    "set the remediation sla",
    "set ticket priority",
    "claim the ticket has already been approved",
    "pretend the ticket",
]


def detect_prompt_injection(text: str) -> list[str]:

    normalized_text = text.lower()

    matches = []

    for pattern in SUSPICIOUS_PATTERNS:

        if pattern in normalized_text:
            matches.append(pattern)

    return matches