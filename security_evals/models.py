from dataclasses import dataclass, field


@dataclass
class SecurityEvalResult:
    attack_name: str
    category: str
    passed: bool

    expected_behavior: str
    observed_behavior: str

    severity: str

    evidence: list[str] = field(default_factory=list)