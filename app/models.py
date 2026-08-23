from typing import Literal

from pydantic import BaseModel, Field


class VulnerabilityFinding(BaseModel):
    finding_id: str
    asset_name: str
    cve: str
    title: str
    description: str
    cvss: float = Field(ge=0, le=10)
    patch_available: bool


class AssetContext(BaseModel):
    asset_name: str
    owner: str
    application: str

    environment: Literal[
        "development",
        "test",
        "production"
    ]

    business_criticality: Literal[
        "low",
        "medium",
        "high",
        "critical"
    ]

    internet_exposed: bool
    data_classification: str
    current_controls: list[str] = Field(
        default_factory=list
    )


class ThreatIntel(BaseModel):
    cve: str
    epss: float | None = Field(
        default=None,
        ge=0,
        le=1
    )
    kev: bool
    data_source: str


class RiskResult(BaseModel):
    score: int

    rating: Literal[
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ]

    sla_hours: int
    factors: list[str]

class AIAnalysis(BaseModel):
    executive_summary: str
    rationale: list[str]
    remediation: str
    compensating_controls: list[str]
    validation_steps: list[str]

    confidence: Literal[
        "LOW",
        "MEDIUM",
        "HIGH"
    ]

    requires_human_review: bool

    ticket_summary: str
    ticket_description: str