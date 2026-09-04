from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class VulnerabilityFinding(BaseModel):
    finding_id: str
    asset_name: str
    cve: str
    title: str
    description: str

    cvss: float = Field(
        ge=0,
        le=10
    )

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


# -------------------------------------------------
# RAG KNOWLEDGE MODELS
# -------------------------------------------------


class KnowledgeDocument(BaseModel):

    source_id: str = Field(
        min_length=1,
        max_length=128
    )

    source_name: str = Field(
        min_length=1,
        max_length=255
    )

    content: str = Field(
        min_length=1,
        max_length=100_000
    )

    content_sha256: str = Field(
        pattern=r"^[a-f0-9]{64}$"
    )

    trust_tier: Literal[
        "trusted_reference"
    ] = "trusted_reference"

    access_level: Literal[
        "standard",
        "restricted"
    ] = "standard"


class KnowledgeChunk(BaseModel):

    chunk_id: str = Field(
        min_length=1,
        max_length=255
    )

    source_id: str = Field(
        min_length=1,
        max_length=128
    )

    source_name: str = Field(
        min_length=1,
        max_length=255
    )

    chunk_number: int = Field(
        ge=0
    )

    content: str = Field(
        min_length=1
    )

    source_sha256: str = Field(
        pattern=r"^[a-f0-9]{64}$"
    )

    trust_tier: Literal[
        "trusted_reference"
    ] = "trusted_reference"

    access_level: Literal[
        "standard",
        "restricted"
    ] = "standard"


class RetrievedEvidence(BaseModel):

    source_id: str = Field(
        min_length=1,
        max_length=128
    )

    source_name: str = Field(
        min_length=1,
        max_length=255
    )

    chunk_id: str = Field(
        min_length=1,
        max_length=255
    )

    chunk_number: int = Field(
        ge=0
    )

    content: str = Field(
        min_length=1
    )

    similarity: float = Field(
        ge=-1.0,
        le=1.0
    )

    source_sha256: str = Field(
        pattern=r"^[a-f0-9]{64}$"
    )

    trust_tier: Literal[
        "trusted_reference"
    ] = "trusted_reference"

    access_level: Literal[
        "standard",
        "restricted"
    ] = "standard"


# -------------------------------------------------
# AI ANALYSIS MODEL
# -------------------------------------------------


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


# -------------------------------------------------
# TICKET MODEL
# -------------------------------------------------


class TicketDraft(BaseModel):
    short_description: str

    priority: Literal[
        "P1",
        "P2",
        "P3",
        "P4"
    ]

    asset_name: str
    cve: str
    assignment_group: str

    risk_rating: Literal[
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ]

    risk_score: int
    sla_hours: int

    description: str
    remediation: str

    validation_steps: list[str]


# -------------------------------------------------
# STRUCTURED WORKFLOW RESULT MODELS
# -------------------------------------------------


class WorkflowSecurity(BaseModel):
    prompt_injection_detected: bool

    prompt_injection_matches: list[str] = Field(
        default_factory=list
    )

    human_review_required: bool


class WorkflowResult(BaseModel):
    workflow_id: str

    status: Literal[
        "AWAITING_APPROVAL",
        "PROCESSING",
        "APPROVED",
        "REJECTED",
        "TICKET_CREATED",
        "NEEDS_REVIEW",
        "FAILED"
    ]

    finding_id: str
    asset_name: str
    cve: str

    risk: RiskResult

    security: WorkflowSecurity

    analysis: AIAnalysis

    retrieved_evidence: list[
        RetrievedEvidence
    ] = Field(
        default_factory=list
    )

    ticket: TicketDraft

    approval_id: str | None = None

    ticket_id: str | None = None

    # -------------------------------------------------
    # EXECUTION / RECOVERY METADATA
    # -------------------------------------------------

    execution_attempt_id: str | None = None

    processing_started_at: datetime | None = None

    recovery_reason: str | None = None