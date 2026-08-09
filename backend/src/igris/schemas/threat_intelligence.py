"""Normalized Phase 5 threat-intelligence schemas."""

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class CapabilityCategory(StrEnum):
    """Normalized capability taxonomy."""

    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class AssessmentLabel(StrEnum):
    """Distinguish fact from inference."""

    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    POSSIBLE = "POSSIBLE"


class IntelligenceStatus(StrEnum):
    """Threat assessment lifecycle status."""

    COMPLETED = "completed"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class Capability(BaseModel):
    """Evidence-supported capability hypothesis."""

    model_config = ConfigDict(extra="forbid")

    capability_id: str
    category: CapabilityCategory
    label: AssessmentLabel
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: list[str]
    source_engines: list[str]
    explanation: str


class Technique(BaseModel):
    """ATT&CK technique mapping."""

    model_config = ConfigDict(extra="forbid")

    technique_id: str
    technique_name: str
    tactic: CapabilityCategory
    evidence_ids: list[str]
    confidence: float = Field(ge=0.0, le=1.0)
    source_engine: str
    explanation: str
    mapping_version: str


class EvidenceMapping(BaseModel):
    """Relationship between evidence, capability, and technique."""

    model_config = ConfigDict(extra="forbid")

    mapping_id: str
    observation_ids: list[str]
    indicator_ids: list[str]
    capability_id: str
    technique_id: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str


class BehaviorHypothesis(BaseModel):
    """Higher-level behavior statement with evidence/inference label."""

    model_config = ConfigDict(extra="forbid")

    hypothesis_id: str
    label: AssessmentLabel
    statement: str
    confidence: float = Field(ge=0.0, le=1.0)
    supporting_capability_ids: list[str]
    supporting_technique_ids: list[str]


class EvidenceGraphNode(BaseModel):
    """Node in the evidence relationship graph."""

    model_config = ConfigDict(extra="forbid")

    node_id: str
    node_type: str
    label: str
    details: dict[str, str | float | int | list[str]] = Field(default_factory=dict)


class EvidenceGraphEdge(BaseModel):
    """Directed relationship in the evidence graph."""

    model_config = ConfigDict(extra="forbid")

    source: str
    target: str
    relationship: str
    confidence: float = Field(ge=0.0, le=1.0)


class EvidenceGraph(BaseModel):
    """Observation to technique graph."""

    model_config = ConfigDict(extra="forbid")

    nodes: list[EvidenceGraphNode]
    edges: list[EvidenceGraphEdge]


class AttributionInterface(BaseModel):
    """Placeholder for future attribution hypotheses."""

    model_config = ConfigDict(extra="forbid")

    family_hypotheses: list[str] = Field(default_factory=list)
    similarity_references: list[str] = Field(default_factory=list)
    attribution_confidence: float | None = None
    limitation: str = (
        "Phase 5 does not perform actor attribution. Future similarity is not attribution."
    )


class ThreatAssessment(BaseModel):
    """Phase 5 threat-intelligence assessment."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    status: IntelligenceStatus
    engine_version: str
    attack_mapping_version: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    capabilities: list[Capability]
    techniques: list[Technique]
    evidence_mappings: list[EvidenceMapping]
    behavior_hypotheses: list[BehaviorHypothesis]
    evidence_graph: EvidenceGraph
    narrative: str
    attribution: AttributionInterface = Field(default_factory=AttributionInterface)
    limitations: list[str] = Field(default_factory=list)


class ThreatAssessmentResponse(BaseModel):
    """API response for full threat assessment."""

    model_config = ConfigDict(extra="forbid")

    threat_assessment: ThreatAssessment


class CapabilitiesResponse(BaseModel):
    """Capabilities endpoint response."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    capabilities: list[Capability]


class TechniquesResponse(BaseModel):
    """ATT&CK mappings endpoint response."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    techniques: list[Technique]


class EvidenceRelationshipsResponse(BaseModel):
    """Evidence graph endpoint response."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    evidence_graph: EvidenceGraph


class NarrativeResponse(BaseModel):
    """Narrative endpoint response."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    narrative: str
