"""Normalized Phase 10 sample similarity analysis schemas."""

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class SimilarityHypothesis(StrEnum):
    """Explainable similarity relationship hypothesis without attribution claims."""

    POSSIBLE_RELATED_CLUSTER = "possible_related_cluster"
    UNRELATED = "unrelated"
    INSUFFICIENT_DATA = "insufficient_data"


class SimilarityConfidence(StrEnum):
    """Confidence rating based on the breadth of corroborated feature layers."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FeatureCategory(StrEnum):
    """Normalized feature dimensions used in similarity evaluation."""

    APIS = "apis"
    STRINGS = "strings"
    SECTIONS = "sections"
    FUNCTIONS = "functions"
    OPCODES = "opcodes"
    BEHAVIOR = "behavior"


class SectionFeature(BaseModel):
    """Normalized representation of a binary section."""

    model_config = ConfigDict(extra="forbid")

    name: str
    entropy: float
    size_ratio: float
    is_executable: bool = False
    is_writable: bool = False


class NormalizedSampleFeatures(BaseModel):
    """Extracted and normalized feature profile of a sample."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    sha256: str
    detected_format: str | None = None
    imported_apis: list[str] = Field(default_factory=list)
    interesting_strings: list[str] = Field(default_factory=list)
    sections: list[SectionFeature] = Field(default_factory=list)
    function_count: int = 0
    function_signatures: list[str] = Field(default_factory=list)
    opcode_distribution: dict[str, int] = Field(default_factory=dict)
    behavior_processes: list[str] = Field(default_factory=list)
    behavior_registry_keys: list[str] = Field(default_factory=list)
    behavior_network_targets: list[str] = Field(default_factory=list)
    behavior_mutexes: list[str] = Field(default_factory=list)
    has_static: bool = False
    has_reverse: bool = False
    has_behavior: bool = False
    feature_version: str = "similarity_features/v1"


class SampleSimilarityMatch(BaseModel):
    """Detailed similarity comparison between the query sample and a candidate."""

    model_config = ConfigDict(extra="forbid")

    target_sample_id: str
    target_sha256: str
    target_filename: str
    overall_similarity: float = Field(ge=0.0, le=1.0)
    file_similarity: float = Field(ge=0.0, le=1.0)
    code_similarity: float = Field(ge=0.0, le=1.0)
    behavior_similarity: float | None = Field(default=None, ge=0.0, le=1.0)
    matching_feature_categories: list[str] = Field(default_factory=list)
    shared_indicators: list[str] = Field(default_factory=list)
    differences: list[str] = Field(default_factory=list)
    hypothesis: SimilarityHypothesis
    confidence: SimilarityConfidence
    explanation: str


class SimilarityReport(BaseModel):
    """Complete Phase 10 sample similarity analysis report."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    sha256: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    schema_version: str = "similarity/v1"
    feature_version: str = "similarity_features/v1"
    scoring_version: str = "similarity_scoring/v1"
    total_candidates_evaluated: int
    matches: list[SampleSimilarityMatch] = Field(default_factory=list)
    summary: str
    limitations: list[str] = Field(default_factory=list)
    provenance: str = "similarity_engine:v1"


class SimilarityResponse(BaseModel):
    """API response envelope for running similarity analysis."""

    model_config = ConfigDict(extra="forbid")

    similarity: SimilarityReport


class SimilarityResultsResponse(BaseModel):
    """API response envelope for retrieving cached similarity results."""

    model_config = ConfigDict(extra="forbid")

    similarity: SimilarityReport
