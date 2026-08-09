"""Normalized Phase 2 static-analysis schemas."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

FEATURE_SCHEMA_VERSION = "static-feature-vector/v1"


class EvidenceSeverity(StrEnum):
    """Observation severity without implying a malware verdict."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class EvidenceType(StrEnum):
    """Static-analysis evidence types."""

    INTERESTING_STRING = "INTERESTING_STRING"
    SUSPICIOUS_KEYWORD = "SUSPICIOUS_KEYWORD"
    API_CAPABILITY = "API_CAPABILITY"
    HIGH_ENTROPY_SECTION = "HIGH_ENTROPY_SECTION"
    EXECUTABLE_WRITABLE_SECTION = "EXECUTABLE_WRITABLE_SECTION"
    UNUSUAL_SECTION_NAME = "UNUSUAL_SECTION_NAME"
    SUSPICIOUS_SIZE_RELATIONSHIP = "SUSPICIOUS_SIZE_RELATIONSHIP"
    POSSIBLE_PACKING_INDICATOR = "POSSIBLE_PACKING_INDICATOR"
    OVERLAY_PRESENT = "OVERLAY_PRESENT"
    RESOURCE_PRESENT = "RESOURCE_PRESENT"
    TLS_CALLBACK_DIRECTORY_PRESENT = "TLS_CALLBACK_DIRECTORY_PRESENT"
    SUSPICIOUS_ENTRY_POINT_SECTION = "SUSPICIOUS_ENTRY_POINT_SECTION"


class StringCategory(StrEnum):
    """String classification categories."""

    URL = "url"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    EMAIL = "email"
    WINDOWS_PATH = "windows_path"
    UNIX_PATH = "unix_path"
    REGISTRY_PATH = "registry_path"
    COMMAND_INTERPRETER = "command_interpreter"
    SUSPICIOUS_KEYWORD = "suspicious_keyword"
    GENERIC = "generic_string"


class ImportCategory(StrEnum):
    """Normalized API capability categories."""

    PROCESS_MANAGEMENT = "process_management"
    MEMORY_MANAGEMENT = "memory_management"
    FILESYSTEM = "filesystem"
    REGISTRY = "registry"
    NETWORKING = "networking"
    CRYPTOGRAPHY = "cryptography"
    SERVICE_MANAGEMENT = "service_management"
    SYSTEM_INFORMATION = "system_information"
    PROCESS_THREAD_MANIPULATION = "process_thread_manipulation"
    OTHER = "other"


class StaticAnalysisStatus(StrEnum):
    """Static-analysis lifecycle states."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ResourceHashSet(BaseModel):
    """Hashes for an extracted resource blob."""

    model_config = ConfigDict(extra="forbid")

    sha256: str = Field(min_length=64, max_length=64)
    sha1: str = Field(min_length=40, max_length=40)
    md5: str = Field(min_length=32, max_length=32)


class Location(BaseModel):
    """Location of an observation in the sample when known."""

    model_config = ConfigDict(extra="forbid")

    offset: int | None = None
    section: str | None = None


class ExtractedString(BaseModel):
    """Extracted static string with classification."""

    model_config = ConfigDict(extra="forbid")

    value: str
    offset: int
    encoding: Literal["ascii", "utf-16le"]
    category: StringCategory
    section: str | None = None


class NormalizedImport(BaseModel):
    """Normalized imported API or statically referenced API-like symbol."""

    model_config = ConfigDict(extra="forbid")

    module: str | None = None
    name: str
    ordinal: int | None = None
    category: ImportCategory
    source: Literal["import_table", "string_reference"]


class StaticResource(BaseModel):
    """Safely inspected embedded resource metadata."""

    model_config = ConfigDict(extra="forbid")

    resource_type: str | None = None
    identifier: str | None = None
    language: str | None = None
    size: int
    offset: int | None = None
    hashes: ResourceHashSet | None = None


class PEStaticFeatures(BaseModel):
    """Additional PE-only static features."""

    model_config = ConfigDict(extra="forbid")

    tls_callbacks_present: bool
    overlay_present: bool
    overlay_size: int
    import_descriptor_count: int
    executable_section_count: int
    writable_executable_section_count: int
    entry_point_section: str | None
    suspicious_entry_point_section: bool


class StaticEvidence(BaseModel):
    """Normalized static-analysis observation."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    type: EvidenceType
    source: str
    severity: EvidenceSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    description: str
    technical_details: dict[str, Any] = Field(default_factory=dict)
    location: Location | None = None
    related_object: str | None = None


class StaticFeatureVector(BaseModel):
    """Versioned normalized feature vector for future ML consumers."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = FEATURE_SCHEMA_VERSION
    file_size: int
    number_of_sections: int
    entropy_min: float | None
    entropy_max: float | None
    entropy_mean: float | None
    import_count: int
    api_category_counts: dict[str, int]
    string_counts: dict[str, int]
    resource_count: int
    overlay_size: int
    executable_section_count: int
    writable_executable_section_count: int
    evidence_counts: dict[str, int]


class StaticAnalysisResult(BaseModel):
    """Persisted Phase 2 static-analysis result."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    status: StaticAnalysisStatus
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    strings: list[ExtractedString]
    imports: list[NormalizedImport]
    resources: list[StaticResource]
    pe_features: PEStaticFeatures | None = None
    evidence: list[StaticEvidence]
    feature_vector: StaticFeatureVector
    limitations: list[str] = Field(default_factory=list)


class StaticAnalysisResponse(BaseModel):
    """API response for Phase 2 static analysis."""

    model_config = ConfigDict(extra="forbid")

    analysis: StaticAnalysisResult


class IndicatorsResponse(BaseModel):
    """Evidence-only response for static indicators."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    indicators: list[StaticEvidence]
