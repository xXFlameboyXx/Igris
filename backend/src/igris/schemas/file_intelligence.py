"""Normalized Phase 1 file intelligence schemas."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from igris.schemas.assessment import ExplainableAssessment
from igris.schemas.behavior_analysis import BehaviorAnalysisResult
from igris.schemas.detection import DetectionResult
from igris.schemas.investigation import AnalystNote, Bookmark
from igris.schemas.ml import MLPrediction
from igris.schemas.reverse_analysis import ReverseAnalysisResult
from igris.schemas.similarity import SimilarityReport
from igris.schemas.static_analysis import StaticAnalysisResult
from igris.schemas.threat_intelligence import ThreatAssessment


class AnalysisStatus(StrEnum):
    """Lifecycle states for Phase 1 file-intelligence analysis."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class DetectedFormat(StrEnum):
    """Content-based file format classification."""

    PE = "pe"
    ELF = "elf"
    TEXT = "text"
    EMPTY = "empty"
    UNKNOWN = "unknown"


class FieldState(StrEnum):
    """State of a metadata field."""

    PRESENT = "present"
    NOT_PRESENT = "not_present"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"


class MetadataValue(BaseModel):
    """A metadata value with explicit absence/failure semantics."""

    model_config = ConfigDict(extra="forbid")

    state: FieldState
    value: Any | None = None
    error: str | None = None

    @classmethod
    def present(cls, value: Any) -> "MetadataValue":
        return cls(state=FieldState.PRESENT, value=value)

    @classmethod
    def not_present(cls) -> "MetadataValue":
        return cls(state=FieldState.NOT_PRESENT)

    @classmethod
    def failed(cls, error: str) -> "MetadataValue":
        return cls(state=FieldState.FAILED, error=error)

    @classmethod
    def not_applicable(cls) -> "MetadataValue":
        return cls(state=FieldState.NOT_APPLICABLE)


class HashSet(BaseModel):
    """Cryptographic hashes for a sample."""

    model_config = ConfigDict(extra="forbid")

    sha256: str = Field(min_length=64, max_length=64)
    sha1: str = Field(min_length=40, max_length=40)
    md5: str = Field(min_length=32, max_length=32)


class SectionMetadata(BaseModel):
    """Normalized section metadata for PE and ELF files."""

    model_config = ConfigDict(extra="forbid")

    name: str
    virtual_size: int | None = None
    raw_size: int
    virtual_address: int | None = None
    raw_offset: int | None = None
    characteristics: str | None = None
    permissions: str | None = None
    entropy: float | None = None


class ImportMetadata(BaseModel):
    """Imported symbol metadata."""

    model_config = ConfigDict(extra="forbid")

    module: str
    name: str | None = None
    ordinal: int | None = None


class ExportMetadata(BaseModel):
    """Exported symbol metadata."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    ordinal: int | None = None
    address: int | None = None


class ResourceMetadata(BaseModel):
    """PE resource metadata."""

    model_config = ConfigDict(extra="forbid")

    resource_type: str | None = None
    name: str | None = None
    language: str | None = None
    size: int | None = None
    offset: int | None = None


class PEDataDirectoryStatus(BaseModel):
    """State for PE imports, exports, or resources."""

    model_config = ConfigDict(extra="forbid")

    state: FieldState
    error: str | None = None


class PEMetadata(BaseModel):
    """Foundational Portable Executable metadata."""

    model_config = ConfigDict(extra="forbid")

    dos_magic: str
    pe_signature: str
    machine: str
    coff_header: dict[str, int | str]
    optional_header: dict[str, int | str]
    architecture: str
    image_base: int | None
    entry_point: MetadataValue
    subsystem: str | None
    number_of_sections: int
    sections: list[SectionMetadata]
    imports: list[ImportMetadata]
    imports_status: PEDataDirectoryStatus
    exports: list[ExportMetadata]
    exports_status: PEDataDirectoryStatus
    resources: list[ResourceMetadata]
    resources_status: PEDataDirectoryStatus
    parse_warnings: list[str] = Field(default_factory=list)


class ProgramHeaderMetadata(BaseModel):
    """ELF program header metadata."""

    model_config = ConfigDict(extra="forbid")

    header_type: str
    offset: int
    virtual_address: int
    file_size: int
    memory_size: int
    permissions: str


class SymbolMetadata(BaseModel):
    """ELF symbol metadata."""

    model_config = ConfigDict(extra="forbid")

    name: str
    binding: str | None = None
    symbol_type: str | None = None
    section_index: str | int | None = None
    value: int | None = None
    size: int | None = None


class ELFMetadata(BaseModel):
    """Foundational Executable and Linkable Format metadata."""

    model_config = ConfigDict(extra="forbid")

    elf_class: Literal["ELF32", "ELF64"]
    architecture: str
    endianness: Literal["little", "big"]
    entry_point: MetadataValue
    program_headers: list[ProgramHeaderMetadata]
    sections: list[SectionMetadata]
    dynamic_libraries: list[str]
    dynamic_libraries_status: MetadataValue
    symbols: list[SymbolMetadata]
    symbols_status: MetadataValue
    parse_warnings: list[str] = Field(default_factory=list)


class FileMetadata(BaseModel):
    """Normalized Phase 1 file intelligence result."""

    model_config = ConfigDict(extra="forbid")

    size_bytes: int
    detected_format: DetectedFormat
    architecture: str | None = None
    mime_type: str
    entropy: float
    created_at: MetadataValue
    modified_at: MetadataValue
    entry_point: MetadataValue
    pe: PEMetadata | None = None
    elf: ELFMetadata | None = None
    parse_errors: list[str] = Field(default_factory=list)


class Sample(BaseModel):
    """Internal sample record."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    original_filename: str
    safe_filename: str
    content_type_supplied: str | None = None
    hashes: HashSet
    storage_ref: str
    size_bytes: int
    status: AnalysisStatus
    file_metadata: FileMetadata | None = None
    static_analysis: StaticAnalysisResult | None = None
    detection: DetectionResult | None = None
    reverse_analysis: ReverseAnalysisResult | None = None
    threat_assessment: ThreatAssessment | None = None
    ml_prediction: MLPrediction | None = None
    behavior_analysis: BehaviorAnalysisResult | None = None
    similarity_analysis: SimilarityReport | None = None
    malware_assessment: ExplainableAssessment | None = None
    bookmarks: list[Bookmark] = Field(default_factory=list)
    notes: list[AnalystNote] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SampleCreateResponse(BaseModel):
    """Response returned after uploading a sample."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    sha256: str
    status: AnalysisStatus


class SampleResponse(BaseModel):
    """Sample metadata response that does not expose filesystem paths."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    original_filename: str
    safe_filename: str
    hashes: HashSet
    size_bytes: int
    status: AnalysisStatus
    detected_format: DetectedFormat | None
    created_at: datetime
    updated_at: datetime
    file_metadata: FileMetadata | None = None
    static_analysis: StaticAnalysisResult | None = None
    detection: DetectionResult | None = None
    reverse_analysis: ReverseAnalysisResult | None = None
    threat_assessment: ThreatAssessment | None = None
    ml_prediction: MLPrediction | None = None
    behavior_analysis: BehaviorAnalysisResult | None = None
    similarity_analysis: SimilarityReport | None = None
    malware_assessment: ExplainableAssessment | None = None
    bookmarks: list[Bookmark] = Field(default_factory=list)
    notes: list[AnalystNote] = Field(default_factory=list)

    @classmethod
    def from_sample(cls, sample: Sample) -> "SampleResponse":
        detected_format = (
            sample.file_metadata.detected_format if sample.file_metadata is not None else None
        )
        return cls(
            sample_id=sample.sample_id,
            original_filename=sample.original_filename,
            safe_filename=sample.safe_filename,
            hashes=sample.hashes,
            size_bytes=sample.size_bytes,
            status=sample.status,
            detected_format=detected_format,
            created_at=sample.created_at,
            updated_at=sample.updated_at,
            file_metadata=sample.file_metadata,
            static_analysis=sample.static_analysis,
            detection=sample.detection,
            reverse_analysis=sample.reverse_analysis,
            threat_assessment=sample.threat_assessment,
            ml_prediction=sample.ml_prediction,
            behavior_analysis=sample.behavior_analysis,
            similarity_analysis=sample.similarity_analysis,
            malware_assessment=sample.malware_assessment,
            bookmarks=sample.bookmarks,
            notes=sample.notes,
        )


class FileInfoResponse(BaseModel):
    """Detailed normalized Phase 1 analysis response."""

    model_config = ConfigDict(extra="forbid")

    sample: SampleResponse
    file: FileMetadata
    hashes: HashSet
    format: dict[str, str | None]
    sections: list[SectionMetadata]
    imports: list[ImportMetadata]
    exports: list[ExportMetadata]
    resources: list[ResourceMetadata]


class SampleListResponse(BaseModel):
    """List of ingested samples."""

    model_config = ConfigDict(extra="forbid")

    samples: list[SampleResponse]
