"""Normalized Phase 4 reverse-engineering schemas."""

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ReverseAnalysisStatus(StrEnum):
    """Reverse-analysis lifecycle state."""

    COMPLETED = "completed"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"


class ReverseEvidenceType(StrEnum):
    """Function-level reverse-engineering evidence types."""

    STRING_API_CORRELATION = "STRING_API_CORRELATION"
    SUSPICIOUS_API_CALL = "SUSPICIOUS_API_CALL"
    EXECUTABLE_MEMORY_OPERATION = "EXECUTABLE_MEMORY_OPERATION"
    UNUSUAL_CONTROL_FLOW = "UNUSUAL_CONTROL_FLOW"
    ENCODED_CONSTANT = "ENCODED_CONSTANT"
    SUSPICIOUS_STRING_REFERENCE = "SUSPICIOUS_STRING_REFERENCE"
    SENSITIVE_CAPABILITY_CALL = "SENSITIVE_CAPABILITY_CALL"


class Instruction(BaseModel):
    """Normalized disassembled instruction."""

    model_config = ConfigDict(extra="forbid")

    address: int
    mnemonic: str
    operands: str
    size: int
    bytes_hex: str
    normalized: str
    is_call: bool = False
    is_jump: bool = False
    target: int | None = None


class BasicBlock(BaseModel):
    """Control-flow basic block."""

    model_config = ConfigDict(extra="forbid")

    block_id: str
    start_address: int
    end_address: int
    instruction_addresses: list[int]
    successors: list[str]
    predecessors: list[str]
    terminal_instruction: str | None = None


class CFGEdge(BaseModel):
    """Control-flow graph edge."""

    model_config = ConfigDict(extra="forbid")

    source: str
    target: str
    edge_type: str


class CFG(BaseModel):
    """Function control-flow graph."""

    model_config = ConfigDict(extra="forbid")

    function_id: str
    blocks: list[BasicBlock]
    edges: list[CFGEdge]


class FunctionEvidence(BaseModel):
    """Reverse-engineering evidence associated with a function."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    type: ReverseEvidenceType
    function_id: str
    description: str
    confidence: float = Field(ge=0.0, le=1.0)
    technical_details: dict[str, str | int | float | list[str]]
    related_strings: list[str] = Field(default_factory=list)
    related_apis: list[str] = Field(default_factory=list)


class Function(BaseModel):
    """Function-oriented disassembly artifact."""

    model_config = ConfigDict(extra="forbid")

    function_id: str
    address: int
    size: int
    instructions: list[Instruction]
    calls: list[int]
    callers: list[str]
    callees: list[str]
    referenced_strings: list[str]
    referenced_apis: list[str]
    basic_block_count: int
    cyclomatic_complexity: int
    evidence: list[FunctionEvidence] = Field(default_factory=list)


class CallGraphNode(BaseModel):
    """Call graph node."""

    model_config = ConfigDict(extra="forbid")

    node_id: str
    label: str
    node_type: str


class CallGraphEdge(BaseModel):
    """Call graph edge."""

    model_config = ConfigDict(extra="forbid")

    source: str
    target: str
    call_type: str


class CallGraph(BaseModel):
    """Function call graph."""

    model_config = ConfigDict(extra="forbid")

    nodes: list[CallGraphNode]
    edges: list[CallGraphEdge]


class Disassembly(BaseModel):
    """Top-level disassembly metadata."""

    model_config = ConfigDict(extra="forbid")

    architecture: str
    entry_point: int | None
    engine: str
    instruction_count: int
    unsupported_reason: str | None = None


class ReverseAnalysisResult(BaseModel):
    """Persisted Phase 4 reverse-engineering result."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    status: ReverseAnalysisStatus
    schema_version: str = "reverse-analysis/v1"
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    disassembly: Disassembly
    functions: list[Function]
    cfgs: dict[str, CFG]
    call_graph: CallGraph
    evidence: list[FunctionEvidence]
    limitations: list[str] = Field(default_factory=list)


class ReverseAnalysisResponse(BaseModel):
    """API response for reverse analysis."""

    model_config = ConfigDict(extra="forbid")

    reverse_analysis: ReverseAnalysisResult


class FunctionsResponse(BaseModel):
    """Function listing response."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    functions: list[Function]


class FunctionResponse(BaseModel):
    """Single function response."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    function: Function


class CFGResponse(BaseModel):
    """Single function CFG response."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    cfg: CFG
