"""Safe offline reverse-engineering analysis using Capstone."""

import hashlib
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from capstone import (  # type: ignore[import-untyped]
    CS_ARCH_X86,
    CS_GRP_CALL,
    CS_GRP_JUMP,
    CS_GRP_RET,
    CS_MODE_32,
    CS_MODE_64,
    CS_OP_IMM,
    Cs,
)

from igris.core.config import Settings
from igris.schemas.file_intelligence import DetectedFormat, Sample, SectionMetadata
from igris.schemas.reverse_analysis import (
    CFG,
    BasicBlock,
    CallGraph,
    CallGraphEdge,
    CallGraphNode,
    CFGEdge,
    Disassembly,
    Function,
    FunctionEvidence,
    Instruction,
    ReverseAnalysisResult,
    ReverseAnalysisStatus,
    ReverseEvidenceType,
)
from igris.schemas.static_analysis import ExtractedString, ImportCategory, NormalizedImport


@dataclass(frozen=True)
class MemorySection:
    name: str
    raw_offset: int
    raw_size: int
    address: int
    virtual_size: int
    executable: bool


@dataclass(frozen=True)
class ReverseContext:
    architecture: str
    entry_point: int | None
    sections: list[MemorySection]
    image_base: int


def analyze_reverse(sample: Sample, path: Path, settings: Settings) -> ReverseAnalysisResult:
    """Disassemble a sample as hostile data and build reverse-engineering artifacts."""

    context = _build_context(sample)
    if context is None or context.entry_point is None:
        return _unsupported_result(
            sample,
            settings,
            "unsupported or missing architecture/entry point for reverse analysis",
        )

    try:
        disassembler = _build_disassembler(context.architecture)
    except ValueError as exc:
        return _unsupported_result(sample, settings, str(exc))

    data = path.read_bytes()
    static_analysis = sample.static_analysis
    strings = static_analysis.strings if static_analysis is not None else []
    imports = static_analysis.imports if static_analysis is not None else []
    string_addresses = _string_addresses(strings, context)
    api_by_name = {item.name: item for item in imports}

    functions: dict[int, Function] = {}
    cfgs: dict[str, CFG] = {}
    queue: deque[int] = deque([context.entry_point])
    queued = {context.entry_point}
    instruction_budget = settings.reverse_max_instructions

    while queue and len(functions) < settings.reverse_max_functions and instruction_budget > 0:
        address = queue.popleft()
        if address in functions:
            continue
        instructions = _disassemble_function(
            disassembler, data, context, address, instruction_budget
        )
        if not instructions:
            continue
        instruction_budget -= len(instructions)
        calls = sorted(
            {ins.target for ins in instructions if ins.is_call and ins.target is not None}
        )
        for target in calls:
            if _address_in_executable_section(target, context.sections) and target not in queued:
                queue.append(target)
                queued.add(target)
        function_id = _function_id(address)
        referenced_strings = _referenced_strings(instructions, string_addresses)
        referenced_apis = _referenced_apis(referenced_strings, api_by_name)
        cfg = _build_cfg(function_id, instructions)
        function = Function(
            function_id=function_id,
            address=address,
            size=(instructions[-1].address + instructions[-1].size) - address,
            instructions=instructions,
            calls=calls,
            callers=[],
            callees=[],
            referenced_strings=referenced_strings,
            referenced_apis=referenced_apis,
            basic_block_count=len(cfg.blocks),
            cyclomatic_complexity=max(1, len(cfg.edges) - len(cfg.blocks) + 2),
            evidence=[],
        )
        cfgs[function_id] = cfg
        functions[address] = function

    function_list = _link_functions(list(functions.values()))
    function_list = _attach_function_evidence(function_list, api_by_name)
    call_graph = _build_call_graph(function_list)
    evidence = [item for function in function_list for item in function.evidence]
    instruction_count = sum(len(function.instructions) for function in function_list)

    return ReverseAnalysisResult(
        sample_id=sample.sample_id,
        status=ReverseAnalysisStatus.COMPLETED,
        schema_version=settings.reverse_engine_version,
        disassembly=Disassembly(
            architecture=context.architecture,
            entry_point=context.entry_point,
            engine="capstone",
            instruction_count=instruction_count,
        ),
        functions=function_list,
        cfgs=cfgs,
        call_graph=call_graph,
        evidence=evidence,
        limitations=[
            "Disassembly is static and does not execute the sample.",
            "Function discovery is entry-point and direct-call oriented; "
            "it is not full decompilation.",
            "Indirect calls, obfuscation, packed code, and unsupported architectures "
            "may reduce coverage.",
        ],
    )


def _build_context(sample: Sample) -> ReverseContext | None:
    metadata = sample.file_metadata
    if metadata is None:
        return None
    if metadata.detected_format == DetectedFormat.PE and metadata.pe is not None:
        image_base = metadata.pe.image_base or 0
        entry_value = metadata.pe.entry_point.value
        entry_point = image_base + int(entry_value) if isinstance(entry_value, int) else None
        return ReverseContext(
            architecture=metadata.pe.architecture,
            entry_point=entry_point,
            sections=_memory_sections(metadata.pe.sections, image_base=image_base, is_pe=True),
            image_base=image_base,
        )
    if metadata.detected_format == DetectedFormat.ELF and metadata.elf is not None:
        entry_value = metadata.elf.entry_point.value
        entry_point = int(entry_value) if isinstance(entry_value, int) else None
        return ReverseContext(
            architecture=metadata.elf.architecture,
            entry_point=entry_point,
            sections=_memory_sections(metadata.elf.sections, image_base=0, is_pe=False),
            image_base=0,
        )
    return None


def _memory_sections(
    sections: list[SectionMetadata], *, image_base: int, is_pe: bool
) -> list[MemorySection]:
    memory_sections: list[MemorySection] = []
    for section in sections:
        if section.raw_offset is None or section.virtual_address is None:
            continue
        characteristics = int(section.characteristics or "0", 16)
        executable = bool(characteristics & 0x20000000) or "X" in (section.permissions or "")
        memory_sections.append(
            MemorySection(
                name=section.name,
                raw_offset=section.raw_offset,
                raw_size=section.raw_size,
                address=(image_base if is_pe else 0) + section.virtual_address,
                virtual_size=section.virtual_size or section.raw_size,
                executable=executable,
            )
        )
    return memory_sections


def _build_disassembler(architecture: str) -> Any:
    if architecture == "x86":
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    elif architecture == "x86_64":
        disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    else:
        raise ValueError(f"unsupported architecture for disassembly: {architecture}")
    disassembler.detail = True
    return disassembler


def _disassemble_function(
    disassembler: Any,
    data: bytes,
    context: ReverseContext,
    address: int,
    max_instructions: int,
) -> list[Instruction]:
    section = _section_for_address(address, context.sections)
    if section is None or not section.executable:
        return []
    offset = section.raw_offset + (address - section.address)
    max_size = min(section.raw_offset + section.raw_size, len(data)) - offset
    if max_size <= 0:
        return []
    instructions: list[Instruction] = []
    for raw in disassembler.disasm(data[offset : offset + max_size], address):
        groups = set(raw.groups)
        target = _instruction_target(raw)
        instruction = Instruction(
            address=int(raw.address),
            mnemonic=str(raw.mnemonic),
            operands=str(raw.op_str),
            size=int(raw.size),
            bytes_hex=bytes(raw.bytes).hex(),
            normalized=_normalize_instruction(str(raw.mnemonic), str(raw.op_str)),
            is_call=CS_GRP_CALL in groups,
            is_jump=CS_GRP_JUMP in groups,
            target=target,
        )
        instructions.append(instruction)
        if len(instructions) >= max_instructions or CS_GRP_RET in groups:
            break
    return instructions


def _instruction_target(raw: Any) -> int | None:
    if not raw.operands:
        return None
    first = raw.operands[0]
    if first.type == CS_OP_IMM:
        return int(first.imm)
    return None


def _normalize_instruction(mnemonic: str, operands: str) -> str:
    if not operands:
        return mnemonic.lower()
    return f"{mnemonic.lower()} {operands.lower()}"


def _build_cfg(function_id: str, instructions: list[Instruction]) -> CFG:
    if not instructions:
        return CFG(function_id=function_id, blocks=[], edges=[])
    by_address = {ins.address: ins for ins in instructions}
    addresses = [ins.address for ins in instructions]
    starts = {addresses[0]}
    for index, instruction in enumerate(instructions):
        next_address = addresses[index + 1] if index + 1 < len(addresses) else None
        if instruction.is_jump and instruction.target in by_address:
            starts.add(instruction.target)
        if _terminates_block(instruction) and next_address is not None:
            starts.add(next_address)
    sorted_starts = sorted(starts)
    block_for_address: dict[int, str] = {}
    blocks: list[BasicBlock] = []
    for index, start in enumerate(sorted_starts):
        end_boundary = sorted_starts[index + 1] if index + 1 < len(sorted_starts) else None
        block_instructions = [
            ins
            for ins in instructions
            if ins.address >= start and (end_boundary is None or ins.address < end_boundary)
        ]
        if not block_instructions:
            continue
        block_id = f"{function_id}_bb_{index}"
        for instruction in block_instructions:
            block_for_address[instruction.address] = block_id
        terminal = block_instructions[-1]
        blocks.append(
            BasicBlock(
                block_id=block_id,
                start_address=block_instructions[0].address,
                end_address=terminal.address + terminal.size,
                instruction_addresses=[ins.address for ins in block_instructions],
                successors=[],
                predecessors=[],
                terminal_instruction=terminal.normalized,
            )
        )
    edges = _cfg_edges(blocks, instructions, block_for_address)
    blocks = _attach_block_links(blocks, edges)
    return CFG(function_id=function_id, blocks=blocks, edges=edges)


def _cfg_edges(
    blocks: list[BasicBlock],
    instructions: list[Instruction],
    block_for_address: dict[int, str],
) -> list[CFGEdge]:
    by_address = {ins.address: ins for ins in instructions}
    edges: list[CFGEdge] = []
    for block in blocks:
        terminal = by_address[block.instruction_addresses[-1]]
        next_address = terminal.address + terminal.size
        if terminal.is_jump and terminal.target in block_for_address:
            edges.append(
                CFGEdge(
                    source=block.block_id,
                    target=block_for_address[terminal.target],
                    edge_type="jump",
                )
            )
        if not _is_unconditional_jump(terminal) and next_address in block_for_address:
            edges.append(
                CFGEdge(
                    source=block.block_id,
                    target=block_for_address[next_address],
                    edge_type="fallthrough",
                )
            )
    return edges


def _attach_block_links(blocks: list[BasicBlock], edges: list[CFGEdge]) -> list[BasicBlock]:
    successors: dict[str, list[str]] = {block.block_id: [] for block in blocks}
    predecessors: dict[str, list[str]] = {block.block_id: [] for block in blocks}
    for edge in edges:
        successors.setdefault(edge.source, []).append(edge.target)
        predecessors.setdefault(edge.target, []).append(edge.source)
    return [
        block.model_copy(
            update={
                "successors": sorted(set(successors.get(block.block_id, []))),
                "predecessors": sorted(set(predecessors.get(block.block_id, []))),
            }
        )
        for block in blocks
    ]


def _terminates_block(instruction: Instruction) -> bool:
    return instruction.is_jump or instruction.mnemonic.startswith("ret")


def _is_unconditional_jump(instruction: Instruction) -> bool:
    return instruction.mnemonic == "jmp" or instruction.mnemonic.startswith("ret")


def _link_functions(functions: list[Function]) -> list[Function]:
    by_address = {function.address: function.function_id for function in functions}
    callers: dict[str, list[str]] = {function.function_id: [] for function in functions}
    updated: list[Function] = []
    for function in functions:
        callees = sorted({by_address[target] for target in function.calls if target in by_address})
        for callee in callees:
            callers[callee].append(function.function_id)
        updated.append(function.model_copy(update={"callees": callees}))
    return [
        function.model_copy(update={"callers": sorted(set(callers[function.function_id]))})
        for function in updated
    ]


def _build_call_graph(functions: list[Function]) -> CallGraph:
    nodes = [
        CallGraphNode(
            node_id=function.function_id,
            label=hex(function.address),
            node_type="internal",
        )
        for function in functions
    ]
    api_nodes: dict[str, CallGraphNode] = {}
    edges: list[CallGraphEdge] = []
    for function in functions:
        for callee in function.callees:
            edges.append(
                CallGraphEdge(source=function.function_id, target=callee, call_type="internal")
            )
        for api in function.referenced_apis:
            node_id = f"api:{api}"
            api_nodes[node_id] = CallGraphNode(node_id=node_id, label=api, node_type="imported_api")
            edges.append(
                CallGraphEdge(
                    source=function.function_id,
                    target=node_id,
                    call_type="api_reference",
                )
            )
    return CallGraph(nodes=nodes + list(api_nodes.values()), edges=edges)


def _attach_function_evidence(
    functions: list[Function], api_by_name: dict[str, NormalizedImport]
) -> list[Function]:
    updated: list[Function] = []
    for function in functions:
        evidence: list[FunctionEvidence] = []
        suspicious_strings = [
            value
            for value in function.referenced_strings
            if any(
                token in value.lower()
                for token in ("registry", "hkcu", "hklm", "credential", "powershell")
            )
        ]
        sensitive_apis = [
            api
            for api in function.referenced_apis
            if api_by_name.get(api) is not None
            and api_by_name[api].category
            in {
                ImportCategory.MEMORY_MANAGEMENT,
                ImportCategory.PROCESS_THREAD_MANIPULATION,
                ImportCategory.REGISTRY,
            }
        ]
        if suspicious_strings:
            evidence.append(
                _function_evidence(
                    ReverseEvidenceType.SUSPICIOUS_STRING_REFERENCE,
                    function.function_id,
                    "Function references strings with persistence, credential, "
                    "or interpreter relevance.",
                    0.64,
                    {"strings": suspicious_strings},
                    related_strings=suspicious_strings,
                )
            )
        if sensitive_apis:
            evidence.append(
                _function_evidence(
                    ReverseEvidenceType.SENSITIVE_CAPABILITY_CALL,
                    function.function_id,
                    "Function references APIs mapped to sensitive static capabilities.",
                    0.68,
                    {"apis": sensitive_apis},
                    related_apis=sensitive_apis,
                )
            )
        if suspicious_strings and sensitive_apis:
            evidence.append(
                _function_evidence(
                    ReverseEvidenceType.STRING_API_CORRELATION,
                    function.function_id,
                    "Function-level correlation links suspicious strings to sensitive "
                    "API capability.",
                    0.78,
                    {"strings": suspicious_strings, "apis": sensitive_apis},
                    related_strings=suspicious_strings,
                    related_apis=sensitive_apis,
                )
            )
        if any(
            api in {"VirtualAlloc", "VirtualProtect", "WriteProcessMemory"}
            for api in sensitive_apis
        ):
            evidence.append(
                _function_evidence(
                    ReverseEvidenceType.EXECUTABLE_MEMORY_OPERATION,
                    function.function_id,
                    "Function references executable memory or process memory operations.",
                    0.72,
                    {"apis": sensitive_apis},
                    related_apis=sensitive_apis,
                )
            )
        if function.cyclomatic_complexity >= 4:
            evidence.append(
                _function_evidence(
                    ReverseEvidenceType.UNUSUAL_CONTROL_FLOW,
                    function.function_id,
                    "Function has elevated static control-flow complexity.",
                    0.55,
                    {"cyclomatic_complexity": function.cyclomatic_complexity},
                )
            )
        updated.append(function.model_copy(update={"evidence": evidence}))
    return updated


def _function_evidence(
    evidence_type: ReverseEvidenceType,
    function_id: str,
    description: str,
    confidence: float,
    details: dict[str, str | int | float | list[str]],
    *,
    related_strings: list[str] | None = None,
    related_apis: list[str] | None = None,
) -> FunctionEvidence:
    digest = hashlib.sha256(f"{function_id}|{evidence_type}|{details}".encode()).hexdigest()[:16]
    return FunctionEvidence(
        evidence_id=f"rev-{digest}",
        type=evidence_type,
        function_id=function_id,
        description=description,
        confidence=confidence,
        technical_details=details,
        related_strings=related_strings or [],
        related_apis=related_apis or [],
    )


def _referenced_strings(
    instructions: list[Instruction], string_addresses: dict[int, ExtractedString]
) -> list[str]:
    referenced: list[str] = []
    for instruction in instructions:
        if instruction.target is not None and instruction.target in string_addresses:
            referenced.append(string_addresses[instruction.target].value)
        for address, string in string_addresses.items():
            needle = hex(address).lower().removeprefix("0x")
            if needle and needle in instruction.operands.lower():
                referenced.append(string.value)
    return sorted(set(referenced))


def _referenced_apis(
    referenced_strings: list[str], api_by_name: dict[str, NormalizedImport]
) -> list[str]:
    apis: set[str] = set()
    for value in referenced_strings:
        for api in api_by_name:
            if api in value or api == value:
                apis.add(api)
    return sorted(apis)


def _string_addresses(
    strings: list[ExtractedString], context: ReverseContext
) -> dict[int, ExtractedString]:
    mapping: dict[int, ExtractedString] = {}
    for string in strings:
        section = _section_for_offset(string.offset, context.sections)
        if section is None:
            continue
        mapping[section.address + (string.offset - section.raw_offset)] = string
    return mapping


def _section_for_address(address: int, sections: list[MemorySection]) -> MemorySection | None:
    for section in sections:
        span = max(section.virtual_size, section.raw_size)
        if section.address <= address < section.address + span:
            return section
    return None


def _section_for_offset(offset: int, sections: list[MemorySection]) -> MemorySection | None:
    for section in sections:
        if section.raw_offset <= offset < section.raw_offset + section.raw_size:
            return section
    return None


def _address_in_executable_section(address: int, sections: list[MemorySection]) -> bool:
    section = _section_for_address(address, sections)
    return section is not None and section.executable


def _function_id(address: int) -> str:
    return f"fn_{address:x}"


def _unsupported_result(sample: Sample, settings: Settings, reason: str) -> ReverseAnalysisResult:
    architecture = (
        sample.file_metadata.architecture if sample.file_metadata is not None else "unknown"
    )
    return ReverseAnalysisResult(
        sample_id=sample.sample_id,
        status=ReverseAnalysisStatus.UNSUPPORTED,
        schema_version=settings.reverse_engine_version,
        disassembly=Disassembly(
            architecture=architecture or "unknown",
            entry_point=None,
            engine="capstone",
            instruction_count=0,
            unsupported_reason=reason,
        ),
        functions=[],
        cfgs={},
        call_graph=CallGraph(nodes=[], edges=[]),
        evidence=[],
        limitations=[reason],
    )
