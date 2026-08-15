"""Phase 10 feature extraction and normalization for sample similarity analysis."""

import re
from collections import Counter

from igris.schemas.file_intelligence import Sample
from igris.schemas.similarity import NormalizedSampleFeatures, SectionFeature


def normalize_api_name(dll_name: str | None, func_name: str | None) -> str:
    """Normalize DLL and function name to uniform 'dll!function' lowercase representation."""
    dll_part = (dll_name or "").strip().lower()
    if dll_part.endswith(".dll"):
        dll_part = dll_part
    elif dll_part:
        dll_part = f"{dll_part}.dll"

    func_part = (func_name or "").strip().lower()
    # Strip ordinal prefix/suffix markers if present (e.g., '@12')
    func_part = re.sub(r"@\d+$", "", func_part)

    if dll_part and func_part:
        return f"{dll_part}!{func_part}"
    return func_part or dll_part


def normalize_string_token(s: str) -> str | None:
    """Normalize candidate string token, filtering out trivial noise, IDs, and whitespace."""
    token = s.strip().lower()
    # Filter trivial / uninformative strings
    if len(token) < 4:
        return None
    # Filter UUIDs or pure hex digests that represent ephemeral sample IDs
    if re.fullmatch(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", token):
        return None
    if re.fullmatch(r"^[0-9a-f]{32,64}$", token):
        return None
    return token


def extract_similarity_features(sample: Sample) -> NormalizedSampleFeatures:
    """Extract and normalize multi-dimensional similarity features from available sample data."""
    detected_format: str | None = None
    if sample.file_metadata and sample.file_metadata.detected_format:
        detected_format = sample.file_metadata.detected_format.value

    # 1. Imported APIs
    imported_apis_set: set[str] = set()
    if sample.file_metadata and sample.file_metadata.pe:
        for imp in sample.file_metadata.pe.imports:
            normalized = normalize_api_name(imp.module, imp.name)
            if normalized:
                imported_apis_set.add(normalized)
    elif sample.file_metadata and sample.file_metadata.elf:
        if sample.file_metadata.elf.symbols:
            for sym in sample.file_metadata.elf.symbols:
                normalized = normalize_api_name(None, sym.name)
                if normalized:
                    imported_apis_set.add(normalized)

    # 2. Section characteristics
    sections: list[SectionFeature] = []
    total_size = max(sample.size_bytes, 1)
    if sample.file_metadata and sample.file_metadata.pe:
        for sec in sample.file_metadata.pe.sections:
            sec_name = sec.name.strip().lower()
            v_size = sec.virtual_size if sec.virtual_size is not None else sec.raw_size
            size_ratio = min(round(v_size / total_size, 4), 1.0) if total_size > 0 else 0.0
            perms = (sec.permissions or "").lower()
            chars = (sec.characteristics or "").lower()
            is_exec = "x" in perms or "exec" in perms or "exec" in chars
            is_write = "w" in perms or "write" in perms or "write" in chars
            sections.append(
                SectionFeature(
                    name=sec_name,
                    entropy=round(sec.entropy, 2) if sec.entropy is not None else 0.0,
                    size_ratio=size_ratio,
                    is_executable=is_exec,
                    is_writable=is_write,
                )
            )
    elif sample.file_metadata and sample.file_metadata.elf:
        for sec in sample.file_metadata.elf.sections:
            sec_name = sec.name.strip().lower()
            size_ratio = min(round(sec.raw_size / total_size, 4), 1.0) if total_size > 0 else 0.0
            perms = (sec.permissions or "").lower()
            is_exec = "x" in perms or "exec" in perms
            is_write = "w" in perms or "write" in perms
            sections.append(
                SectionFeature(
                    name=sec_name,
                    entropy=round(sec.entropy, 2) if sec.entropy is not None else 0.0,
                    size_ratio=size_ratio,
                    is_executable=is_exec,
                    is_writable=is_write,
                )
            )

    # 3. High-signal interesting strings & static imports
    interesting_strings_set: set[str] = set()
    if sample.static_analysis:
        for s in sample.static_analysis.strings:
            norm_s = normalize_string_token(s.value)
            if norm_s:
                interesting_strings_set.add(norm_s)
        for static_imp in sample.static_analysis.imports:
            norm_api = normalize_api_name(static_imp.module, static_imp.name)
            if norm_api:
                imported_apis_set.add(norm_api)
        for ev in sample.static_analysis.evidence:
            if ev.related_object:
                if ev.type.value in ("INTERESTING_STRING", "SUSPICIOUS_KEYWORD"):
                    norm_str = normalize_string_token(ev.related_object)
                    if norm_str:
                        interesting_strings_set.add(norm_str)
                elif ev.type.value == "API_CAPABILITY":
                    norm_api = normalize_api_name(None, ev.related_object)
                    if norm_api:
                        imported_apis_set.add(norm_api)

    # 4. Reverse analysis: Functions and Opcode distribution
    function_count = 0
    function_signatures: list[str] = []
    opcode_counts: Counter[str] = Counter()
    has_reverse = False

    if sample.reverse_analysis and sample.reverse_analysis.functions:
        has_reverse = True
        function_count = len(sample.reverse_analysis.functions)
        for fn in sample.reverse_analysis.functions:
            fn_sig = (
                f"blocks:{fn.basic_block_count}|size:{fn.size}|calls:{len(fn.calls)}|"
                f"complexity:{fn.cyclomatic_complexity}"
            )
            function_signatures.append(fn_sig)
            for instr in fn.instructions:
                mnem = instr.mnemonic.strip().lower()
                if mnem:
                    opcode_counts[mnem] += 1

    # 5. Behavioral telemetry
    behavior_procs: set[str] = set()
    behavior_regs: set[str] = set()
    behavior_nets: set[str] = set()
    behavior_muts: set[str] = set()
    has_behavior = False

    if sample.behavior_analysis:
        has_behavior = True
        for proc in sample.behavior_analysis.processes:
            p_name = proc.process_name.strip().lower()
            if p_name:
                behavior_procs.add(p_name)
        for reg in sample.behavior_analysis.registry_events:
            r_key = reg.key_path.strip().lower()
            if r_key:
                behavior_regs.add(r_key)
        for net in sample.behavior_analysis.network_events:
            if net.destination_ip and net.destination_port:
                target = f"{net.destination_ip}:{net.destination_port}".lower()
                behavior_nets.add(target)
            if net.domain:
                behavior_nets.add(net.domain.strip().lower())
        for mut in sample.behavior_analysis.mutexes:
            m_name = mut.name.strip().lower()
            if m_name:
                behavior_muts.add(m_name)

    return NormalizedSampleFeatures(
        sample_id=sample.sample_id,
        sha256=sample.hashes.sha256,
        detected_format=detected_format,
        imported_apis=sorted(imported_apis_set),
        interesting_strings=sorted(interesting_strings_set),
        sections=sections,
        function_count=function_count,
        function_signatures=sorted(function_signatures),
        opcode_distribution=dict(opcode_counts),
        behavior_processes=sorted(behavior_procs),
        behavior_registry_keys=sorted(behavior_regs),
        behavior_network_targets=sorted(behavior_nets),
        behavior_mutexes=sorted(behavior_muts),
        has_static=sample.static_analysis is not None,
        has_reverse=has_reverse,
        has_behavior=has_behavior,
        feature_version="similarity_features/v1",
    )
