"""Deterministic heuristic engine for Phase 3 detection."""

from igris.schemas.detection import HeuristicFinding
from igris.schemas.static_analysis import EvidenceSeverity, StaticAnalysisResult


class HeuristicEngine:
    """Evaluate transparent static-analysis heuristics."""

    def evaluate(self, analysis: StaticAnalysisResult) -> list[HeuristicFinding]:
        vector = analysis.feature_vector
        findings: list[HeuristicFinding] = []
        evidence_by_type = _evidence_ids_by_type(analysis)
        api_counts = vector.api_category_counts
        string_counts = vector.string_counts
        evidence_counts = vector.evidence_counts

        if (
            string_counts.get("registry_path", 0) >= 1
            and string_counts.get("command_interpreter", 0) >= 1
        ):
            findings.append(
                HeuristicFinding(
                    heuristic_id="HEUR-PERSISTENCE-001",
                    name="Persistence-Like Strings With Interpreter Indicator",
                    category="suspicious_persistence_indicators",
                    severity=EvidenceSeverity.MEDIUM,
                    confidence=0.68,
                    contribution=1.2,
                    explanation=(
                        "Registry-path strings appear together with command/interpreter strings. "
                        "This may be benign, but the combination is persistence-relevant."
                    ),
                    supporting_evidence_ids=evidence_by_type.get("INTERESTING_STRING", []),
                )
            )

        if (
            api_counts.get("process_thread_manipulation", 0) >= 1
            and api_counts.get("memory_management", 0) >= 1
        ):
            findings.append(
                HeuristicFinding(
                    heuristic_id="HEUR-PROC-001",
                    name="Process Manipulation With Memory Management",
                    category="suspicious_process_manipulation_indicators",
                    severity=EvidenceSeverity.MEDIUM,
                    confidence=0.72,
                    contribution=1.4,
                    explanation=(
                        "Process/thread manipulation capability appears with memory-management "
                        "capability. This combination is more meaningful than either API alone."
                    ),
                    supporting_evidence_ids=evidence_by_type.get("API_CAPABILITY", []),
                )
            )

        if vector.writable_executable_section_count >= 1:
            findings.append(
                HeuristicFinding(
                    heuristic_id="HEUR-MEM-001",
                    name="Writable Executable Section",
                    category="suspicious_memory_characteristics",
                    severity=EvidenceSeverity.MEDIUM,
                    confidence=0.76,
                    contribution=1.0,
                    explanation=(
                        "At least one section is both writable and executable. Benign packers or "
                        "protectors may do this, so this is not a verdict."
                    ),
                    supporting_evidence_ids=evidence_by_type.get("EXECUTABLE_WRITABLE_SECTION", []),
                )
            )

        if evidence_counts.get("POSSIBLE_PACKING_INDICATOR", 0) >= 2:
            findings.append(
                HeuristicFinding(
                    heuristic_id="HEUR-OBF-001",
                    name="Multiple Possible Packing Indicators",
                    category="obfuscation_or_packing_indicators",
                    severity=EvidenceSeverity.LOW,
                    confidence=0.66,
                    contribution=0.9,
                    explanation=(
                        "Multiple conservative packing indicators co-occur. This can also occur "
                        "in installers and protected commercial software."
                    ),
                    supporting_evidence_ids=evidence_by_type.get("POSSIBLE_PACKING_INDICATOR", []),
                )
            )

        if string_counts.get("command_interpreter", 0) >= 1:
            findings.append(
                HeuristicFinding(
                    heuristic_id="HEUR-SCRIPT-001",
                    name="Command Or Interpreter Reference",
                    category="suspicious_scripting_interpreter_indicators",
                    severity=EvidenceSeverity.LOW,
                    confidence=0.6,
                    contribution=0.5,
                    explanation=(
                        "A command/interpreter reference was extracted. This is weak by itself "
                        "and is common in benign administration tools."
                    ),
                    supporting_evidence_ids=evidence_by_type.get("INTERESTING_STRING", []),
                )
            )

        if api_counts.get("networking", 0) >= 1 and (
            string_counts.get("url", 0) >= 1
            or string_counts.get("domain", 0) >= 1
            or string_counts.get("ipv4", 0) >= 1
            or string_counts.get("ipv6", 0) >= 1
        ):
            findings.append(
                HeuristicFinding(
                    heuristic_id="HEUR-NET-001",
                    name="Networking Capability With Network Indicator",
                    category="suspicious_network_indicators",
                    severity=EvidenceSeverity.LOW,
                    confidence=0.64,
                    contribution=0.8,
                    explanation=(
                        "Networking capability appears with network-like strings. This is common "
                        "in benign updaters, browsers, and administration tools."
                    ),
                    supporting_evidence_ids=evidence_by_type.get("API_CAPABILITY", [])
                    + evidence_by_type.get("INTERESTING_STRING", []),
                )
            )

        if evidence_counts.get("SUSPICIOUS_ENTRY_POINT_SECTION", 0) >= 1:
            findings.append(
                HeuristicFinding(
                    heuristic_id="HEUR-PE-001",
                    name="Entry Point In Unusual Section",
                    category="unusual_pe_characteristics",
                    severity=EvidenceSeverity.MEDIUM,
                    confidence=0.68,
                    contribution=0.9,
                    explanation=(
                        "The PE entry point is located in an unusual section. This is relevant "
                        "context, not proof of maliciousness."
                    ),
                    supporting_evidence_ids=evidence_by_type.get(
                        "SUSPICIOUS_ENTRY_POINT_SECTION", []
                    ),
                )
            )

        return findings


def _evidence_ids_by_type(analysis: StaticAnalysisResult) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for evidence in analysis.evidence:
        grouped.setdefault(str(evidence.type), []).append(evidence.evidence_id)
    return grouped
