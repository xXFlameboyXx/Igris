"""Evidence-driven capability and ATT&CK mapping."""

import hashlib
import json
from collections import Counter
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

from igris.core.errors import AppError
from igris.schemas.behavior_analysis import BehaviorAnalysisResult, BehaviorEvidence
from igris.schemas.reverse_analysis import FunctionEvidence
from igris.schemas.static_analysis import ExtractedString, NormalizedImport, StaticEvidence
from igris.schemas.threat_intelligence import (
    AssessmentLabel,
    BehaviorHypothesis,
    Capability,
    CapabilityCategory,
    EvidenceGraph,
    EvidenceGraphEdge,
    EvidenceGraphNode,
    EvidenceMapping,
    IntelligenceStatus,
    Technique,
    TechniqueEvidenceItem,
    ThreatAssessment,
)


class MappingRule(BaseModel):
    """Data-driven ATT&CK mapping rule."""

    model_config = ConfigDict(extra="ignore")

    mapping_id: str
    capability: CapabilityCategory
    label: AssessmentLabel = AssessmentLabel.POSSIBLE
    capability_confidence: float = Field(ge=0.0, le=1.0)
    technique_id: str
    technique_name: str
    subtechnique_id: str | None = None
    subtechnique_name: str | None = None
    tactic: str | None = None
    description: str = ""
    how_it_works: str = ""
    why_igris_mapped: str = ""
    hypothesis: str = ""
    source_engine: str
    explanation: str = ""
    required_evidence_types: list[str] = Field(default_factory=list)
    required_reverse_evidence_types: list[str] = Field(default_factory=list)
    required_behavior_evidence_types: list[str] = Field(default_factory=list)
    required_string_categories: list[str] = Field(default_factory=list)
    required_string_categories_any: list[str] = Field(default_factory=list)
    required_api_categories: list[str] = Field(default_factory=list)
    keyword_any: list[str] = Field(default_factory=list)
    minimum_evidence_count: int = 1


class MappingDataset(BaseModel):
    """Versioned ATT&CK mapping dataset."""

    model_config = ConfigDict(extra="forbid")

    mapping_version: str
    attack_version: str
    rules: list[MappingRule]


DATASET_ADAPTER = TypeAdapter(MappingDataset)


def load_mapping_dataset(path: Path) -> MappingDataset:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return DATASET_ADAPTER.validate_python(raw)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise AppError(
            "ATT&CK mapping dataset failed validation",
            code="attack_mapping_invalid",
            status_code=500,
            details={"path": str(path), "reason": str(exc)},
        ) from exc


def build_threat_assessment(
    *,
    sample_id: str,
    engine_version: str,
    dataset: MappingDataset,
    static_evidence: list[StaticEvidence],
    strings: list[ExtractedString],
    imports: list[NormalizedImport],
    reverse_evidence: list[FunctionEvidence],
    behavior_analysis: BehaviorAnalysisResult | None = None,
) -> ThreatAssessment:
    capabilities: list[Capability] = []
    techniques: list[Technique] = []
    mappings: list[EvidenceMapping] = []

    behavior_evidence = behavior_analysis.evidence if behavior_analysis is not None else []

    for rule in dataset.rules:
        matched_ids, evidence_items = _matched_evidence_and_items(
            rule,
            static_evidence,
            strings,
            imports,
            reverse_evidence,
            behavior_evidence,
            behavior_analysis,
        )
        if not matched_ids:
            continue
        capability = _capability_from_rule(rule, matched_ids)
        technique = _technique_from_rule(rule, matched_ids, evidence_items, dataset.mapping_version)
        mapping = _evidence_mapping(
            rule, matched_ids, capability.capability_id, technique.technique_id
        )
        capabilities.append(capability)
        techniques.append(technique)
        mappings.append(mapping)

    capabilities = _merge_capabilities(capabilities)
    hypotheses = _behavior_hypotheses(capabilities, techniques)
    graph = _build_graph(
        static_evidence, reverse_evidence, behavior_evidence, capabilities, techniques, mappings
    )
    narrative = _narrative(capabilities, techniques, hypotheses)
    status = (
        IntelligenceStatus.COMPLETED
        if capabilities or techniques
        else IntelligenceStatus.INSUFFICIENT_EVIDENCE
    )
    return ThreatAssessment(
        sample_id=sample_id,
        status=status,
        engine_version=engine_version,
        attack_mapping_version=f"{dataset.mapping_version}; {dataset.attack_version}",
        capabilities=capabilities,
        techniques=techniques,
        attack_techniques=techniques,
        evidence_mappings=mappings,
        behavior_hypotheses=hypotheses,
        evidence_graph=graph,
        narrative=narrative,
        limitations=[
            "Mappings are evidence-driven hypotheses, not proof of malicious behavior.",
            "ATT&CK mappings use a local versioned dataset and do not imply actor attribution.",
            "Behavior mappings use only cached behavior-analysis results and do not launch "
            "sample execution or sandbox infrastructure.",
            "Similarity, if added later, is not attribution.",
        ],
    )


def _matched_evidence_and_items(
    rule: MappingRule,
    static_evidence: list[StaticEvidence],
    strings: list[ExtractedString],
    imports: list[NormalizedImport],
    reverse_evidence: list[FunctionEvidence],
    behavior_evidence: list[BehaviorEvidence],
    behavior_analysis: BehaviorAnalysisResult | None = None,
) -> tuple[list[str], list[TechniqueEvidenceItem]]:
    matched_ids: list[str] = []
    evidence_items: list[TechniqueEvidenceItem] = []
    seen_keys: set[str] = set()

    evidence_by_type = _ids_by_type(static_evidence)
    reverse_by_type = _reverse_ids_by_type(reverse_evidence)
    behavior_by_type = _behavior_ids_by_type(behavior_evidence)
    string_values = [item.value.lower() for item in strings]
    string_categories = Counter(str(item.category) for item in strings)
    api_categories = Counter(str(item.category) for item in imports)

    # 1. Required static evidence
    for evidence_type in rule.required_evidence_types:
        ids = evidence_by_type.get(evidence_type, [])
        if len(ids) < rule.minimum_evidence_count:
            return [], []
        matched_ids.extend(ids)
        for ev in static_evidence:
            if str(ev.type) == evidence_type:
                val = (
                    ev.technical_details.get("value")
                    or ev.technical_details.get("section")
                    or ev.technical_details.get("api")
                )
                if not val and "entropy" in ev.technical_details:
                    val = f"Entropy {ev.technical_details['entropy']}"
                key = f"static:{ev.type}:{val or ev.description}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    evidence_items.append(
                        TechniqueEvidenceItem(
                            evidence_id=ev.evidence_id,
                            category="static",
                            evidence_type=str(ev.type),
                            statement=ev.description,
                            value=str(val) if val else None,
                            observation_level=AssessmentLabel.OBSERVED,
                            strength=str(ev.severity).upper(),
                            source=ev.source,
                        )
                    )

    # 2. Required reverse evidence
    for evidence_type in rule.required_reverse_evidence_types:
        ids = reverse_by_type.get(evidence_type, [])
        if not ids:
            return [], []
        matched_ids.extend(ids)
        for rev in reverse_evidence:
            if str(rev.type) == evidence_type:
                val = (", ".join(rev.related_apis) if rev.related_apis else None) or rev.function_id
                key = f"reverse:{rev.type}:{val}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    evidence_items.append(
                        TechniqueEvidenceItem(
                            evidence_id=rev.evidence_id,
                            category="reverse",
                            evidence_type=str(rev.type),
                            statement=rev.description,
                            value=str(val) if val else None,
                            observation_level=AssessmentLabel.INFERRED,
                            strength="HIGH" if rev.confidence >= 0.7 else "MEDIUM",
                            source="reverse_analysis",
                        )
                    )

    # 3. Required behavior evidence
    for evidence_type in rule.required_behavior_evidence_types:
        ids = behavior_by_type.get(evidence_type, [])
        if not ids:
            return [], []
        matched_ids.extend(ids)
        for beh in behavior_evidence:
            if str(beh.type) == evidence_type:
                val = (
                    beh.technical_details.get("key")
                    or beh.technical_details.get("destination")
                    or beh.technical_details.get("path")
                    or beh.technical_details.get("process")
                    or beh.related_process
                )
                key = f"behavior:{beh.type}:{val or beh.description}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    obs_lvl = (
                        AssessmentLabel.OBSERVED
                        if (
                            behavior_analysis
                            and behavior_analysis.sandbox_metadata
                            and behavior_analysis.sandbox_metadata.analysis_mode == "sandbox"
                        )
                        else AssessmentLabel.POSSIBLE
                    )
                    evidence_items.append(
                        TechniqueEvidenceItem(
                            evidence_id=beh.evidence_id,
                            category="behavior",
                            evidence_type=str(beh.type),
                            statement=beh.description,
                            value=str(val) if val else None,
                            observation_level=obs_lvl,
                            strength=str(beh.severity).upper(),
                            source="behavior_analysis",
                        )
                    )

    # 4. Required string categories
    for category in rule.required_string_categories:
        if string_categories.get(category, 0) < 1:
            return [], []
        matched_strings = [
            s
            for s in strings
            if str(s.category) == category
            and (
                not rule.keyword_any or any(k.lower() in s.value.lower() for k in rule.keyword_any)
            )
        ]
        if rule.keyword_any and not matched_strings:
            return [], []
        for s in matched_strings:
            s_id = f"str-{_digest(str(s.offset) + s.value)}"
            matched_ids.append(s_id)
            key = f"string:{category}:{s.value}"
            if key not in seen_keys:
                seen_keys.add(key)
                evidence_items.append(
                    TechniqueEvidenceItem(
                        evidence_id=s_id,
                        category="static",
                        evidence_type="extracted_string",
                        statement=f"Extracted {s.category} string: {s.value}",
                        value=s.value,
                        observation_level=AssessmentLabel.OBSERVED,
                        strength="MEDIUM",
                        source="static_analysis",
                    )
                )

    # 5. Required string categories any
    if rule.required_string_categories_any:
        matched_any = [
            s
            for s in strings
            if str(s.category) in rule.required_string_categories_any
            and (
                not rule.keyword_any or any(k.lower() in s.value.lower() for k in rule.keyword_any)
            )
        ]
        if not matched_any:
            return [], []
        for s in matched_any:
            s_id = f"str-{_digest(str(s.offset) + s.value)}"
            matched_ids.append(s_id)
            key = f"string:{s.category}:{s.value}"
            if key not in seen_keys:
                seen_keys.add(key)
                evidence_items.append(
                    TechniqueEvidenceItem(
                        evidence_id=s_id,
                        category="static",
                        evidence_type="extracted_string",
                        statement=f"Extracted {s.category} string: {s.value}",
                        value=s.value,
                        observation_level=AssessmentLabel.OBSERVED,
                        strength="MEDIUM",
                        source="static_analysis",
                    )
                )

    # 6. Required API categories
    for category in rule.required_api_categories:
        if api_categories.get(category, 0) < 1:
            return [], []
        matched_apis = [imp for imp in imports if str(imp.category) == category]
        for imp in matched_apis:
            api_id = f"api-{_digest((imp.module or '') + imp.name)}"
            matched_ids.append(api_id)
            key = f"api:{category}:{imp.name}"
            if key not in seen_keys:
                seen_keys.add(key)
                mod_str = f" ({imp.module})" if imp.module else ""
                evidence_items.append(
                    TechniqueEvidenceItem(
                        evidence_id=api_id,
                        category="static",
                        evidence_type="imported_api",
                        statement=f"Imported API: {imp.name}{mod_str}",
                        value=imp.name,
                        observation_level=AssessmentLabel.OBSERVED,
                        strength="MEDIUM",
                        source="static_analysis",
                    )
                )

    # 7. Keyword check if not checked by string categories
    if (
        rule.keyword_any
        and not rule.required_string_categories
        and not rule.required_string_categories_any
    ):
        if not any(
            keyword.lower() in value for keyword in rule.keyword_any for value in string_values
        ):
            return [], []
        for s in strings:
            if any(k.lower() in s.value.lower() for k in rule.keyword_any):
                s_id = f"str-{_digest(str(s.offset) + s.value)}"
                matched_ids.append(s_id)
                key = f"string:keyword:{s.value}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    evidence_items.append(
                        TechniqueEvidenceItem(
                            evidence_id=s_id,
                            category="static",
                            evidence_type="extracted_string",
                            statement=f"Extracted {s.category} string: {s.value}",
                            value=s.value,
                            observation_level=AssessmentLabel.OBSERVED,
                            strength="MEDIUM",
                            source="static_analysis",
                        )
                    )

    if not matched_ids:
        return [], []
    return sorted(set(matched_ids)), evidence_items


def _capability_from_rule(rule: MappingRule, evidence_ids: list[str]) -> Capability:
    capability_id = f"cap-{_digest(rule.mapping_id + str(rule.capability))}"
    return Capability(
        capability_id=capability_id,
        category=rule.capability,
        name=str(rule.capability),
        label=rule.label,
        confidence=rule.capability_confidence,
        evidence_ids=evidence_ids,
        supporting_evidence_ids=evidence_ids,
        source_engines=sorted({rule.source_engine}),
        explanation=rule.explanation,
        description=rule.explanation,
    )


def _technique_from_rule(
    rule: MappingRule,
    evidence_ids: list[str],
    evidence_items: list[TechniqueEvidenceItem],
    mapping_version: str,
) -> Technique:
    why_mapped = (
        rule.why_igris_mapped
        or f"IGRIS identified technical evidence associated with {rule.technique_name}."
    )

    base_hypothesis = (
        rule.hypothesis or f"the specimen may exhibit {rule.technique_name} capabilities"
    )
    clean_hypothesis = base_hypothesis.rstrip(".")
    if rule.label == AssessmentLabel.OBSERVED:
        hypothesis_statement = (
            f"The analysis directly observed evidence indicating that {clean_hypothesis}."
        )
    elif rule.label == AssessmentLabel.INFERRED:
        hypothesis_statement = (
            f"The available evidence supports an inferred hypothesis that {clean_hypothesis}."
        )
    else:
        hypothesis_statement = (
            f"Technical indicators suggest a possible relationship where {clean_hypothesis}, "
            "though available evidence does not establish confirmed execution."
        )

    return Technique(
        technique_id=rule.technique_id,
        technique_name=rule.technique_name,
        tactic=rule.capability,
        subtechnique_id=rule.subtechnique_id,
        subtechnique_name=rule.subtechnique_name,
        description=rule.description or rule.explanation,
        how_it_works=rule.how_it_works or rule.explanation,
        why_igris_mapped=why_mapped,
        hypothesis=hypothesis_statement,
        label=rule.label,
        confidence=rule.capability_confidence,
        source_engine=rule.source_engine,
        explanation=why_mapped,
        mapping_version=mapping_version,
        evidence_ids=evidence_ids,
        supporting_evidence_ids=evidence_ids,
        supporting_evidence=evidence_items,
    )


def _evidence_mapping(
    rule: MappingRule, evidence_ids: list[str], capability_id: str, technique_id: str
) -> EvidenceMapping:
    mapping_id = f"map-{_digest(rule.mapping_id + '|'.join(evidence_ids))}"
    return EvidenceMapping(
        mapping_id=mapping_id,
        observation_ids=evidence_ids,
        indicator_ids=evidence_ids,
        capability_id=capability_id,
        technique_id=technique_id,
        confidence=rule.capability_confidence,
        explanation=rule.explanation,
    )


def _merge_capabilities(capabilities: list[Capability]) -> list[Capability]:
    merged: dict[CapabilityCategory, Capability] = {}
    for capability in capabilities:
        existing = merged.get(capability.category)
        if existing is None:
            merged[capability.category] = capability
            continue
        evidence_ids = sorted(set(existing.evidence_ids + capability.evidence_ids))
        source_engines = sorted(set(existing.source_engines + capability.source_engines))
        label = _stronger_label(existing.label, capability.label)
        merged[capability.category] = existing.model_copy(
            update={
                "label": label,
                "confidence": max(existing.confidence, capability.confidence),
                "evidence_ids": evidence_ids,
                "source_engines": source_engines,
                "explanation": f"{existing.explanation} {capability.explanation}",
            }
        )
    return sorted(merged.values(), key=lambda item: item.category)


def _behavior_hypotheses(
    capabilities: list[Capability], techniques: list[Technique]
) -> list[BehaviorHypothesis]:
    hypotheses: list[BehaviorHypothesis] = []
    techniques_by_tactic: dict[CapabilityCategory, list[str]] = {}
    for technique in techniques:
        techniques_by_tactic.setdefault(technique.tactic, []).append(technique.technique_id)
    for capability in capabilities:
        statement = (
            f"{capability.label}: evidence supports {capability.category} capability context. "
            f"{capability.explanation}"
        )
        hypotheses.append(
            BehaviorHypothesis(
                hypothesis_id=f"hyp-{_digest(capability.capability_id)}",
                label=capability.label,
                statement=statement,
                confidence=capability.confidence,
                supporting_capability_ids=[capability.capability_id],
                supporting_technique_ids=sorted(
                    set(techniques_by_tactic.get(capability.category, []))
                ),
            )
        )
    return hypotheses


def _build_graph(
    static_evidence: list[StaticEvidence],
    reverse_evidence: list[FunctionEvidence],
    behavior_evidence: list[BehaviorEvidence],
    capabilities: list[Capability],
    techniques: list[Technique],
    mappings: list[EvidenceMapping],
) -> EvidenceGraph:
    nodes: dict[str, EvidenceGraphNode] = {}
    edges: list[EvidenceGraphEdge] = []
    for static_item in static_evidence:
        nodes[static_item.evidence_id] = EvidenceGraphNode(
            node_id=static_item.evidence_id,
            node_type="Observation",
            label=str(static_item.type),
            details={"source": static_item.source, "confidence": static_item.confidence},
        )
    for reverse_item in reverse_evidence:
        nodes[reverse_item.evidence_id] = EvidenceGraphNode(
            node_id=reverse_item.evidence_id,
            node_type="Observation",
            label=str(reverse_item.type),
            details={
                "function_id": reverse_item.function_id,
                "confidence": reverse_item.confidence,
            },
        )
    for behavior_item in behavior_evidence:
        nodes[behavior_item.evidence_id] = EvidenceGraphNode(
            node_id=behavior_item.evidence_id,
            node_type="Observation",
            label=str(behavior_item.type),
            details={
                "source": behavior_item.source,
                "confidence": behavior_item.confidence,
                "severity": str(behavior_item.severity),
            },
        )
    for capability in capabilities:
        nodes[capability.capability_id] = EvidenceGraphNode(
            node_id=capability.capability_id,
            node_type="Capability",
            label=str(capability.category),
            details={"label": str(capability.label), "confidence": capability.confidence},
        )
    for technique in techniques:
        nodes[technique.technique_id] = EvidenceGraphNode(
            node_id=technique.technique_id,
            node_type="ATTACKTechnique",
            label=f"{technique.technique_id} {technique.technique_name}",
            details={"tactic": str(technique.tactic), "confidence": technique.confidence},
        )
    for mapping in mappings:
        indicator_node_ids: list[str] = []
        for indicator_id in mapping.indicator_ids:
            node_id = f"indicator:{indicator_id}"
            indicator_node_ids.append(node_id)
            nodes.setdefault(
                node_id,
                EvidenceGraphNode(
                    node_id=node_id,
                    node_type="Indicator",
                    label=indicator_id,
                    details={"mapping_id": mapping.mapping_id},
                ),
            )

        for observation_id in mapping.observation_ids:
            nodes.setdefault(
                observation_id,
                EvidenceGraphNode(
                    node_id=observation_id,
                    node_type="Observation",
                    label=observation_id,
                    details={"source": "derived_indicator"},
                ),
            )
            for indicator_node_id in indicator_node_ids:
                edges.append(
                    EvidenceGraphEdge(
                        source=observation_id,
                        target=indicator_node_id,
                        relationship="produces_indicator",
                        confidence=mapping.confidence,
                    )
                )

        for indicator_node_id in indicator_node_ids:
            edges.append(
                EvidenceGraphEdge(
                    source=indicator_node_id,
                    target=mapping.capability_id,
                    relationship="supports_capability",
                    confidence=mapping.confidence,
                )
            )

        if mapping.technique_id is not None:
            edges.append(
                EvidenceGraphEdge(
                    source=mapping.capability_id,
                    target=mapping.technique_id,
                    relationship="maps_to_attack_technique",
                    confidence=mapping.confidence,
                )
            )
    return EvidenceGraph(nodes=list(nodes.values()), edges=edges)


def _narrative(
    capabilities: list[Capability],
    techniques: list[Technique],
    hypotheses: list[BehaviorHypothesis],
) -> str:
    if not capabilities:
        return (
            "OBSERVED: The available static and reverse-engineering evidence is insufficient "
            "to support a higher-level capability assessment. INFERRED: No ATT&CK mapping is "
            "made. POSSIBLE: Additional dynamic or similarity analysis in later phases may "
            "provide more context."
        )
    capability_text = ", ".join(str(item.category) for item in capabilities)
    technique_text = ", ".join(f"{item.technique_id} {item.technique_name}" for item in techniques)
    hypothesis_text = " ".join(item.statement for item in hypotheses)
    return (
        f"OBSERVED: Igris found technical evidence associated with {capability_text}. "
        f"INFERRED: Evidence-driven ATT&CK mappings include {technique_text}. "
        f"POSSIBLE: {hypothesis_text} These are hypotheses, not actor attribution or proof "
        "of malicious behavior."
    )


def _ids_by_type(evidence: list[StaticEvidence]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for item in evidence:
        grouped.setdefault(str(item.type), []).append(item.evidence_id)
    return grouped


def _reverse_ids_by_type(evidence: list[FunctionEvidence]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for item in evidence:
        grouped.setdefault(str(item.type), []).append(item.evidence_id)
    return grouped


def _behavior_ids_by_type(evidence: list[BehaviorEvidence]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for item in evidence:
        grouped.setdefault(str(item.type), []).append(item.evidence_id)
    return grouped


def _string_indicator_ids(strings: list[ExtractedString], category: str) -> list[str]:
    return [
        f"string-{_digest(str(item.offset) + item.value)}"
        for item in strings
        if str(item.category) == category
    ]


def _api_indicator_ids(imports: list[NormalizedImport], category: str) -> list[str]:
    return [
        f"api-{_digest((item.module or '') + item.name)}"
        for item in imports
        if str(item.category) == category
    ]


def _stronger_label(left: AssessmentLabel, right: AssessmentLabel) -> AssessmentLabel:
    rank = {
        AssessmentLabel.OBSERVED: 3,
        AssessmentLabel.INFERRED: 2,
        AssessmentLabel.POSSIBLE: 1,
    }
    return left if rank[left] >= rank[right] else right


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]
