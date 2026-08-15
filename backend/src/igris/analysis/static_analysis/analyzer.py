"""Deterministic Phase 2 static analysis."""

import hashlib
from collections import Counter
from pathlib import Path

from igris.analysis.static_analysis.pe_features import (
    api_references_from_strings,
    extract_pe_static,
)
from igris.analysis.static_analysis.strings import extract_strings
from igris.analysis.static_analysis.taxonomy import is_interesting_string
from igris.core.config import Settings
from igris.schemas.file_intelligence import DetectedFormat, Sample, SectionMetadata
from igris.schemas.static_analysis import (
    EvidenceSeverity,
    EvidenceType,
    ExtractedString,
    Location,
    NormalizedImport,
    PEStaticFeatures,
    StaticAnalysisResult,
    StaticAnalysisStatus,
    StaticEvidence,
    StaticFeatureVector,
    StaticResource,
)

SUSPICIOUS_SECTION_NAMES = {
    "",
    ".packed",
    ".pack",
    ".upx",
    "upx0",
    "upx1",
    ".aspack",
    ".petite",
    ".themida",
    ".vmp",
}


def analyze_static(sample: Sample, path: Path, settings: Settings) -> StaticAnalysisResult:
    """Run static evidence extraction over a stored sample without execution."""

    data = path.read_bytes()
    file_metadata = sample.file_metadata
    sections = _sections_from_sample(sample)
    strings = extract_strings(
        data,
        min_length=settings.static_min_string_length,
        max_strings=settings.static_max_strings,
        sections=sections,
    )

    imports: list[NormalizedImport] = []
    resources: list[StaticResource] = []
    pe_features: PEStaticFeatures | None = None
    limitations: list[str] = []

    if file_metadata is not None and file_metadata.detected_format == DetectedFormat.PE:
        extracted = extract_pe_static(data, path, sections)
        imports.extend(extracted.imports)
        resources.extend(extracted.resources)
        pe_features = extracted.features
        limitations.extend(extracted.parse_warnings)
    else:
        limitations.append("PE-only static features are not applicable to this format.")

    imports.extend(api_references_from_strings({item.value for item in strings}))
    imports = _deduplicate_imports(imports)
    evidence = _build_evidence(strings, imports, sections, resources, pe_features, settings)
    feature_vector = _feature_vector(
        sample=sample,
        sections=sections,
        imports=imports,
        strings=strings,
        resources=resources,
        pe_features=pe_features,
        evidence=evidence,
    )
    return StaticAnalysisResult(
        sample_id=sample.sample_id,
        status=StaticAnalysisStatus.COMPLETED,
        strings=strings,
        imports=imports,
        resources=resources,
        pe_features=pe_features,
        evidence=evidence,
        feature_vector=feature_vector,
        limitations=limitations,
    )


def _build_evidence(
    strings: list[ExtractedString],
    imports: list[NormalizedImport],
    sections: list[SectionMetadata],
    resources: list[StaticResource],
    pe_features: PEStaticFeatures | None,
    settings: Settings,
) -> list[StaticEvidence]:
    evidence: list[StaticEvidence] = []

    for string in strings:
        if not is_interesting_string(string.category):
            continue
        evidence_type = (
            EvidenceType.SUSPICIOUS_KEYWORD
            if string.category == "suspicious_keyword"
            else EvidenceType.INTERESTING_STRING
        )
        evidence.append(
            _evidence(
                evidence_type,
                source="string_analysis",
                severity=EvidenceSeverity.LOW
                if evidence_type == EvidenceType.INTERESTING_STRING
                else EvidenceSeverity.MEDIUM,
                confidence=0.7,
                description=f"Extracted {string.category} string.",
                details={"value": string.value, "encoding": string.encoding},
                location=Location(offset=string.offset, section=string.section),
                related_object=string.value,
            )
        )

    for imported in imports:
        if imported.category == "other":
            continue
        evidence.append(
            _evidence(
                EvidenceType.API_CAPABILITY,
                source="import_analysis",
                severity=EvidenceSeverity.LOW,
                confidence=0.75 if imported.source == "import_table" else 0.55,
                description=f"Observed {imported.category} API capability.",
                details={
                    "api": imported.name,
                    "module": imported.module,
                    "source": imported.source,
                    "category": imported.category,
                },
                related_object=imported.name,
            )
        )

    evidence.extend(_section_evidence(sections, settings))

    for resource in resources:
        evidence.append(
            _evidence(
                EvidenceType.RESOURCE_PRESENT,
                source="resource_analysis",
                severity=EvidenceSeverity.INFO,
                confidence=0.8,
                description="Embedded PE resource data was observed and hashed without execution.",
                details={
                    "resource_type": resource.resource_type,
                    "identifier": resource.identifier,
                    "size": resource.size,
                    "offset": resource.offset,
                },
                location=Location(offset=resource.offset),
            )
        )

    if pe_features is not None:
        evidence.extend(_pe_feature_evidence(pe_features))

    return _assign_evidence_ids(evidence)


def _section_evidence(sections: list[SectionMetadata], settings: Settings) -> list[StaticEvidence]:
    evidence: list[StaticEvidence] = []
    previous_raw_offset = -1
    for section in sections:
        name = section.name.lower()
        characteristics = int(section.characteristics or "0", 16)
        executable = bool(characteristics & 0x20000000) or ("X" in (section.permissions or ""))
        writable = bool(characteristics & 0x80000000) or ("W" in (section.permissions or ""))
        if name in SUSPICIOUS_SECTION_NAMES or "pack" in name:
            evidence.append(
                _evidence(
                    EvidenceType.UNUSUAL_SECTION_NAME,
                    source="section_analysis",
                    severity=EvidenceSeverity.MEDIUM,
                    confidence=0.72,
                    description="Section name is commonly associated with unusual layouts.",
                    details={"section": section.name},
                    location=Location(offset=section.raw_offset, section=section.name),
                    related_object=section.name,
                )
            )
        if executable and writable:
            evidence.append(
                _evidence(
                    EvidenceType.EXECUTABLE_WRITABLE_SECTION,
                    source="section_analysis",
                    severity=EvidenceSeverity.MEDIUM,
                    confidence=0.82,
                    description="Section is both writable and executable.",
                    details={
                        "section": section.name,
                        "characteristics": section.characteristics,
                        "permissions": section.permissions,
                    },
                    location=Location(offset=section.raw_offset, section=section.name),
                    related_object=section.name,
                )
            )
        if (
            section.entropy is not None
            and section.entropy >= settings.static_high_entropy_threshold
        ):
            evidence.append(
                _evidence(
                    EvidenceType.HIGH_ENTROPY_SECTION,
                    source="section_analysis",
                    severity=EvidenceSeverity.MEDIUM,
                    confidence=0.78,
                    description="Section has high Shannon entropy.",
                    details={"section": section.name, "entropy": section.entropy},
                    location=Location(offset=section.raw_offset, section=section.name),
                    related_object=section.name,
                )
            )
            evidence.append(
                _evidence(
                    EvidenceType.POSSIBLE_PACKING_INDICATOR,
                    source="packing_indicators",
                    severity=EvidenceSeverity.LOW,
                    confidence=0.62,
                    description="High section entropy is a possible packing indicator.",
                    details={"section": section.name, "entropy": section.entropy},
                    location=Location(offset=section.raw_offset, section=section.name),
                    related_object=section.name,
                )
            )
        if (
            section.raw_size
            and section.virtual_size
            and section.virtual_size > section.raw_size * 8
        ):
            evidence.append(
                _evidence(
                    EvidenceType.SUSPICIOUS_SIZE_RELATIONSHIP,
                    source="section_analysis",
                    severity=EvidenceSeverity.LOW,
                    confidence=0.6,
                    description="Section virtual size is much larger than raw size.",
                    details={
                        "section": section.name,
                        "virtual_size": section.virtual_size,
                        "raw_size": section.raw_size,
                    },
                    location=Location(offset=section.raw_offset, section=section.name),
                    related_object=section.name,
                )
            )
        if section.raw_offset is not None and section.raw_offset < previous_raw_offset:
            evidence.append(
                _evidence(
                    EvidenceType.POSSIBLE_PACKING_INDICATOR,
                    source="section_analysis",
                    severity=EvidenceSeverity.LOW,
                    confidence=0.58,
                    description="Section raw offsets are not in ascending order.",
                    details={"section": section.name, "raw_offset": section.raw_offset},
                    location=Location(offset=section.raw_offset, section=section.name),
                    related_object=section.name,
                )
            )
        if section.raw_offset is not None:
            previous_raw_offset = section.raw_offset
    return evidence


def _pe_feature_evidence(pe_features: PEStaticFeatures) -> list[StaticEvidence]:
    evidence: list[StaticEvidence] = []
    if pe_features.overlay_present:
        evidence.append(
            _evidence(
                EvidenceType.OVERLAY_PRESENT,
                source="pe_features",
                severity=EvidenceSeverity.LOW,
                confidence=0.7,
                description="Data exists after the final PE section.",
                details={"overlay_size": pe_features.overlay_size},
            )
        )
    if pe_features.tls_callbacks_present:
        evidence.append(
            _evidence(
                EvidenceType.TLS_CALLBACK_DIRECTORY_PRESENT,
                source="pe_features",
                severity=EvidenceSeverity.LOW,
                confidence=0.7,
                description="PE TLS directory is present; callbacks may run before entry point.",
                details={},
            )
        )
    if pe_features.writable_executable_section_count:
        evidence.append(
            _evidence(
                EvidenceType.POSSIBLE_PACKING_INDICATOR,
                source="packing_indicators",
                severity=EvidenceSeverity.LOW,
                confidence=0.66,
                description="Writable executable sections are a possible packing indicator.",
                details={"count": pe_features.writable_executable_section_count},
            )
        )
    if pe_features.suspicious_entry_point_section:
        evidence.append(
            _evidence(
                EvidenceType.SUSPICIOUS_ENTRY_POINT_SECTION,
                source="pe_features",
                severity=EvidenceSeverity.MEDIUM,
                confidence=0.68,
                description="Entry point falls in an unusual section.",
                details={"entry_point_section": pe_features.entry_point_section},
                related_object=pe_features.entry_point_section,
            )
        )
    return evidence


def _feature_vector(
    *,
    sample: Sample,
    sections: list[SectionMetadata],
    imports: list[NormalizedImport],
    strings: list[ExtractedString],
    resources: list[StaticResource],
    pe_features: PEStaticFeatures | None,
    evidence: list[StaticEvidence],
) -> StaticFeatureVector:
    entropies = [section.entropy for section in sections if section.entropy is not None]
    api_counts = Counter(str(imported.category) for imported in imports)
    string_counts = Counter(str(string.category) for string in strings)
    evidence_counts = Counter(str(item.type) for item in evidence)
    return StaticFeatureVector(
        file_size=sample.size_bytes,
        number_of_sections=len(sections),
        entropy_min=min(entropies) if entropies else None,
        entropy_max=max(entropies) if entropies else None,
        entropy_mean=round(sum(entropies) / len(entropies), 6) if entropies else None,
        import_count=len(imports),
        api_category_counts=dict(sorted(api_counts.items())),
        string_counts=dict(sorted(string_counts.items())),
        resource_count=len(resources),
        overlay_size=pe_features.overlay_size if pe_features is not None else 0,
        executable_section_count=(
            pe_features.executable_section_count
            if pe_features is not None
            else _count_executable(sections)
        ),
        writable_executable_section_count=(
            pe_features.writable_executable_section_count
            if pe_features is not None
            else _count_writable_executable(sections)
        ),
        evidence_counts=dict(sorted(evidence_counts.items())),
    )


def _sections_from_sample(sample: Sample) -> list[SectionMetadata]:
    metadata = sample.file_metadata
    if metadata is None:
        return []
    if metadata.pe is not None:
        return metadata.pe.sections
    if metadata.elf is not None:
        return metadata.elf.sections
    return []


def _deduplicate_imports(imports: list[NormalizedImport]) -> list[NormalizedImport]:
    seen: set[tuple[str | None, str, str]] = set()
    unique: list[NormalizedImport] = []
    for imported in imports:
        key = (imported.module, imported.name, imported.source)
        if key in seen:
            continue
        unique.append(imported)
        seen.add(key)
    return unique


def _count_executable(sections: list[SectionMetadata]) -> int:
    return sum(
        1
        for section in sections
        if int(section.characteristics or "0", 16) & 0x20000000
        or "X" in (section.permissions or "")
    )


def _count_writable_executable(sections: list[SectionMetadata]) -> int:
    count = 0
    for section in sections:
        characteristics = int(section.characteristics or "0", 16)
        executable = bool(characteristics & 0x20000000) or "X" in (section.permissions or "")
        writable = bool(characteristics & 0x80000000) or "W" in (section.permissions or "")
        count += int(executable and writable)
    return count


def _assign_evidence_ids(evidence: list[StaticEvidence]) -> list[StaticEvidence]:
    assigned: list[StaticEvidence] = []
    for item in evidence:
        digest = hashlib.sha256(
            f"{item.type}|{item.source}|{item.related_object}|{item.location}".encode()
        ).hexdigest()[:16]
        assigned.append(item.model_copy(update={"evidence_id": f"ev-{digest}"}))
    return assigned


def _evidence(
    evidence_type: EvidenceType,
    *,
    source: str,
    severity: EvidenceSeverity,
    confidence: float,
    description: str,
    details: dict[str, object],
    location: Location | None = None,
    related_object: str | None = None,
) -> StaticEvidence:
    return StaticEvidence(
        evidence_id="pending",
        type=evidence_type,
        source=source,
        severity=severity,
        confidence=confidence,
        description=description,
        technical_details=details,
        location=location,
        related_object=related_object,
    )
