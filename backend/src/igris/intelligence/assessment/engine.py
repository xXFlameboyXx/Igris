"""Phase 11: Explainable Malware Assessment Engine.

Aggregates independent evidence, tracks epistemology (Observed vs Inferred vs Possible),
detects contradictions, calculates deterministic evidence scores, evaluates confidence,
and computes explainable verdicts without attribution leaps.
"""

from datetime import UTC, datetime

from igris.schemas.assessment import (
    AssessmentEvidenceItem,
    AssessmentVerdict,
    ConfidenceBreakdown,
    ConfidenceLevel,
    EvidenceCategory,
    EvidenceRole,
    EvidenceStrength,
    EvidenceSummary,
    ExplainableAssessment,
    ObservationLevel,
    RiskFactor,
    RiskLevel,
    RiskScoreDetails,
    UncertaintyItem,
)
from igris.schemas.file_intelligence import Sample
from igris.schemas.ml import MLLabel


class AssessmentEngine:
    """Core analytical intelligence engine synthesizing multi-layer evidence into verdicts."""

    def assess(self, sample: Sample) -> ExplainableAssessment:
        """Run deterministic explainable malware assessment across attached analysis artifacts."""
        evidence_items: list[AssessmentEvidenceItem] = []
        uncertainties: list[UncertaintyItem] = []
        disagreements: list[str] = []

        # 1. Collect Evidence from all available analysis layers
        self._collect_file_and_static_evidence(sample, evidence_items, uncertainties)
        self._collect_reverse_evidence(sample, evidence_items, uncertainties)
        self._collect_behavior_evidence(sample, evidence_items, uncertainties)
        self._collect_detection_evidence(sample, evidence_items, uncertainties)
        self._collect_ml_evidence(sample, evidence_items, uncertainties)
        self._collect_similarity_evidence(sample, evidence_items, uncertainties)

        # 2. Contradiction & Disagreement Analysis
        self._detect_disagreements(sample, evidence_items, disagreements)

        # 3. Deterministic Risk Score Calculation
        risk_score_details = self._calculate_risk_score(sample, evidence_items, uncertainties)

        # 4. Deterministic Verdict Logic
        verdict, risk_level = self._determine_verdict(
            sample, evidence_items, risk_score_details, uncertainties
        )

        # 5. Multi-dimensional Confidence Evaluation
        confidence = self._evaluate_confidence(sample, verdict, evidence_items, uncertainties)

        # 6. Construct Evidence Summary
        supporting = [e for e in evidence_items if e.role == EvidenceRole.SUPPORTING]
        contradicting = [e for e in evidence_items if e.role == EvidenceRole.CONTRADICTING]
        neutral = [e for e in evidence_items if e.role == EvidenceRole.NEUTRAL]
        observed = [e for e in evidence_items if e.observation_level == ObservationLevel.OBSERVED]
        inferred = [e for e in evidence_items if e.observation_level == ObservationLevel.INFERRED]
        possible = [e for e in evidence_items if e.observation_level == ObservationLevel.POSSIBLE]

        evidence_summary = EvidenceSummary(
            sample_id=sample.sample_id,
            sha256=sample.hashes.sha256,
            total_evidence_count=len(evidence_items),
            supporting_count=len(supporting),
            contradicting_count=len(contradicting),
            neutral_count=len(neutral),
            observed_count=len(observed),
            inferred_count=len(inferred),
            possible_count=len(possible),
            evidence_items=evidence_items,
            disagreements=disagreements,
            uncertainties=uncertainties,
            created_at=datetime.now(UTC),
        )

        # 7. Generate Human Explanation
        from igris.intelligence.assessment.explanation import generate_human_explanation

        explanation = generate_human_explanation(
            verdict=verdict,
            risk_level=risk_level,
            risk_score=risk_score_details,
            confidence=confidence,
            evidence_summary=evidence_summary,
            disagreements=disagreements,
        )

        # 8. Analytical Limitations
        limitations = [
            "Verdict reflects technical assessment and does not constitute absolute proof.",
            (
                "Attribution metrics evaluate similarity clusters and NEVER establish confirmed "
                "malware family or threat actor identity."
            ),
            "Unobserved telemetry categories represent unknown factors, not negative proof.",
        ]

        return ExplainableAssessment(
            sample_id=sample.sample_id,
            sha256=sample.hashes.sha256,
            schema_version="assessment/v1",
            created_at=datetime.now(UTC),
            verdict=verdict,
            risk_level=risk_level,
            risk_score=risk_score_details,
            confidence=confidence,
            explanation=explanation,
            evidence_summary=evidence_summary,
            limitations=limitations,
            provenance="explainable_assessment_engine:v1",
        )

    def _collect_file_and_static_evidence(
        self,
        sample: Sample,
        evidence_items: list[AssessmentEvidenceItem],
        uncertainties: list[UncertaintyItem],
    ) -> None:
        """Extract traceable static and structural file evidence."""
        if sample.file_metadata is None:
            uncertainties.append(
                UncertaintyItem(
                    category="file_intelligence",
                    reason="Foundational file metadata extraction unperformed or failed.",
                    impact="Binary format, section layout, and file hashes unavailable.",
                )
            )
        else:
            # Check for suspicious PE / ELF sections
            if sample.file_metadata.pe:
                for sec in sample.file_metadata.pe.sections:
                    perms = (sec.permissions or "").lower()
                    is_wx = ("w" in perms or "write" in perms) and ("x" in perms or "exec" in perms)
                    if is_wx:
                        evidence_items.append(
                            AssessmentEvidenceItem(
                                evidence_id=f"ev-static-sec-{sec.name.strip()}",
                                category=EvidenceCategory.STATIC,
                                source="static_analysis.pe_headers",
                                source_id=sec.name.strip(),
                                statement=(
                                    f"Section '{sec.name.strip()}' has both Writable "
                                    f"and Executable permissions (W+X)."
                                ),
                                evidence_type="suspicious_section_permissions",
                                observation_level=ObservationLevel.OBSERVED,
                                role=EvidenceRole.SUPPORTING,
                                strength=EvidenceStrength.HIGH,
                                weight=0.85,
                                provenance="pe_header_parser",
                                technical_details={
                                    "entropy": sec.entropy,
                                    "raw_size": sec.raw_size,
                                },
                            )
                        )
                    elif sec.entropy and sec.entropy > 7.2:
                        evidence_items.append(
                            AssessmentEvidenceItem(
                                evidence_id=f"ev-static-ent-{sec.name.strip()}",
                                category=EvidenceCategory.STATIC,
                                source="static_analysis.pe_headers",
                                source_id=sec.name.strip(),
                                statement=(
                                    f"Section '{sec.name.strip()}' exhibits very high "
                                    f"entropy ({round(sec.entropy, 2)}), suggesting packing."
                                ),
                                evidence_type="high_entropy_section",
                                observation_level=ObservationLevel.OBSERVED,
                                role=EvidenceRole.SUPPORTING,
                                strength=EvidenceStrength.MEDIUM,
                                weight=0.70,
                                provenance="pe_header_parser",
                                technical_details={"entropy": sec.entropy},
                            )
                        )

        if sample.static_analysis is None:
            uncertainties.append(
                UncertaintyItem(
                    category="static_analysis",
                    reason="Static analysis has not been executed on this sample.",
                    impact="Extracted strings, imports, and static indicators unknown.",
                )
            )
        else:
            # Extract static evidence observations
            for ev in sample.static_analysis.evidence:
                is_suspicious = ev.severity.value in ("medium", "high", "critical")
                role = EvidenceRole.SUPPORTING if is_suspicious else EvidenceRole.NEUTRAL
                evidence_items.append(
                    AssessmentEvidenceItem(
                        evidence_id=ev.evidence_id,
                        category=EvidenceCategory.STATIC,
                        source=ev.source,
                        source_id=ev.related_object,
                        statement=ev.description,
                        evidence_type=ev.type.value,
                        observation_level=ObservationLevel.OBSERVED,
                        role=role,
                        strength=EvidenceStrength(ev.severity.value.upper())
                        if is_suspicious
                        else EvidenceStrength.LOW,
                        weight=ev.confidence,
                        provenance=f"static_engine:{ev.source}",
                        technical_details=ev.technical_details,
                    )
                )

    def _collect_reverse_evidence(
        self,
        sample: Sample,
        evidence_items: list[AssessmentEvidenceItem],
        uncertainties: list[UncertaintyItem],
    ) -> None:
        """Extract reverse engineering and disassembly evidence."""
        if sample.reverse_analysis is None:
            uncertainties.append(
                UncertaintyItem(
                    category="reverse_analysis",
                    reason="Reverse engineering and disassembly analysis unperformed.",
                    impact="Function CFGs, cyclomatic complexity, and call hierarchies unobserved.",
                )
            )
        else:
            for ev in sample.reverse_analysis.evidence:
                evidence_items.append(
                    AssessmentEvidenceItem(
                        evidence_id=ev.evidence_id,
                        category=EvidenceCategory.REVERSE,
                        source=f"reverse_analysis.{ev.function_id}",
                        source_id=ev.function_id,
                        statement=ev.description,
                        evidence_type=ev.type.value,
                        observation_level=ObservationLevel.INFERRED,
                        role=EvidenceRole.SUPPORTING,
                        strength=EvidenceStrength.MEDIUM
                        if ev.confidence >= 0.6
                        else EvidenceStrength.LOW,
                        weight=ev.confidence,
                        provenance="reverse_analysis_engine",
                        technical_details={
                            "related_apis": ev.related_apis,
                            "related_strings": ev.related_strings,
                        },
                    )
                )

    def _collect_behavior_evidence(
        self,
        sample: Sample,
        evidence_items: list[AssessmentEvidenceItem],
        uncertainties: list[UncertaintyItem],
    ) -> None:
        """Extract observed runtime behavioral telemetry evidence."""
        if sample.behavior_analysis is None:
            uncertainties.append(
                UncertaintyItem(
                    category="behavior_analysis",
                    reason="Behavioral analysis has not been run for this sample.",
                    impact="Process execution, persistence, and network activity unobserved.",
                )
            )
        else:
            beh = sample.behavior_analysis
            # Process events
            for proc in beh.processes:
                p_name = proc.process_name.lower()
                if any(
                    k in p_name
                    for k in ("powershell", "cmd.exe", "rundll32", "regsvr32", "wscript")
                ):
                    evidence_items.append(
                        AssessmentEvidenceItem(
                            evidence_id=f"ev-beh-proc-{proc.pid}",
                            category=EvidenceCategory.BEHAVIOR,
                            source="behavior_analysis.process_tree",
                            source_id=str(proc.pid),
                            statement=(
                                f"Spawned suspicious process: '{proc.process_name}' "
                                f"(PID: {proc.pid})."
                            ),
                            evidence_type="process_execution",
                            observation_level=ObservationLevel.OBSERVED,
                            role=EvidenceRole.SUPPORTING,
                            strength=EvidenceStrength.HIGH,
                            weight=0.90,
                            provenance="behavior_analyzer:process_monitor",
                            technical_details={
                                "command_line": proc.command_line,
                                "ppid": proc.ppid,
                            },
                        )
                    )

            # Registry persistence events
            for reg in beh.registry_events:
                r_key = reg.key_path.lower()
                if "currentversion\\run" in r_key or "services" in r_key:
                    evidence_items.append(
                        AssessmentEvidenceItem(
                            evidence_id=f"ev-beh-reg-{reg.timestamp_ms}",
                            category=EvidenceCategory.BEHAVIOR,
                            source="behavior_analysis.registry_monitor",
                            source_id=reg.key_path,
                            statement=f"Modified autostart registry key: '{reg.key_path}'.",
                            evidence_type="registry_persistence",
                            observation_level=ObservationLevel.OBSERVED,
                            role=EvidenceRole.SUPPORTING,
                            strength=EvidenceStrength.HIGH,
                            weight=0.90,
                            provenance="behavior_analyzer:registry_monitor",
                            technical_details={
                                "operation": reg.operation,
                                "value_name": reg.value_name,
                            },
                        )
                    )

            # Network events
            for net in beh.network_events:
                dest = (
                    f"{net.destination_ip}:{net.destination_port}"
                    if net.destination_ip
                    else (net.domain or "unknown")
                )
                evidence_items.append(
                    AssessmentEvidenceItem(
                        evidence_id=f"ev-beh-net-{net.timestamp_ms}",
                        category=EvidenceCategory.BEHAVIOR,
                        source="behavior_analysis.network_monitor",
                        source_id=dest,
                        statement=(
                            f"Initiated outbound network connection to '{dest}' "
                            f"({net.protocol.upper()})."
                        ),
                        evidence_type="network_connection",
                        observation_level=ObservationLevel.OBSERVED,
                        role=EvidenceRole.SUPPORTING,
                        strength=EvidenceStrength.MEDIUM,
                        weight=0.75,
                        provenance="behavior_analyzer:network_monitor",
                        technical_details={"protocol": net.protocol, "direction": net.direction},
                    )
                )

            # Check for clean behavior (mitigating factor)
            if (
                not beh.processes
                and not beh.registry_events
                and not beh.network_events
                and not beh.dropped_files
            ):
                evidence_items.append(
                    AssessmentEvidenceItem(
                        evidence_id="ev-beh-clean-01",
                        category=EvidenceCategory.BEHAVIOR,
                        source="behavior_analysis.runtime_telemetry",
                        source_id="clean_execution",
                        statement=(
                            "Dynamic execution completed without spawning suspicious processes, "
                            "modifying registry, or generating network traffic."
                        ),
                        evidence_type="clean_execution",
                        observation_level=ObservationLevel.OBSERVED,
                        role=EvidenceRole.CONTRADICTING,
                        strength=EvidenceStrength.MEDIUM,
                        weight=0.60,
                        provenance="behavior_analyzer:telemetry",
                    )
                )

    def _collect_detection_evidence(
        self,
        sample: Sample,
        evidence_items: list[AssessmentEvidenceItem],
        uncertainties: list[UncertaintyItem],
    ) -> None:
        """Extract detection rule matching evidence."""
        if sample.detection is None:
            uncertainties.append(
                UncertaintyItem(
                    category="detection_rules",
                    reason="Detection rule evaluation has not been executed.",
                    impact="Known signature and heuristic rule matches unassessed.",
                )
            )
        else:
            det = sample.detection
            if det.triggered_rules or det.heuristics:
                for rule in det.triggered_rules:
                    sev_val = rule.severity.value.upper()
                    strength = (
                        EvidenceStrength(sev_val)
                        if sev_val in ("LOW", "MEDIUM", "HIGH")
                        else EvidenceStrength.MEDIUM
                    )
                    evidence_items.append(
                        AssessmentEvidenceItem(
                            evidence_id=f"ev-rule-{rule.rule_id}",
                            category=EvidenceCategory.RULES,
                            source="detection_engine.rules",
                            source_id=rule.rule_id,
                            statement=f"Triggered detection rule '{rule.name}': {rule.explanation}",
                            evidence_type="rule_match",
                            observation_level=ObservationLevel.INFERRED,
                            role=EvidenceRole.SUPPORTING,
                            strength=strength,
                            weight=rule.confidence,
                            provenance=f"rule_engine:{rule.rule_id}",
                            technical_details={"contribution": rule.contribution},
                        )
                    )
                for finding in det.heuristics:
                    sev_val = finding.severity.value.upper()
                    strength = (
                        EvidenceStrength(sev_val)
                        if sev_val in ("LOW", "MEDIUM", "HIGH")
                        else EvidenceStrength.MEDIUM
                    )
                    evidence_items.append(
                        AssessmentEvidenceItem(
                            evidence_id=f"ev-heuristic-{finding.heuristic_id}",
                            category=EvidenceCategory.RULES,
                            source=f"detection_engine.heuristic.{finding.category}",
                            source_id=finding.heuristic_id,
                            statement=(
                                f"Triggered heuristic '{finding.name}': {finding.explanation}"
                            ),
                            evidence_type="heuristic_finding",
                            observation_level=ObservationLevel.INFERRED,
                            role=EvidenceRole.SUPPORTING,
                            strength=strength,
                            weight=finding.confidence,
                            provenance=f"heuristic_engine:{finding.heuristic_id}",
                            technical_details={"contribution": finding.contribution},
                        )
                    )
            else:
                # Contradicting evidence: Zero rule triggers
                evidence_items.append(
                    AssessmentEvidenceItem(
                        evidence_id="ev-rules-none",
                        category=EvidenceCategory.RULES,
                        source="detection_engine.rules",
                        source_id="zero_matches",
                        statement="Zero static detection or heuristic rules triggered.",
                        evidence_type="no_rule_matches",
                        observation_level=ObservationLevel.OBSERVED,
                        role=EvidenceRole.CONTRADICTING,
                        strength=EvidenceStrength.LOW,
                        weight=0.30,
                        provenance="detection_engine:evaluator",
                    )
                )

    def _collect_ml_evidence(
        self,
        sample: Sample,
        evidence_items: list[AssessmentEvidenceItem],
        uncertainties: list[UncertaintyItem],
    ) -> None:
        """Extract machine learning classification evidence and feature importances."""
        if sample.ml_prediction is None:
            uncertainties.append(
                UncertaintyItem(
                    category="ml_classifier",
                    reason="Machine learning classifier prediction has not been run.",
                    impact="Statistical model scoring and feature importance ranking unavailable.",
                )
            )
        else:
            pred = sample.ml_prediction
            is_mal = pred.prediction == MLLabel.MALWARE
            role = EvidenceRole.SUPPORTING if is_mal else EvidenceRole.CONTRADICTING
            score_pct = round(pred.score * 100, 1)
            strength = (
                EvidenceStrength.HIGH
                if (pred.score >= 0.85 or pred.score <= 0.15)
                else EvidenceStrength.MEDIUM
            )

            statement = (
                f"Statistical ML model classified sample as '{pred.prediction.value.upper()}' "
                f"with score {score_pct}% (model: {pred.model_version})."
            )
            top_feats = [feat[0] for feat in pred.important_contributing_features[:4]]
            weight = (
                0.85
                if pred.uncertainty == "low"
                else (0.65 if pred.uncertainty == "medium" else 0.40)
            )
            evidence_items.append(
                AssessmentEvidenceItem(
                    evidence_id="ev-ml-prediction",
                    category=EvidenceCategory.ML,
                    source=f"ml_model.{pred.model_version}",
                    source_id=pred.model_version,
                    statement=statement,
                    evidence_type="ml_classification",
                    observation_level=ObservationLevel.INFERRED,
                    role=role,
                    strength=strength,
                    weight=weight,
                    provenance=f"ml_engine:{pred.model_version}",
                    technical_details={"score": pred.score, "top_features": top_feats},
                    limitations=["Statistical correlation only; does not establish causal proof."],
                )
            )

    def _collect_similarity_evidence(
        self,
        sample: Sample,
        evidence_items: list[AssessmentEvidenceItem],
        uncertainties: list[UncertaintyItem],
    ) -> None:
        """Extract Phase 10 sample similarity and cluster evidence with strict attribution."""
        if sample.similarity_analysis is None:
            uncertainties.append(
                UncertaintyItem(
                    category="similarity_analysis",
                    reason="Sample similarity indexing and candidate search unperformed.",
                    impact="Structural and behavioral similarity cluster relationships unknown.",
                )
            )
        else:
            sim = sample.similarity_analysis
            cluster_matches = [
                m for m in sim.matches if m.hypothesis.value == "possible_related_cluster"
            ]
            if cluster_matches:
                top = cluster_matches[0]
                pct = round(top.overall_similarity * 100, 1)
                statement = (
                    f"Sample exhibits strong similarity ({pct}%) to candidate "
                    f"'{top.target_filename}' suggesting a possible related cluster hypothesis."
                )
                evidence_items.append(
                    AssessmentEvidenceItem(
                        evidence_id=f"ev-sim-cluster-{top.target_sample_id[:8]}",
                        category=EvidenceCategory.SIMILARITY,
                        source="similarity_engine",
                        source_id=top.target_sample_id,
                        statement=statement,
                        evidence_type="similarity_cluster_match",
                        observation_level=ObservationLevel.POSSIBLE,
                        role=EvidenceRole.SUPPORTING,
                        strength=EvidenceStrength(top.confidence.value.upper()),
                        weight=top.overall_similarity,
                        provenance="similarity_engine:v1",
                        technical_details={"matching_categories": top.matching_feature_categories},
                        limitations=[
                            (
                                "Similarity indicates technical feature overlap and does NOT imply "
                                "confirmed malware family or actor attribution."
                            )
                        ],
                    )
                )

    def _detect_disagreements(
        self,
        sample: Sample,
        evidence_items: list[AssessmentEvidenceItem],
        disagreements: list[str],
    ) -> None:
        """Identify contradictions and disagreements across independent evidence layers."""
        has_suspicious_rules_or_behavior = any(
            e.role == EvidenceRole.SUPPORTING
            and e.category in (EvidenceCategory.RULES, EvidenceCategory.BEHAVIOR)
            for e in evidence_items
        )
        has_benign_ml = any(
            e.role == EvidenceRole.CONTRADICTING and e.category == EvidenceCategory.ML
            for e in evidence_items
        )
        if has_suspicious_rules_or_behavior and has_benign_ml:
            disagreements.append(
                "Statistical ML model classified the sample as benign, but heuristic rules "
                "or behavioral telemetry observed suspicious active indicators."
            )

        has_suspicious_static = any(
            e.role == EvidenceRole.SUPPORTING and e.category == EvidenceCategory.STATIC
            for e in evidence_items
        )
        has_clean_behavior = any(e.evidence_type == "clean_execution" for e in evidence_items)
        if has_suspicious_static and has_clean_behavior:
            disagreements.append(
                "Static analysis identified suspicious indicators (e.g. packed section), "
                "but dynamic runtime execution did not exhibit active malicious behavior."
            )

    def _calculate_risk_score(
        self,
        sample: Sample,
        evidence_items: list[AssessmentEvidenceItem],
        uncertainties: list[UncertaintyItem],
    ) -> RiskScoreDetails:
        """Compute deterministic evidence-backed risk score (0-100)."""
        contributing: list[RiskFactor] = []
        mitigating: list[RiskFactor] = []
        unknowns: list[str] = [u.reason for u in uncertainties]

        # Scoring Weights Table
        for ev in evidence_items:
            if ev.role == EvidenceRole.SUPPORTING:
                pts = 0.0
                if ev.evidence_type in ("process_execution", "registry_persistence"):
                    pts = 25.0
                elif ev.evidence_type == "suspicious_section_permissions":
                    pts = 20.0
                elif ev.evidence_type in ("rule_match", "network_connection"):
                    pts = 15.0
                elif ev.evidence_type in ("high_entropy_section", "ml_classification"):
                    pts = 12.0
                elif ev.evidence_type == "similarity_cluster_match":
                    pts = 10.0
                else:
                    pts = 8.0

                contributing.append(
                    RiskFactor(
                        name=ev.evidence_type,
                        category=ev.category,
                        points=pts,
                        description=ev.statement,
                        observation_level=ev.observation_level,
                    )
                )
            elif ev.role == EvidenceRole.CONTRADICTING:
                pts = 0.0
                if ev.evidence_type == "clean_execution":
                    pts = 15.0
                elif ev.evidence_type == "ml_classification":
                    pts = 15.0
                elif ev.evidence_type == "no_rule_matches":
                    pts = 10.0
                else:
                    pts = 5.0

                mitigating.append(
                    RiskFactor(
                        name=ev.evidence_type,
                        category=ev.category,
                        points=pts,
                        description=ev.statement,
                        observation_level=ev.observation_level,
                    )
                )

        raw_positive = sum(f.points for f in contributing)
        raw_negative = sum(f.points for f in mitigating)

        # Base formula: Positive evidence points minus mitigating factors clamped to [0, 100]
        final_score = int(round(max(0.0, min(100.0, raw_positive - (raw_negative * 0.5)))))

        formula = (
            f"min(100, max(0, sum(positive_factors[{round(raw_positive, 1)}]) - "
            f"0.5 * sum(mitigating_factors[{round(raw_negative, 1)}])))"
        )

        return RiskScoreDetails(
            score=final_score,
            formula=formula,
            contributing_factors=contributing,
            mitigating_factors=mitigating,
            unknown_factors=unknowns,
        )

    def _determine_verdict(
        self,
        sample: Sample,
        evidence_items: list[AssessmentEvidenceItem],
        risk_score_details: RiskScoreDetails,
        uncertainties: list[UncertaintyItem],
    ) -> tuple[AssessmentVerdict, RiskLevel]:
        """Apply documented deterministic logic to reach an evidence-backed verdict."""
        # 1. Check for Insufficient Evidence -> UNKNOWN (Missing != Benign)
        executed_layers = 0
        if sample.static_analysis is not None:
            executed_layers += 1
        if sample.reverse_analysis is not None:
            executed_layers += 1
        if sample.behavior_analysis is not None:
            executed_layers += 1
        if sample.detection is not None:
            executed_layers += 1
        if sample.ml_prediction is not None:
            executed_layers += 1

        # If zero or only basic metadata without static/behavior/rules
        if executed_layers == 0 and not evidence_items:
            return AssessmentVerdict.UNKNOWN, RiskLevel.UNKNOWN

        score = risk_score_details.score

        # 2. Strong / Convergent Suspicious Evidence
        supporting_categories = {
            e.category for e in evidence_items if e.role == EvidenceRole.SUPPORTING
        }
        if score >= 75 and len(supporting_categories) >= 2:
            return (
                AssessmentVerdict.HIGHLY_SUSPICIOUS,
                RiskLevel.CRITICAL if score >= 85 else RiskLevel.HIGH,
            )

        if score >= 45 or len(supporting_categories) >= 2:
            return AssessmentVerdict.SUSPICIOUS, RiskLevel.HIGH if score >= 60 else RiskLevel.MEDIUM

        # 3. Clean / Benign Assessment
        if score < 20 and executed_layers >= 3:
            # Fully corroborated clean findings
            return AssessmentVerdict.BENIGN, RiskLevel.NONE

        if score < 35 and executed_layers >= 2:
            return AssessmentVerdict.LIKELY_BENIGN, RiskLevel.LOW

        # If minimal analysis done and score is low, mark as UNKNOWN rather than claiming Benign
        if executed_layers <= 1 and score < 30:
            return AssessmentVerdict.UNKNOWN, RiskLevel.UNKNOWN

        return AssessmentVerdict.LIKELY_BENIGN, RiskLevel.LOW

    def _evaluate_confidence(
        self,
        sample: Sample,
        verdict: AssessmentVerdict,
        evidence_items: list[AssessmentEvidenceItem],
        uncertainties: list[UncertaintyItem],
    ) -> ConfidenceBreakdown:
        """Calculate separate confidence ratings across orthogonal dimensions."""
        # 1. Detection Confidence
        if verdict == AssessmentVerdict.UNKNOWN:
            det_conf = ConfidenceLevel.LOW
        else:
            supporting = [e for e in evidence_items if e.role == EvidenceRole.SUPPORTING]
            if len(supporting) >= 3 or verdict == AssessmentVerdict.HIGHLY_SUSPICIOUS:
                det_conf = ConfidenceLevel.HIGH
            elif len(supporting) >= 1 or verdict in (
                AssessmentVerdict.SUSPICIOUS,
                AssessmentVerdict.LIKELY_BENIGN,
            ):
                det_conf = ConfidenceLevel.MEDIUM
            else:
                det_conf = ConfidenceLevel.LOW

        # 2. Evidence Quality
        executed_count = sum(
            1
            for s in (
                sample.static_analysis,
                sample.reverse_analysis,
                sample.behavior_analysis,
                sample.detection,
                sample.ml_prediction,
                sample.similarity_analysis,
            )
            if s is not None
        )
        if executed_count >= 4:
            ev_quality = ConfidenceLevel.HIGH
        elif executed_count >= 2:
            ev_quality = ConfidenceLevel.MEDIUM
        else:
            ev_quality = ConfidenceLevel.LOW

        # 3. Behavioral Confidence
        if sample.behavior_analysis is None:
            beh_conf = ConfidenceLevel.UNAVAILABLE
        else:
            beh_conf = ConfidenceLevel.HIGH

        # 4. Similarity & Attribution Confidence
        if sample.similarity_analysis is None:
            sim_conf = ConfidenceLevel.UNAVAILABLE
            attr_conf = ConfidenceLevel.UNAVAILABLE
        else:
            sim = sample.similarity_analysis
            cluster_matches = [
                m for m in sim.matches if m.hypothesis.value == "possible_related_cluster"
            ]
            if cluster_matches:
                sim_conf = ConfidenceLevel(cluster_matches[0].confidence.value.upper())
                attr_conf = ConfidenceLevel.MEDIUM
            else:
                sim_conf = ConfidenceLevel.LOW
                attr_conf = ConfidenceLevel.UNAVAILABLE

        explanation = (
            f"Detection confidence is {det_conf.value} based on available corroborating evidence. "
            f"Evidence quality is {ev_quality.value} across {executed_count} executed subsystems. "
            f"Attribution confidence reflects technical cluster hypotheses only."
        )

        return ConfidenceBreakdown(
            detection_confidence=det_conf,
            evidence_quality=ev_quality,
            behavioral_confidence=beh_conf,
            similarity_confidence=sim_conf,
            attribution_confidence=attr_conf,
            attribution_scope="cluster_only",
            explanation=explanation,
        )
