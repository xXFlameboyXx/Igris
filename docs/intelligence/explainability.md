# Phase 11: Explainable Malware Assessment

## 1. Overview & Purpose

Phase 11 implements the defining intelligence layer of the Igris platform: **Explainable Malware Assessment**. Rather than functioning as a black-box detection engine, Phase 11 sits directly above all existing analysis subsystems to synthesize evidence into a structured, transparent, uncertainty-aware assessment.

The system deterministically answers:
1. **What does Igris think?** (Verdict & Risk Level)
2. **How confident is it?** (Multi-Dimensional Confidence Breakdown)
3. **Why?** (Human-Readable Epistemological Narrative)
4. **What evidence supports the assessment?** (Supporting Evidence List)
5. **What evidence contradicts it?** (Contradicting Evidence & Mitigating Factors)
6. **What remains unknown?** (Explicit Uncertainty & Unobserved Telemetry)

---

## 2. Architectural Position

The Explainable Assessment engine consumes artifacts produced by Phases 1–10 without duplicating analysis or modifying underlying telemetry:

```
                            ┌────────────────────────┐
                            │      Raw Sample        │
                            └───────────┬────────────┘
                                        │
             ┌──────────────────────────┼──────────────────────────┐
             ▼                          ▼                          ▼
   ┌───────────────────┐      ┌───────────────────┐      ┌───────────────────┐
   │  Static Analysis  │      │ Reverse Analysis  │      │ Behavior Analysis │
   │ (PE/ELF, Strings) │      │  (CFG, Opcodes)   │      │(Process, Reg, Net)│
   └─────────┬─────────┘      └─────────┬─────────┘      └─────────┬─────────┘
             │                          │                          │
             ├──────────────────────────┼──────────────────────────┤
             ▼                          ▼                          ▼
   ┌───────────────────┐      ┌───────────────────┐      ┌───────────────────┐
   │  Detection Rules  │      │   ML Classifier   │      │ Similarity Engine │
   │ (YARA/Heuristics) │      │ (Random Forest)   │      │  (Phase 10 Index) │
   └─────────┬─────────┘      └─────────┬─────────┘      └─────────┬─────────┘
             │                          │                          │
             └──────────────────────────┼──────────────────────────┘
                                        ▼
                         ┌─────────────────────────────┐
                         │   Phase 11 Assessment Engine│
                         │(Evidence Aggregation & Dedup│
                         │ Disagreement & Uncertainty) │
                         └──────────────┬──────────────┘
                                        ▼
                         ┌─────────────────────────────┐
                         │  Explainable Verdict Report │
                         │ (Verdict, Risk Score, Conf, │
                         │  Observed/Inferred/Possible)│
                         └─────────────────────────────┘
```

---

## 3. Epistemological Classifications: Observed vs Inferred vs Possible

A fundamental design requirement is the strict distinction between raw observations, analytical inferences, and unproven possibilities:

| Classification | Definition | Example Statement |
| :--- | :--- | :--- |
| **`OBSERVED`** | Directly observed in raw binary structure or recorded runtime telemetry. | *"Section '.text' has W+X permissions."* / *"Spawned child process 'powershell.exe' (PID: 1042)."* |
| **`INFERRED`** | Derived interpretation or rule-based deduction from observed evidence. | *"Modified registry key CurrentVersion\Run (consistent with autostart persistence)."* / *"ML model classified sample as malicious."* |
| **`POSSIBLE`** | Unproven hypothesis, similarity cluster suggestion, or potential capability. | *"Sample exhibits 84.5% technical similarity to candidate X suggesting a possible related cluster."* |

---

## 4. Verdict & Risk Score Semantics

### Structured Verdicts
- **`HIGHLY_SUSPICIOUS`**: Multiple independent analysis layers corroborate severe malicious activity (e.g. process injection, persistence, C2 communication).
- **`SUSPICIOUS`**: Substantial evidence indicating unauthorized or hostile capabilities in at least one primary analysis layer.
- **`LIKELY_BENIGN`**: Predominantly clean technical characteristics with low risk score across evaluated subsystems.
- **`BENIGN`**: Comprehensive multi-layer analysis confirms complete absence of suspicious artifacts, anomalous telemetry, or heuristic triggers.
- **`UNKNOWN`**: Insufficient evidence or unperformed analysis subsystems prevent reaching a confident conclusion.

> [!IMPORTANT]
> **Missing Evidence $\neq$ Negative Evidence**: Unexecuted analysis layers (e.g. dynamic sandbox unperformed) are explicitly recorded as uncertainties and never converted into benign proof. Absolute "safe" claims are strictly forbidden.

### Deterministic Evidence-Backed Risk Score
The risk score is a deterministic integer between `0` and `100` reflecting cumulative technical evidence weight (it is **not** a calibrated statistical probability):

$$\text{RiskScore} = \min\left(100, \max\left(0, \sum \text{PositivePoints} - 0.5 \times \sum \text{MitigatingPoints}\right)\right)$$

- **Contributing Factors**:
  - Process Injection / Execution: `+25`
  - Autostart Persistence: `+25`
  - W+X Section Permissions: `+20`
  - C2 Network Connections: `+15`
  - Detection Rule Matches: `+15`
  - High Entropy Section: `+12`
  - ML Malicious Prediction: `+12`
  - Technical Similarity Cluster Match: `+10`
- **Mitigating Factors**:
  - Clean Dynamic Runtime Execution: `-15`
  - ML Benign Prediction: `-15`
  - Zero Rule Matches: `-10`

---

## 5. Multi-Dimensional Confidence Breakdown

Confidence is decoupled across orthogonal analytical dimensions:

1. **`detection_confidence`**: Conviction in the suspiciousness/malware assessment based on evidence strength and convergence.
2. **`evidence_quality`**: Completeness and independent corroboration across executed analysis subsystems (`HIGH` $\ge$ 4 layers, `MEDIUM` 2–3 layers, `LOW` $\le$ 1 layer).
3. **`behavioral_confidence`**: Confidence derived specifically from dynamic runtime telemetry.
4. **`similarity_confidence`**: Confidence in technical feature overlap with candidate samples.
5. **`attribution_confidence`**: Confidence in technical cluster membership only (`attribution_scope = "cluster_only"`).

### Attribution Guardrails
The assessment engine strictly adheres to Phase 10 safety bounds:
- Similarity evidence identifies **possible related clusters**.
- It **never** claims confirmed malware family attribution, threat actor identity, or campaign membership.

---

## 6. Contradiction & Disagreement Handling

When independent analysis layers produce conflicting conclusions, the engine exposes the disagreement rather than suppressing contradictory evidence:
- **ML Disagreement**: If the ML model classifies a sample as Benign while behavioral telemetry records active persistence, the report highlights: *"ML model prediction (Benign) conflicts with observed behavioral telemetry."*
- **Static vs Runtime Disagreement**: If static analysis detects packed sections or suspicious APIs but dynamic execution generates zero network or process activity, the discrepancy is surfaced in the narrative.

---

## 7. REST API Endpoints

### 1. Retrieve Structured Verdict
- **`GET /api/v1/samples/{id}/verdict`**
- Returns `VerdictResponse` containing `verdict`, `risk_level`, `risk_score` breakdown, `confidence` metrics, and analytical limitations.

### 2. Retrieve Human-Readable Narrative
- **`GET /api/v1/samples/{id}/explanation`**
- Returns `ExplanationResponse` containing epistemologically partitioned sections: `observed_findings`, `inferred_findings`, `possible_hypotheses`, `supporting_arguments`, `contradicting_arguments`, and `uncertainty_and_unknowns`.

### 3. Retrieve Complete Evidence Summary
- **`GET /api/v1/samples/{id}/evidence-summary`**
- Returns `EvidenceSummaryResponse` containing all individual traceable `AssessmentEvidenceItem` records, count tallies, disagreements, and uncertainty items.

---

## 8. Caching & Invalidation Architecture

Assessments are cached on `sample.malware_assessment`. Re-running any upstream subsystem (`static-analysis`, `reverse-analysis`, `behavior-analysis`, `detection`, `ml/predict`, `similarity`) automatically invalidates `sample.malware_assessment = None` and triggers fresh recalculation on next access.
