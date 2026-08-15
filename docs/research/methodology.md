# Research Evaluation Methodology & Empirical Design

## 1. Overview & Research Philosophy

The **Igris Experimental Evaluation Framework** is designed to transform Igris into an empirically rigorous, reproducible cybersecurity research platform. The framework measures how the existing system actually operates across individual capabilities, evidence sources, and pipeline configurations without modifying detection logic or tuning thresholds to artificially flatter benchmark metrics.

---

## 2. Research Questions (RQ1 – RQ6)

The evaluation architecture enables empirical investigation into the following fundamental questions:

- **RQ1 (Static Analysis Baseline):** How effective is static PE/ELF binary intelligence alone without dynamic telemetry or heuristic rule matching?
- **RQ2 (Reverse Engineering Impact):** Does safe linear disassembly and control-flow graph (CFG) structure improve detection and reduce uncertainty?
- **RQ3 (Behavioral Sandbox Impact):** Does behavioral telemetry (process trees, registry modifications, socket connections) catch evasive, packed, or mutating malware?
- **RQ4 (Evidence Correlation & ML):** Does cross-engine evidence correlation combined with explainable ML scoring reduce false positives and resolve conflicting signals?
- **RQ5 (Family-Aware Generalization):** How robust is Igris when evaluated against held-out, previously unseen malware families under strict leakage prevention?
- **RQ6 (Computational Efficiency):** What computational latency overhead and resource cost is imposed by each incremental analysis stage?

---

## 3. Dataset Abstraction & Safety Principles

### Dataset Manifest Schema
Every evaluated dataset must provide a cryptographically verified manifest defining:
- `dataset_id` & `dataset_version`: Immutable unique identifiers.
- `source` & `license`: Provenance tracking.
- `collection_methodology`: Explicit sampling protocols and inclusion/exclusion criteria.
- `class_distribution` & `family_distribution`: Balance metrics across labels and families.
- `samples`: Individual records with verified SHA-256 hashes, file formats, and tags.

### Dataset Safety Guardrails
- **No Unsafe Auto-Execution:** Ingestion processes never execute binary files outside controlled sandbox boundaries.
- **Reference-Based Evaluation:** Evaluation routines operate on metadata, pre-extracted features, and safe sandbox traces where live sample execution is unwarranted.
- **Controlled Behavioral Sandboxing:** Dynamic analysis strictly utilizes existing isolation sandboxes with timeout deadlines and network containment.

---

## 4. Split Methodology & Leakage Prevention

To prevent optimistic bias and test-set contamination:

### Split Strategies
1. **`FAMILY_AWARE` (Default for generalization studies):**
   - Samples are grouped strictly by threat family.
   - Entire families are randomly partitioned into `TRAIN` (50%), `VALIDATION` (25%), and `TEST` (25%).
   - Guarantees zero family overlap between training/tuning artifacts and the evaluation split.
2. **`STRATIFIED`:**
   - Preserves balanced proportions of benign and malicious classes across splits.
3. **`RANDOM`:**
   - Uniform random assignment seeded with a deterministic integer.

### Duplicate Leakage Prevention
- All samples are deduplicated by exact SHA-256 hash prior to partitioning.
- Duplicate and near-duplicate binaries are prevented from spanning multiple splits.

---

## 5. Metric Formulations & Statistical Calibration

Evaluation metrics reflect operational reality without suppressing difficult edge cases.

### Operational Verdict Mapping
- **Positive Assessment:** Verdicts of `HIGHLY_SUSPICIOUS` or `SUSPICIOUS`.
- **Negative Assessment:** Verdicts of `BENIGN` or `LIKELY_BENIGN`.
- **Indeterminate / UNKNOWN:** Preserved as a distinct outcome (`unknown_count`). UNKNOWN verdicts are **never** silently converted to benign or malicious.

### Formulas
- **Precision:** $\text{Precision} = \frac{TP}{TP + FP}$
- **Recall (Sensitivity):** $\text{Recall} = \frac{TP}{TP + FN}$
- **F1-Score:** $\text{F1} = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$
- **False Positive Rate (FPR):** $\text{FPR} = \frac{FP}{FP + TN}$
- **False Negative Rate (FNR):** $\text{FNR} = \frac{FN}{TP + FN}$
- **Accuracy:** $\text{Accuracy} = \frac{TP + TN}{TP + TN + FP + FN}$

### Statistical Confidence Intervals
- Wilson score 95% binomial confidence intervals are computed for all proportion metrics (Precision, Recall, FPR, FNR) to account for sample size constraints:
  $$\text{Wilson Center} = \frac{p + \frac{z^2}{2n}}{1 + \frac{z^2}{n}}, \quad \text{Margin} = \frac{z \sqrt{\frac{p(1-p)}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}}$$

---

## 6. Diagnostic Error Taxonomy

Misclassifications are systematically investigated and assigned to an evidence-grounded error category:

| Error Category | Typical Scenario | Observation Level |
|---|---|---|
| `misleading_heuristic` | Benign compressor, runtime packer, or updater triggering static entropy thresholds. | `INFERRED` |
| `behavior_unavailable` | Malware employing sleep evasion or sandbox escape during dynamic observation. | `INFERRED` |
| `insufficient_static_evidence` | Stealthy script dropper with clean PE header and minimal static imports. | `OBSERVED` |
| `reverse_analysis_limitation` | Heavily obfuscated indirect control flow resisting linear disassembly. | `INFERRED` |
| `ml_disagreement` | Feature vector ambiguity near classifier decision boundary. | `INFERRED` |
| `contradictory_evidence` | High static suspicion contradicted by benign behavior execution trace. | `POSSIBLE` |
| `insufficient_evidence` | Indeterminate assessment due to early pipeline stage failure. | `UNKNOWN` |
