# Research Experiments & Ablation Protocol Guide

## 1. Overview

This document defines the standard research experiment protocols and ablation configurations supported by the Igris experimental evaluation subsystem.

---

## 2. Standard Ablation Configurations

Ablation studies isolate the contribution of individual analysis engines under identical sample populations and ground truths.

```
A: [STATIC_ONLY]
     │ (Adds Detection Rules & Heuristics)
     ▼
B: [STATIC_HEURISTICS]
     │ (Adds Safe Linear Disassembly & CFGs)
     ▼
C: [STATIC_REVERSE]
     │ (Adds Machine Learning Classification)
     ▼
D: [STATIC_REVERSE_ML]
     │ (Adds Dynamic Behavioral Sandbox)
     ▼
E: [STATIC_REVERSE_BEHAVIOR]
     │ (Adds Similarity, Threat Intel & Correlation)
     ▼
F: [FULL_IGRIS]
```

### Stage Composition Matrix

| Config ID | Name | Enabled Pipeline Stages |
|---|---|---|
| **A** | `STATIC_ONLY` | `FILE_INTELLIGENCE`, `STATIC_ANALYSIS`, `ASSESSMENT` |
| **B** | `STATIC_HEURISTICS` | `FILE_INTELLIGENCE`, `STATIC_ANALYSIS`, `DETECTION`, `ASSESSMENT` |
| **C** | `STATIC_REVERSE` | `FILE_INTELLIGENCE`, `STATIC_ANALYSIS`, `DETECTION`, `REVERSE_ANALYSIS`, `ASSESSMENT` |
| **D** | `STATIC_REVERSE_ML` | `FILE_INTELLIGENCE`, `STATIC_ANALYSIS`, `DETECTION`, `REVERSE_ANALYSIS`, `ML`, `ASSESSMENT` |
| **E** | `STATIC_REVERSE_BEHAVIOR` | `FILE_INTELLIGENCE`, `STATIC_ANALYSIS`, `DETECTION`, `REVERSE_ANALYSIS`, `BEHAVIOR`, `ASSESSMENT` |
| **F** | `FULL_IGRIS` | All 11 stages (`FILE_INTELLIGENCE` through `REPORT`) |

---

## 3. Standard Experiment Protocols

### Experiment Protocol 1: End-to-End Ablation Benchmark (RQ1, RQ2, RQ3, RQ6)
- **Objective:** Evaluate detection progression and computational cost across all 6 configurations.
- **Dataset:** `igris-synthetic-benchmark-v1` (or researcher-provided manifest).
- **Split Strategy:** `FAMILY_AWARE` (Random Seed = 42).
- **Configurations:** All A through F.
- **Measured Outputs:** Precision, Recall, F1, FPR, FNR, per-stage latency, throughput.

### Experiment Protocol 2: Generalization & Family Leakage Study (RQ5)
- **Objective:** Compare `FAMILY_AWARE` vs `RANDOM` split performance to measure family overfitting and cross-family generalization degradation.
- **Dataset:** Multi-family evaluation corpus.
- **Hypothesis:** `FAMILY_AWARE` will reflect lower (but more realistic) recall than `RANDOM` due to the elimination of shared family feature leakage.

### Experiment Protocol 3: False Positive Reduction via Evidence Correlation (RQ4)
- **Objective:** Measure false positive rate reduction when `EVIDENCE_CORRELATION` and `ASSESSMENT` reconcile contradictory heuristic alerts with clean behavioral traces on benign utilities.
- **Target Population:** Benign system binaries, packed runtime installers, compressor utilities.

---

## 4. Executing Experiments via REST API

### Creating & Running an Experiment
```bash
POST /api/v1/experiments
Content-Type: application/json

{
  "research_question": "RQ1-RQ6: Comprehensive Multi-Stage Ablation Benchmark",
  "dataset_id": "igris-synthetic-benchmark-v1",
  "dataset_version": "v1.0",
  "split_strategy": "FAMILY_AWARE",
  "ablation_configurations": [
    "STATIC_ONLY",
    "STATIC_HEURISTICS",
    "STATIC_REVERSE",
    "STATIC_REVERSE_ML",
    "STATIC_REVERSE_BEHAVIOR",
    "FULL_IGRIS"
  ],
  "random_seed": 42,
  "description": "Multi-stage ablation study evaluating precision, recall, latency, and error taxonomies."
}
```

### Retrieving Experiment Artifacts
```bash
GET /api/v1/experiments/{experiment_id}/artifacts
```
Returns machine-readable JSON reports, reproducibility metadata, and formatted markdown summaries.
