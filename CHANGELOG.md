# Changelog

All notable changes to the **Igris Malware Analysis & Intelligence Platform** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-08-15

### Phase 18 — Public Project, Documentation, Reproducibility & Release Readiness
- **Project Documentation:** Complete rewrite of [`README.md`](README.md), [`CONTRIBUTING.md`](CONTRIBUTING.md), [`SECURITY.md`](SECURITY.md), and [`docs/responsible-use.md`](docs/responsible-use.md).
- **Developer Guide:** Added [`docs/development/developer-guide.md`](docs/development/developer-guide.md) with practical instructions for extending analyzers, adding evidence types, writing rules, and training ML models.
- **Pipeline & Epistemology Architecture:** Authored [`docs/architecture/pipeline.md`](docs/architecture/pipeline.md) formalizing the end-to-end execution flow, epistemology levels (`OBSERVED`, `INFERRED`, `POSSIBLE`), and verdict synthesis.
- **API Catalog:** Added [`docs/api/endpoints.md`](docs/api/endpoints.md) documenting all FastAPI REST routes with benign example payloads.
- **Release Dossier:** Created [`docs/release/readiness.md`](docs/release/readiness.md) with comprehensive verification checklists and deployment boundaries.

### Phase 17 — Security Hardening & Defensive Assessment
- **Input Security:** Hardened streaming upload validation in `_stream_to_temp` with 64KB chunk iteration, path-traversal sanitization in `sanitize_filename`, and SHA-256 content-addressed storage isolation.
- **Parser Safety:** Added bounds checking and exception trapping in PE/ELF parsers (`PEParseError`, `ELFParseError`).
- **Defensive Headers:** Implemented ASGI `SecurityHeadersMiddleware` setting `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `CSP`, and `Referrer-Policy`.
- **Report Protection:** Added `_sanitize_pdf_text` escaping in pure Python `PurePDFRenderer`.
- **Regression Suite:** Added 9 permanent security tests in `tests/backend/test_security_hardening.py`.
- **Audit Documentation:** Authored `docs/security/hardening.md` and machine-readable `config/security/security_review_record.json`.

### Phase 16 — Robustness & Adversarial Perturbation Evaluation
- **Perturbation Engine:** Added deterministic transformation operators (`rename`, `metadata_strip`, `string_obfuscate`, `section_inject`, `upx_simulate`, `noop_pad`).
- **Degradation Scoring:** Implemented robustness metrics measuring detection delta, confidence shift, and feature stability.
- **Storage & REST APIs:** Added `RobustnessRepository` and `/api/v1/robustness` endpoints.
- **Frontend Matrix:** Added `RobustnessView.tsx` with perturbation matrix and resistance heatmaps.

### Phase 15 — Research Infrastructure & Evaluation Benchmark
- **Benchmarking Suite:** Implemented `EvaluationHarness` executing reproducible experiments across benign and synthetic malware datasets.
- **Ablation Matrix:** Added ablation testing across analysis subsystems (static-only, ML-only, dynamic-only).
- **Metric Computation:** Automated calculation of Accuracy, Precision, Recall, F1, ROC-AUC with bootstrap confidence intervals.
- **Dataset Splitting:** Leakage-aware family/hash splitting ensuring zero train/test contamination.

### Phase 14 — End-to-End Orchestration & Analysis DAG
- **Pipeline Orchestrator:** Implemented `OrchestrationService` coordinating dependencies across all analysis engines.
- **Partial-Result Fault Tolerance:** Engine failures or disabled stages record stage errors without crashing downstream analysis.
- **Job Lifecycle:** Async job execution, status polling, cancellation, and stage-by-stage progress tracking.

### Phase 13 — Investigation Workspace, Dossiers & Pure PDF Reporting
- **Investigation Workspace:** Added bookmarking, analyst notes, and investigation timeline management.
- **Pure Python PDF Dossier:** Built `PurePDFRenderer` generating standalone, formatted investigation reports in-memory without external subprocesses.

### Phase 8–12 — Explainable Verdict Assessment & Analyst Interface
- **Epistemology Framework:** Segregated evidence into `OBSERVED` (hard facts), `INFERRED` (deductions), and `POSSIBLE` (heuristics/hypotheses).
- **Verdict Synthesis:** Transparent risk formula mapping evidence items to `BENIGN`, `SUSPICIOUS`, `HIGHLY_SUSPICIOUS`, or `MALICIOUS`.
- **Analyst UI:** Comprehensive React/TypeScript interface with interactive graph views, disassembler, and evidence explorer.

### Phases 1–7 — Core Analysis Engines & Machine Learning
- **Phase 1 (File Intelligence):** Magic byte detection, cryptographic hashing (SHA256, SHA1, MD5), and Shannon entropy profiling.
- **Phase 2 (Static Analysis):** String extraction, import capability taxonomy, PE/ELF section entropy, overlay detection.
- **Phase 3 (Detection):** Declarative YAML rules, heuristic indicator scoring, and transparent rule hit breakdowns.
- **Phase 4 (Reverse Engineering):** Linear sweep disassembly with Capstone, control flow graph (CFG) construction, basic block extraction.
- **Phase 5 (Threat Intelligence):** MITRE ATT&CK technique mapping and threat actor profiling.
- **Phase 6 (Machine Learning):** Scikit-Learn baseline classifiers (Random Forest, Gradient Boosting) with SHAP feature importance explainability.
- **Phase 7 (Behavioral Telemetry):** Deterministic synthetic behavioral simulation modeling process, filesystem, registry, and network activity.

### Phase 0 — Foundation & Architecture
- **Architecture Scaffolding:** FastAPI backend, Starlette middleware, Pydantic data validation, React frontend, Docker compose, and CI configuration.
