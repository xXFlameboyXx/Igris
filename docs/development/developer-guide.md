# Igris Developer & Extension Guide

This guide provides practical instructions for developers and security researchers extending the **Igris Malware Analysis & Intelligence Platform**.

---

## 1. Local Development Environment

### 1.1 Prerequisites
- **Python:** 3.11 or newer
- **Package Manager:** `uv` (recommended) or `pip`
- **Node.js:** 20 or newer
- **Frontend Package Manager:** `npm`

### 1.2 Initial Setup
```bash
# Clone the repository
git clone https://github.com/xXFlameboyXx/Igris.git
cd Igris

# Sync backend environment and dev tools
uv sync --extra dev

# Install frontend dependencies
cd frontend && npm install && cd ..
```

### 1.3 Running Development Servers
```bash
# Terminal 1: Backend API (runs at http://127.0.0.1:8000)
uv run uvicorn igris.main:app --app-dir backend/src --reload --port 8000

# Terminal 2: Frontend UI (runs at http://127.0.0.1:5173)
cd frontend
npm run dev
```

---

## 2. Extending Analysis Engines

### 2.1 Adding a New Analyzer
To add a new analysis capability (e.g. Authenticode signature verifier, archive unpacker, or compiler fingerprinter):

1. **Create Analysis Service:**
   Create a module under `backend/src/igris/analysis/<your_feature>/service.py`:
   ```python
   from pathlib import Path
   from igris.schemas.evidence import EvidenceItem, EpistemologyTier, ConfidenceLevel


   class CustomAnalyzer:
       def analyze(self, sample_path: Path) -> list[EvidenceItem]:
           evidence: list[EvidenceItem] = []
           # 1. Read binary data safely
           data = sample_path.read_bytes()
           # 2. Extract feature
           has_custom_marker = b"SPECIAL_MARKER" in data
           if has_custom_marker:
               evidence.append(
                   EvidenceItem(
                       evidence_id=f"ev-custom-{sample_path.stem[:8]}",
                       source_component="custom_analyzer",
                       epistemology=EpistemologyTier.OBSERVED,
                       confidence=ConfidenceLevel.CONFIRMED,
                       weight=5.0,
                       rationale="Found special binary signature marker in payload.",
                       data={"marker": "SPECIAL_MARKER"},
                   )
               )
           return evidence
   ```

2. **Register in Orchestration DAG:**
   Update [`OrchestrationService`](file:///e:/IGRIS/backend/src/igris/orchestration/service.py) in `backend/src/igris/orchestration/service.py` to declare dependencies and invoke the analyzer in `execute_job()`.

3. **Add Unit & Regression Tests:**
   Add tests in `tests/backend/test_<your_feature>.py` verifying behavior under valid inputs, malformed files, and empty files.

---

## 3. Adding Evidence Types & Epistemology Mapping

When generating new evidence items:
- **`EpistemologyTier.OBSERVED`:** Use exclusively for directly extracted binary bytes, cryptographic hashes, raw disassembly opcodes, or explicit header fields.
- **`EpistemologyTier.INFERRED`:** Use for structural graph algorithms, call graph relationships, or rule-based MITRE ATT&CK technique inferences.
- **`EpistemologyTier.POSSIBLE`:** Use for heuristic score triggers, statistical anomaly scores, ML predictions, or fuzzy similarity matches.

---

## 4. Adding Static Detection Rules

Detection rules reside in `backend/src/igris/analysis/detection/` or configuration YAML files.

### 4.1 Rule Schema Definition
```python
from igris.schemas.detection import DetectionRule, RuleSeverity

my_rule = DetectionRule(
    rule_id="RULE-PERSIST-RUNKEY",
    name="Suspicious Run Key Persistence Reference",
    severity=RuleSeverity.HIGH,
    category="persistence",
    attck_techniques=["T1547.001"],
    weight=15.0,
    rationale="Detects explicit references to CurrentVersion\\Run registry persistence keys.",
)
```

---

## 5. Adding & Updating ML Models

To integrate a new machine learning classifier:
1. **Feature Extraction:** Register new numerical or categorical features in `backend/src/igris/analysis/ml/features.py`. Ensure feature extractors fail gracefully if upstream static or reverse analysis fields are missing.
2. **Model Training & Artifact Serialization:**
   - Train using `backend/src/igris/analysis/ml/training.py` with leakage-aware family-level splitting.
   - Save versioned model artifacts and metadata in `data/models/<model_name>_<version>.joblib`.
3. **Inference & Explainability:**
   - Implement SHAP TreeExplainer or LinearExplainer in `backend/src/igris/analysis/ml/service.py` to return top contributing features per prediction.

---

## 6. Pre-Commit Quality Standards

Ensure all quality gates pass before pushing:
```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
cd frontend && npm test && npm run lint && npm run build
```
