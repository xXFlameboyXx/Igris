# Contributing to Igris

Thank you for your interest in contributing to the **Igris Malware Analysis & Intelligence Platform**!

We welcome contributions from researchers, reverse engineers, software developers, and security analysts. This document outlines our development standards, branching strategy, code quality requirements, and pull request procedures.

---

## 1. Core Development Invariants

When contributing to Igris, you **must** preserve these foundational architectural invariants:

1. **Epistemological Evidence Separation:**
   - Always classify evidence strictly as `OBSERVED` (unambiguous facts), `INFERRED` (deductive logic / ATT&CK mappings), or `POSSIBLE` (heuristic alerts / ML predictions).
   - Never artificially promote a heuristic signal into an observed fact.
2. **Deterministic Evidence Provenance:**
   - Every evidence item must contain an `evidence_id`, `source_component`, `timestamp`, `confidence`, and verifiable `data` payload.
3. **Inert Sample Handling & Zero Host Execution:**
   - Never commit live malware, exploit payloads, or operational malware to the repository.
   - Use synthetic test binaries (or tiny non-functional fixtures) in test suites.
   - Do not invoke host subprocesses to execute uploaded binaries.
4. **Transparent Research Claims:**
   - Do not claim production-grade malware execution or commercial antivirus equivalence.
   - Clearly identify synthetic benchmarks and document threats to validity.

---

## 2. Development Workflow

### 2.1 Branching Strategy
- `main`: Stable, release-ready branch. All commits must pass full CI.
- `feature/<description>`: New analysis engines, UI components, or research tools.
- `fix/<description>`: Bug fixes and security mitigations.
- `docs/<description>`: Documentation additions and clarifications.

### 2.2 Commit Message Conventions
We follow [Conventional Commits](https://www.conventionalcommits.org/):
- `feat: add CFG dominator tree computation in reverse analysis`
- `fix: trap integer overflow in PE data directory size calculation`
- `docs: update research benchmark methodology documentation`
- `test: add adversarial perturbation regression test for section injection`
- `refactor: extract evidence normalization utility`

---

## 3. Local Environment Setup

### 3.1 Backend Setup
```bash
# Clone the repository
git clone https://github.com/xXFlameboyXx/Igris.git
cd Igris

# Create virtual environment and install dependencies using uv
uv sync --extra dev
```

### 3.2 Frontend Setup
```bash
cd frontend
npm install
```

---

## 4. Verification Checklist Before Submitting a PR

Before opening a pull request, verify that all local test and lint checks pass cleanly:

```bash
# 1. Run full backend pytest suite (all 146+ tests must pass)
uv run pytest

# 2. Run Ruff security linter (with Bandit S-rules)
uv run ruff check .

# 3. Check Ruff formatting
uv run ruff format --check .

# 4. Run strict Mypy type checker
uv run mypy

# 5. Run Frontend TypeScript type check
cd frontend
npm test

# 6. Run Frontend ESLint
npm run lint

# 7. Run Frontend production build
npm run build
```

---

## 5. Security & Vulnerability Reporting

Do not open public GitHub issues for security vulnerabilities or parser crashes. Follow our responsible disclosure process in [`SECURITY.md`](SECURITY.md).
