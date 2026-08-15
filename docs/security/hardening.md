# Phase 17 Security Hardening, Threat Model & Defensive Security Review

## 1. Executive Summary & Review Verdict

This document presents the defensive security assessment and hardening review for the **Igris Malware Analysis & Intelligence Platform** across all components implemented from Phase 0 through Phase 16.

> [!IMPORTANT]
> **Audit Philosophy & Realistic Boundary:**
> - The objective is **not** to claim that Igris is impervious to attack.
> - The objective is to identify realistic security weaknesses, verify that input boundaries fail safely under malformed inputs, mitigate confirmed risks, maintain automated regression tests, and transparently document residual risks and deployment assumptions.

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│                           SECURITY AUDIT VERDICT:                                 │
│      SECURITY REVIEW COMPLETE — HARDENED WITH DOCUMENTED RESIDUAL RISK            │
└───────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Attack Surface & Architecture Review

Igris processes untrusted, potentially hostile binary programs. The end-to-end execution pipeline from upload to report generation was audited:

```
[Untrusted Client / Attacker]
         │  (HTTP Multipart Upload / REST API)
         ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│ Trust Boundary 1: API Gateway & Input Validation                                  │
│ • SecurityHeadersMiddleware: Nosniff, Frame-Deny, CSP, Referrer-Policy            │
│ • Request ID tracking, Error masking (no Python tracebacks / paths leaked)        │
│ • Upload streaming: 64KB chunks with strict max_upload_bytes (50MB default)       │
│ • Filename sanitization: Path.name stripping, regex character substitution        │
└───────────────────────────────────────────────────────────────────────────────────┘
         │
         ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│ Trust Boundary 2: Storage & Ingestion                                             │
│ • Content-addressed storage: Isolated data/samples/{sha256}.bin                   │
│ • Zero reliance on client-supplied filenames for disk paths                       │
│ • Temporary files created via mkstemp() and cleaned up on error                   │
└───────────────────────────────────────────────────────────────────────────────────┘
         │
         ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│ Trust Boundary 3: Binary Parsers & Static Analysis                                │
│ • PE & ELF Parsers: Bounds checks on headers, section offsets, and counts         │
│ • Truncated/corrupted binaries raise PEParseError/ELFParseError gracefully        │
│ • Disassembler: Capstone linear sweep bounded by reverse_max_instructions         │
│ • String Extractor: Bounded by static_max_strings (5,000 strings default)         │
└───────────────────────────────────────────────────────────────────────────────────┘
         │
         ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│ Trust Boundary 4: Orchestration & Execution Isolation                             │
│ • Analysis DAG orchestrator with per-stage timeouts (analysis_timeout_seconds)    │
│ • Isolated error capture: Stage failure does not crash pipeline                   │
│ • Emulated sandbox boundary: Safe synthetic telemetry for offline environments   │
└───────────────────────────────────────────────────────────────────────────────────┘
         │
         ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│ Trust Boundary 5: Investigation, Reporting & UI Presentation                      │
│ • Pure Python in-memory PDF renderer (zero external binaries or shell execution)  │
│ • Strict string escaping (_sanitize_pdf_text) for backslashes and parentheses     │
│ • React frontend: Zero dangerouslySetInnerHTML, full JSX auto-escaping            │
└───────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Updated Threat Model (Phases 1–16)

### 3.1 Assets
1. **Host Workstation / Server Integrity:** Host system executing the Igris backend and file parsers.
2. **Analysis Data & Metadata:** Extracted evidence, hashes, function graphs, and analyst notes.
3. **Reproducibility Artifacts:** Benchmark datasets, similarity indices, and historical reports.

### 3.2 Attacker Capabilities & Threat Agents
- **Malicious Upload Submitter:** Provides path-traversal filenames, oversized files, truncated PE/ELF headers, zip bombs, or pathological entropy streams.
- **Evasive Malware Author:** Obfuscates binary structures to trigger parser denial-of-service or memory exhaustion.
- **Local Network Attacker:** Attempts cross-site framing, clickjacking, or MIME confusion against the web UI.

### 3.3 Security Controls Matrix

| Attack Vector | Vulnerability Category | Implemented Defensive Control | Verification Status |
|---|---|---|---|
| Malicious Filename (`../../evil.exe`) | Path Traversal / Directory Escape | `sanitize_filename()` strips all path elements; disk storage uses SHA256 hashes. | **VERIFIED (Test)** |
| Multi-Gigabyte Upload Stream | Denial of Service / Disk Exhaustion | `_stream_to_temp` enforces `max_upload_bytes` per chunk; immediate 413 error and unlink. | **VERIFIED (Test)** |
| Truncated / Corrupted PE/ELF | Parser Crash / Unhandled Exception | Bounds-checked struct unpacking raising `PEParseError`/`ELFParseError` safely caught. | **VERIFIED (Test)** |
| Delimiter Injection in Reports | PDF Stream Syntax Corruption | `_sanitize_pdf_text()` escapes `\`, `(`, `)`, and strips unprintable control chars. | **VERIFIED (Test)** |
| API Unhandled Exception | Information Disclosure / Stack Leak | Global `app_error_handler` masks tracebacks into generic `"Unexpected server error"`. | **VERIFIED (Test)** |
| Browser Frame Hijacking | Clickjacking / MIME Sniffing | `SecurityHeadersMiddleware` sets `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`. | **VERIFIED (Test)** |
| Cross-Site Scripting (XSS) | DOM Injection in Analyst UI | React standard JSX escaping; zero `dangerouslySetInnerHTML` in frontend codebase. | **VERIFIED (Audit)** |

---

## 4. Confirmed Findings & Remediation Dossier

### Finding 1: Path Traversal Prevention in Filename Sanitization
- **Finding ID:** `SEC-001-PATH-TRAVERSAL-FILENAME`
- **Severity:** `MEDIUM`
- **Status:** `RESOLVED_FINDING`
- **Affected Component:** `FileIntelligenceService (sanitize_filename)`
- **Attack Preconditions:** Attacker submits malicious filename with `../` or backslashes.
- **Root Cause:** User-supplied filename header in multipart requests.
- **Remediation:** Normalized path separators, applied `Path.name` extraction, and substituted non-alphanumeric characters with safe underscores.
- **Regression Test:** [`test_path_traversal_filename_sanitization`](file:///e:/IGRIS/tests/backend/test_security_hardening.py#L31)
- **Residual Risk:** None for storage; sample files are stored strictly by content SHA256 digest (`data/samples/{sha256}.bin`).

### Finding 2: Resource Exhaustion via Unbounded Upload Stream
- **Finding ID:** `SEC-002-OVERSIZED-FILE-EXHAUSTION`
- **Severity:** `HIGH`
- **Status:** `RESOLVED_FINDING`
- **Affected Component:** `FileIntelligenceService (_stream_to_temp)`
- **Attack Preconditions:** Attacker attempts to stream gigabytes of data.
- **Root Cause:** Ingesting upload streams without chunk-level limit checks.
- **Remediation:** Evaluates `size_bytes > max_upload_bytes` on every 64KB chunk; raises HTTP 413 and unlinks temporary storage.
- **Regression Test:** [`test_oversized_upload_rejected`](file:///e:/IGRIS/tests/backend/test_security_hardening.py#L67)
- **Residual Risk:** Low; configurable via `IGRIS_MAX_UPLOAD_BYTES` (default: 50MB).

### Finding 3: Missing Defensive HTTP Response Security Headers
- **Finding ID:** `SEC-003-DEFENSIVE-HTTP-HEADERS`
- **Severity:** `LOW`
- **Status:** `RESOLVED_FINDING`
- **Affected Component:** `SecurityHeadersMiddleware`
- **Attack Preconditions:** Browser client accessing API in cross-origin or framing context.
- **Root Cause:** FastAPI default router does not include explicit security headers.
- **Remediation:** Added ASGI `SecurityHeadersMiddleware` enforcing `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, and `Content-Security-Policy`.
- **Regression Test:** [`test_security_headers_middleware_enforced`](file:///e:/IGRIS/tests/backend/test_security_hardening.py#L131)
- **Residual Risk:** None.

### Finding 4: PDF Content Stream Delimiter Injection
- **Finding ID:** `SEC-004-PDF-STREAM-DELIMITER-INJECTION`
- **Severity:** `MEDIUM`
- **Status:** `RESOLVED_FINDING`
- **Affected Component:** `PurePDFRenderer (_sanitize_pdf_text)`
- **Attack Preconditions:** Hostile sample or analyst notes containing unbalanced parentheses or backslashes.
- **Root Cause:** Direct insertion of arbitrary strings into PDF content streams.
- **Remediation:** Implement strict PDF string escaping and control character stripping in `_sanitize_pdf_text`.
- **Regression Test:** [`test_report_pdf_generation_text_sanitization`](file:///e:/IGRIS/tests/backend/test_security_hardening.py#L165)
- **Residual Risk:** None; pure in-memory generation without external subprocess execution.

---

## 5. Security Regression Test Suite

All security hardening tests are permanently integrated in [`tests/backend/test_security_hardening.py`](file:///e:/IGRIS/tests/backend/test_security_hardening.py):
1. `test_path_traversal_filename_sanitization`: Verifies `../../etc/shadow` and `..\\..\\calc.exe` are stripped to safe basenames.
2. `test_zero_byte_upload_handled_safely`: Verifies 0-byte upload is safely parsed as format empty without crashing.
3. `test_oversized_upload_rejected`: Verifies uploads exceeding `max_upload_bytes` return HTTP 413.
4. `test_malformed_pe_headers_handled_safely`: Verifies corrupted PE offsets raise `PEParseError` safely.
5. `test_malformed_elf_headers_handled_safely`: Verifies truncated ELF headers raise `ELFParseError` safely.
6. `test_security_headers_middleware_enforced`: Verifies `X-Content-Type-Options`, `X-Frame-Options`, and `CSP` on all endpoints.
7. `test_error_masking_no_stack_trace_leakage`: Verifies unhandled errors mask Python tracebacks and paths.
8. `test_report_pdf_generation_text_sanitization`: Verifies PDF renderer safely handles hostile inputs.
9. `test_secrets_and_config_sanitization`: Verifies `SecretStr` masks sensitive connection strings.

---

## 6. Static Scanner Verification

- **Ruff (Bandit Rules `S`):** `uv run ruff check .` $\to$ **All checks passed (0 errors across 168 files)**.
- **Mypy (Strict Typing):** `uv run mypy` $\to$ **Success (0 errors across 119 source files)**.
- **ESLint:** `npm run lint` $\to$ **Passed (0 errors, 0 warnings across frontend)**.

---

## 7. Deployment Assumptions & Residual Risks

### Implemented Controls (Verified):
- Robust content-addressed storage isolation with SHA256 hashing.
- Pure Python in-memory PDF report generator with full escaping.
- Input streaming limits and chunked file validation.
- Defensive ASGI HTTP security headers and error masking.

### Deployment Assumptions (Documented):
- **Single-Tenant Application:** Igris is currently designed as a single-tenant local/research platform. It does not implement multi-user RBAC or OAuth2/OIDC authentication.
- **Emulated Behavioral Sandbox:** Behavioral analysis in default test configurations uses synthetic/emulated telemetry. Live malware execution in production requires external hardware-isolated hypervisor VMs.
- **Network Perimeter:** Direct exposure of the Igris API to untrusted public networks requires a reverse proxy (e.g. Nginx, Envoy) with TLS termination and external authentication.
