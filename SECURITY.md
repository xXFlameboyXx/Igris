# Security Policy & Vulnerability Reporting

The **Igris** project treats defensive security as a foundational requirement. This document defines our security policy, supported versions, threat model, and responsible disclosure procedures.

---

## 1. Supported Versions

| Version | Supported | Security Review Status | Notes |
|---|---|---|---|
| **0.1.0 (Phase 18)** | **Yes** | **Hardened (Phase 17 Review)** | Current active release branch. |
| < 0.1.0 | No | Legacy Development Branches | Deprecated historical builds. |

---

## 2. Reporting a Vulnerability

If you discover a security vulnerability in Igris (including parser vulnerabilities, path traversal, injection flaws, memory exhaustion bugs, or denial-of-service risks), please report it responsibly.

### 2.1 Submission Guidelines
- **Contact:** Send an email to `security@igris-research.internal` (or submit a confidential security advisory via GitHub Security Advisories).
- **Include in your report:**
  1. Affected component, endpoint, or module (e.g., PE parser, upload handler, PDF generator).
  2. Clear, reproducible step-by-step instructions or non-destructive proof-of-concept.
  3. Impact assessment (e.g., parser crash, memory leak, authorization bypass).
  4. Suggested remediation if available.
- **Safety Requirement:** **DO NOT** attach live weaponized malware, zero-day exploit payloads, or production credentials. Use benign synthetic binary fixtures for demonstrations.

### 2.2 Response Timeline
- **Initial Acknowledgment:** Within 48 hours.
- **Triage & Reproduction:** Within 5 business days.
- **Patch & Advisory Release:** Within 30 days of confirmation.

---

## 3. Implemented Security Controls Summary

Following the Phase 17 defensive security review, the following controls are permanently enforced:

1. **Streaming Input Boundary:** Multipart uploads iterate in 64KB chunks and enforce `max_upload_bytes` (50MB default), rejecting oversized streams with HTTP 413.
2. **Path Traversal & Filename Neutralization:** All upload filenames are stripped to safe basenames via `sanitize_filename()`. Binaries are stored exclusively by content-addressed SHA-256 digests (`data/samples/{sha256}.bin`).
3. **Parser Exception Trapping:** PE and ELF parsers validate structural bounds and catch truncation/corruption gracefully as `PEParseError` and `ELFParseError`.
4. **Defensive HTTP Response Headers:** ASGI `SecurityHeadersMiddleware` sets `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, and strict `Content-Security-Policy`.
5. **Error Masking:** Global exception handlers catch unhandled server errors and mask Python tracebacks/internal filesystem paths from HTTP responses.
6. **Pure Python PDF Sanitization:** In-memory PDF report generator escapes backslashes and parentheses and strips unprintable control characters.
7. **DOM Escaping:** React UI renders all user and sample metadata via JSX escaping with zero `dangerouslySetInnerHTML`.

---

## 4. Documented Deployment Assumptions & Residual Risks

Igris operates under explicit deployment boundaries:

1. **Single-Tenant Local Research Application:**
   - Igris currently does not implement multi-user RBAC or OAuth2/OIDC authentication.
   - **Deployment Requirement:** If exposing Igris across a network or to multiple users, you **must** deploy a reverse proxy (e.g., Nginx, Envoy, Traefik) providing TLS termination, rate limiting, and external authentication.
2. **Behavioral Analysis Sandbox Boundary:**
   - Default dynamic analysis uses deterministic synthetic simulation.
   - **Deployment Requirement:** Live execution of untrusted binaries must only take place in dedicated, isolated hypervisor virtual machines with sinkholed networking.
