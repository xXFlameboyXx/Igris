# Responsible Use & Malware Handling Safety Policy

## 1. Overview and Purpose

The **Igris Malware Analysis & Intelligence Platform** is designed strictly for defensive cybersecurity research, academic investigation, digital forensics, reverse engineering education, and authorized security operations.

This document establishes the mandatory safety, legal, and operational guidelines governing the deployment, development, and use of Igris.

---

## 2. Core Operational Principles

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│                           DEFENSIVE RESEARCH MANDATE                              │
│                                                                                   │
│ 1. AUTHORIZED ANALYSIS ONLY: Analyze only samples for which you possess explicit  │
│    written authorization or ownership.                                            │
│ 2. NON-OPERATIONAL SAFETY: Igris does not contain offensive malware payloads,     │
│    evasion frameworks, or operational exploit tools.                              │
│ 3. HOST ISOLATION: Host environments must never execute untrusted binary samples. │
│ 4. SAFE TELEMETRY BOUNDARY: Default behavioral simulation uses synthetic traces.  │
└───────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Sample Handling & Laboratory Safety

### 3.1 Host Execution Prohibition
- **Never execute untrusted or unknown binaries directly on the host system** running the Igris backend API or analyst interface.
- Igris performs **pure static inspection, linear disassembly, and metadata extraction**. All file handling occurs through stream-bounded, content-addressed storage (`data/samples/{sha256}.bin`).

### 3.2 Behavioral Analysis Boundary
- The default behavioral analysis subsystem in Igris uses **deterministic synthetic simulation** ([`SyntheticBehaviorAnalyzer`](file:///e:/IGRIS/backend/src/igris/analysis/behavioral/synthetic.py)) to model process execution, registry modifications, network connections, and filesystem hooks without executing code.
- If integrating an external dynamic analysis sandbox for live malware execution:
  - You **must** utilize dedicated, hardware-isolated hypervisor virtual machines (e.g., KVM, Proxmox, VMware ESXi).
  - The guest VM network **must** be isolated behind an air-gapped virtual bridge or software-defined honeynet with internet access disabled or strictly sinkholed.
  - Snapshots **must** be reverted automatically after each analysis session.

### 3.3 Storage and Inert Handling
- Store samples in restricted directories with non-executable filesystem permissions (`chmod 0600` on POSIX systems).
- Always retain samples under content-addressed names (`.bin` extension) rather than original executable extensions (`.exe`, `.elf`, `.scr`).

---

## 4. Prohibited Uses

The following activities are strictly prohibited:

1. **Malware Distribution & Weaponization:** Using Igris components or perturbation operators to develop, test, optimize, or deploy operational malware, rootkits, ransomware, or evasion tooling.
2. **Unauthorized Inspection:** Uploading proprietary, confidential, or sensitive third-party software without authorization.
3. **Operational Disruption:** Attempting denial-of-service or stress testing against shared or production infrastructure without permission.
4. **Public Exposure of Unprotected APIs:** Exposing unauthenticated Igris instances directly to the public internet.

---

## 5. Research & Academic Integrity

When publishing research or benchmarking results derived from Igris:
- **Disclose Dataset Provenance:** Transparently distinguish synthetic/demo datasets from real-world malware corpora.
- **Acknowledge Epistemological Limitations:** Differentiate directly observed facts (`OBSERVED`) from statistical inferences (`INFERRED`) or heuristic indicators (`POSSIBLE`).
- **Prevent Data Leakage:** Ensure test sets are strictly partitioned by malware family and compile date to avoid synthetic inflation of classification metrics.

---

## 6. Vulnerability Disclosure

If you discover a security vulnerability in Igris itself (e.g., parser panic, path traversal, injection flaw), please follow the responsible disclosure process outlined in [`SECURITY.md`](../SECURITY.md).
