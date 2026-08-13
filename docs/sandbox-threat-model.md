# Sandbox Threat Model

This document defines the Phase 7 sandbox boundary. It is a design contract for
future real dynamic analysis, not an implementation of a sandbox backend.

## Isolation Target

The preferred future isolation target is a microVM / Firecracker-style
architecture. The Igris API process must never execute uploaded samples and must
not share secrets, database access, application storage credentials, or internal
network access with the sandbox environment.

## Trust Boundaries

Boundaries:

- API process: validates requests, stores metadata, and submits work references.
- Queue abstraction: carries job metadata, not raw sample bytes.
- Sandbox worker: retrieves a storage reference and talks to the disposable
  sandbox runtime.
- Sandbox guest: receives a staged sample in an isolated workspace.
- Artifact store: accepts only bounded, hashed, provenance-tracked outputs.

The current `InProcessJobQueue` is development-only and must not execute samples.

## Sample Lifecycle

Future real sandbox flow:

1. API records a sample and storage reference.
2. A sandbox work item is created with timeout, network policy, resource limits,
   and artifact policy.
3. A dedicated worker stages the sample into a disposable microVM workspace.
4. The guest runs instrumentation and emits structured telemetry.
5. The worker validates telemetry against `BehaviorAnalysisResult`.
6. Approved artifact metadata and bounded retained artifacts are stored.
7. The microVM and staging workspace are destroyed.

## Network Policy

Default network policy is `deny_all`.

Future network simulation may be designed as a controlled sinkhole, but it must
not provide uncontrolled internet egress, access to the application network, or
access to deployment secrets.

## Resource Limits

Future sandbox controllers must enforce:

- wall-clock timeout
- CPU count
- memory limit
- disk limit
- process count
- artifact count and artifact byte limits

Timeouts must produce a structured `timeout` result or a failed job state with
cleanup status recorded.

## Telemetry Boundary

The worker may accept only structured telemetry matching the Pydantic behavior
schemas. Untrusted guest output must be validated before persistence. Telemetry
must preserve provenance:

- analyzer version
- sandbox image
- analysis mode
- network policy
- resource limits
- exit reason
- artifact retention policy

## Cleanup Guarantees

Future implementations must destroy the sandbox instance and staging workspace
after success, failure, crash, or timeout. Cleanup failure is itself a security
event and must be observable.

## Security Invariants

- The API process never executes samples.
- The developer host never executes uploaded samples.
- The sandbox has no application secrets.
- The sandbox has no database access.
- The sandbox has no production network access.
- Artifacts are bounded, hashed, and provenance-tracked.
- Behavior evidence is evidence, not proof of maliciousness.
- Similarity is not attribution.
