# Phase 7 Behavior Analysis

Phase 7 adds a behavior-analysis evidence layer without executing uploaded
samples in the API process or developer environment.

## Current Analyzer

The current analyzer is `SyntheticBehaviorAnalyzer`. It produces deterministic
synthetic telemetry for exercising schemas, APIs, evidence mapping, scoring, and
feature extraction. It does not read sample bytes, execute files, start
subprocesses, open sockets, or communicate with a sandbox runtime.

Every synthetic result is marked:

- `sandbox_metadata.analysis_mode = "synthetic"`
- `sandbox_metadata.synthetic_scenario = "<scenario>"`
- `sandbox_metadata.network_policy = "deny_all"`

Synthetic behavior is pipeline test evidence, not an observation of the
uploaded sample.

## API Boundary

Behavior analysis is explicit:

- `POST /api/v1/samples/{sample_id}/behavior-analysis`
- `GET /api/v1/samples/{sample_id}/behavior-analysis`
- `GET /api/v1/samples/{sample_id}/behavior-events`
- `GET /api/v1/samples/{sample_id}/behavior-evidence`

Upload, static analysis, detection, threat intelligence, and ML prediction do
not automatically run behavior analysis.

## Downstream Consumption

Once a behavior result is cached on a sample, later engines may consume it:

- Detection adds conservative behavior heuristics and score contributions.
- Threat intelligence maps behavior evidence into the evidence graph and
  low-confidence ATT&CK hypotheses.
- ML feature extraction populates `static_future_behavior` slots from cached
  behavior telemetry.

If behavior analysis is created after derived results already exist, cached
detection, threat assessment, and ML prediction are invalidated so later runs can
include the new evidence.

## Artifact Policy

Behavior metadata includes an `ArtifactRetentionPolicy`:

- default mode: `metadata_only`
- hash algorithm: `sha256`
- bounded artifact count and size
- provenance required

Current synthetic dropped files are metadata-only records. No artifact bytes are
created or retained.

## Limitations

- No real sandbox exists yet.
- No uploaded sample execution occurs.
- Synthetic scenarios do not describe the uploaded file's actual behavior.
- Network simulation is not implemented.
- Behavior-to-detection and behavior-to-ATT&CK mappings are conservative
  evidence contributions, not malware verdicts.
