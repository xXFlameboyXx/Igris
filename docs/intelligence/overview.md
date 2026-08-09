# Threat Intelligence Mapping

Phase 5 converts raw static-analysis and reverse-engineering observations into
evidence-supported intelligence hypotheses. It does not execute samples, use ML,
query reputation systems, or perform actor attribution.

## Mapping Methodology

The pipeline is intentionally explicit:

```text
Observation -> Indicator -> Capability -> ATT&CK Technique
```

- Observation: a concrete artifact produced by earlier engines, such as static
  evidence or function-level reverse-engineering evidence.
- Indicator: a normalized signal derived from observations, strings, or API
  categories.
- Capability: an evidence-supported hypothesis such as Persistence, Execution,
  Defense Evasion, or Command and Control.
- ATT&CK Technique: a possible MITRE ATT&CK mapping when the evidence meets a
  versioned rule.

Rules live in `config/intelligence/attack_mappings.json`. The application loads
that JSON dataset through schema validation. The rules are declarative data, not
arbitrary executable code.

## Capability Taxonomy

Capabilities use this normalized taxonomy:

- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Collection
- Command and Control
- Exfiltration
- Impact

Igris does not assert a capability unless the mapping rule's required evidence
is present. A single API name or string is treated as weak context unless the
rule explicitly allows that low-confidence interpretation.

## Confidence Semantics

Confidence values are deterministic analyst weights between `0.0` and `1.0`.
They are not statistical probabilities and are not calibrated against a malware
population.

Labels distinguish the kind of statement:

- `OBSERVED`: the statement is directly supported by concrete evidence.
- `INFERRED`: multiple evidence items support a higher-level interpretation.
- `POSSIBLE`: evidence is relevant but may also appear in benign software.

The current dataset intentionally uses cautious confidence values because static
and reverse-engineering observations can be shared by installers, debuggers,
administration tools, security products, and normal updaters.

## ATT&CK Versioning

Each assessment records both the Igris intelligence engine version and the local
ATT&CK mapping dataset version. The initial dataset identifies itself as:

- mapping version: `attack-mapping/v1`
- ATT&CK version: `ATT&CK Enterprise v16.1`

Updating ATT&CK mappings should happen by changing the versioned JSON dataset
and adding focused tests for new evidence combinations.

## Evidence vs Inference

The narrative generator separates:

- `OBSERVED`: concrete lower-level evidence.
- `INFERRED`: ATT&CK and capability mappings derived from rule combinations.
- `POSSIBLE`: behavior hypotheses and caveats.

For example, a URL alone does not map to Command and Control. A networking API
plus a URL or domain can support possible Command and Control context, while
still warning that benign updaters may look similar.

## Attribution Limitations

Phase 5 includes an attribution interface placeholder for future family
hypotheses, similarity references, and attribution confidence. Those fields are
empty by design. Similarity is not attribution, and this phase does not identify
threat actors or malware families.
