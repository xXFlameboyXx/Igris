# Detection Scoring

Phase 3 produces a transparent heuristic risk score from `0` to `10`. The score
is not statistically calibrated and must not be described as a probability.

Use this wording:

```text
heuristic risk score
```

Do not use wording such as:

```text
96% probability of malware
```

## Score Components

The score is the sum of:

- rule contributions
- heuristic contributions
- bounded evidence-severity contributions

Rule and heuristic contributions are multiplied by confidence:

```text
effective contribution = configured contribution * confidence
```

Evidence contributes small bounded context:

- `info`: `0.00`
- `low`: `0.05 * confidence`
- `medium`: `0.12 * confidence`
- `high`: `0.20 * confidence`

Evidence contribution is capped at `1.5` so many weak observations cannot
overwhelm stronger combined reasoning.

## Status Thresholds

- `BENIGN`: no static evidence
- `UNKNOWN`: evidence exists, score below `1.5`
- `SUSPICIOUS`: score from `1.5` to below `5.0`
- `HIGHLY_SUSPICIOUS`: score `5.0` or higher

These thresholds are engineering heuristics. They are documented so they can be
reviewed and changed deliberately.

## Example Breakdown

```text
Process manipulation with memory management      +1.008
Writable executable section                      +0.760
Multiple possible packing indicators             +0.594
Process manipulation rule                        +1.326
Packing indicators rule                          +0.770
Evidence context                                 +1.500 cap
Total                                            5.958 / 10
```

## Limitations

Benign installers, administration tools, debuggers, security products, protected
commercial software, and development tools can trigger similar evidence. Phase 3
does not use sandboxing, dynamic behavior, ML, similarity analysis, reputation,
or external lookups.

