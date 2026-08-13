# ML Explainability

ML predictions expose important contributing features when the selected model
supports feature importance or coefficients.

## What It Means

For tree-based models, feature importance describes how much a feature influenced
model splits across the fitted ensemble. For linear models, coefficient
magnitude is used.

The prediction endpoint returns:

- model version
- feature schema version
- prediction
- uncalibrated score
- uncertainty band
- important contributing features
- limitations

## What It Does Not Mean

Feature importance is not causal proof. A high feature score does not prove a
file is malicious, and the ML prediction is only one evidence source alongside
rules, heuristics, static analysis, reverse engineering, and threat-intelligence
mapping.

## Probability Calibration

Phase 6 does not perform probability calibration. Therefore
`calibrated_probability` is always `null`, and the numeric `score` must be read
as an uncalibrated model score.
