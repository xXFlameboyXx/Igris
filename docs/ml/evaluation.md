# ML Evaluation

Phase 6 reports metrics beyond accuracy:

- precision
- recall
- F1
- confusion matrix
- false-positive rate
- ROC-AUC when score output is available and both classes are present
- inference time per sample

Malware is treated as the positive class.

## Baseline Result

The initial synthetic experiment compares:

- Logistic Regression
- Random Forest
- Gradient Boosting

The selected model is recorded in `config/ml/model_registry.json`. The current
numbers are useful for checking that the pipeline trains, evaluates, versions,
loads, and predicts correctly.

## Interpretation

The synthetic baseline is not a claim that the ML system is operationally better
than deterministic rules or heuristics. Real evaluation would require a legally
sourced dataset with documented provenance, family-aware splits, duplicate and
near-duplicate controls, and representative benign software.

## False Positives

False-positive rate is recorded because benign administration tools, installers,
security products, and developer tools can share many static indicators with
malware-like samples.
