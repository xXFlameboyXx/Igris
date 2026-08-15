# ML Training

Phase 6 training is reproducible and local. The baseline trainer:

1. loads `config/ml/synthetic_dataset.json`
2. validates dataset and feature schema metadata
3. removes duplicate SHA-256 records
4. prepares train/validation/test splits
5. trains three baseline model families
6. evaluates validation and test metrics
7. selects a model by validation F1, then lower false-positive rate
8. writes a versioned model artifact and registry

## Baselines

Implemented model families:

- Logistic Regression
- Random Forest
- Gradient Boosting

Deep learning is intentionally out of scope. The dataset is too small and too
synthetic to justify it.

## Versioning

Every selected model records:

- model version
- model kind
- feature schema version
- dataset version
- training timestamp
- hyperparameters
- test metrics
- model artifact path
- important features

The current registry lives at `config/ml/model_registry.json`, and model
artifacts live under `config/ml/models/`.

## Reproduce

Run the baseline from the repository root:

```powershell
uv --cache-dir E:\IGRIS\.uv-cache run python -c "from pathlib import Path; from igris.ml.dataset import load_dataset_manifest; from igris.ml.training import run_baseline_experiment, write_registry; dataset=load_dataset_manifest(Path('config/ml/synthetic_dataset.json')); registry=run_baseline_experiment(dataset=dataset, output_dir=Path('config/ml/models')); write_registry(registry, Path('config/ml/model_registry.json'))"
```
