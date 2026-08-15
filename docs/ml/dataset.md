# ML Dataset

Phase 6 uses a legally safe synthetic dataset at
`config/ml/synthetic_dataset.json`.

## Provenance

The initial dataset contains synthetic feature records derived from Igris test
fixture patterns. It does not include downloaded malware, third-party malware
collections, or unknown binaries.

Dataset metadata records:

- dataset version: `synthetic-phase6/v1`
- license: `MIT; synthetic project-owned test data`
- source: `Igris synthetic fixture`
- label: `benign` or `malware`
- split: `train`, `validation`, or `test`
- optional family/group name for leakage-aware splitting

## Leakage Controls

The splitter removes duplicate SHA-256 records before training. When records do
not already specify splits, grouping can use the `family` field so related
samples stay in one split.

The synthetic baseline currently uses explicit train/validation/test splits and
unique synthetic SHA-256 values. This validates the pipeline mechanics but does
not solve real-world family leakage.

## Limitations

Synthetic labels are fixture intent, not threat-intelligence ground truth.
Metrics from this dataset must not be presented as operational malware-detection
performance.
