# ML Features

The Phase 6 feature schema is versioned as:

`ml-static-reverse-feature-vector/v1`

Feature extraction is deterministic and uses existing safe analyses only. It
does not execute uploaded samples.

## Static Features

The baseline includes:

- file size
- section count
- entropy minimum, maximum, and mean
- import count
- resource count
- PE overlay size
- executable section count
- writable executable section count
- API category counts
- string category counts
- static evidence counts

## Reverse-Engineering Features

When reverse analysis is available and stable, the vector includes:

- function count
- instruction count
- total basic blocks
- maximum and mean cyclomatic complexity
- reverse evidence counts

Unsupported reverse analysis produces zero-valued reverse features rather than
failing inference.

## Ablation Sets

Feature sets are represented explicitly:

- `static_only`
- `static_reverse`
- `static_future_behavior`

The first baseline model uses `static_reverse`. Future experiments can compare
static-only and behavior-augmented variants without changing prediction schema.

## Missing Features

Inference validates the feature schema and model feature list. Missing model
features fail closed with `ml_missing_features` rather than silently changing the
model input shape.
