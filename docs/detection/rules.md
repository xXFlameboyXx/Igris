# Detection Rules

Igris Phase 3 uses declarative JSON rules. Rule files are data, not executable
Python code. This keeps custom rule execution separate from application logic and
avoids blindly running arbitrary code.

Default rules live in:

```text
config/rules/static_rules.json
```

The active path is configured with:

```text
IGRIS_DETECTION_RULES_PATH
```

## Rule Shape

```json
{
  "rule_id": "IGRIS-RULE-0001",
  "name": "Network Indicators With Suspicious Strings",
  "description": "Networking capability appears together with suspicious strings.",
  "severity": "medium",
  "confidence": 0.72,
  "version": "1.0.0",
  "contribution": 1.2,
  "evidence": "Networking API/category co-occurs with suspicious strings.",
  "conditions": [
    {
      "field": "api_category_counts.networking",
      "operator": ">=",
      "value": 1
    }
  ]
}
```

## Supported Operators

- `exists`
- `==`
- `!=`
- `>=`
- `>`
- `<=`
- `<`
- `contains`
- `in`

Rules evaluate against the Phase 2 static feature vector, including API category
counts, string counts, evidence counts, section counts, resource count, and
overlay size.

## Reloadability

Rules are loaded from the configured JSON file when detection runs. Updating the
JSON file changes detection behavior without changing core Python code. Invalid
rules fail validation and the engine fails closed with a structured error.

## Current Built-In Rules

`IGRIS-RULE-0001`: Networking indicators with suspicious strings.

`IGRIS-RULE-0002`: Process manipulation with writable executable section.

`IGRIS-RULE-0003`: Multiple packing indicators.

These rules intentionally reason about combinations rather than isolated APIs.

