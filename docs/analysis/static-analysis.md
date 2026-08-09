# Static Analysis

Phase 2 answers: "Does anything about this file look suspicious?" It produces
evidence and normalized features only. It does not produce a malware verdict,
score, or family classification.

## Security Model

Static analysis treats all sample bytes, strings, metadata, resources, and import
names as hostile input. The analyzer does not execute the sample, extracted
objects, scripts, commands found in strings, or embedded resources. It does not
open URLs, resolve domains, or connect to addresses discovered in files.

## String Analysis

Igris extracts ASCII and UTF-16LE strings with a configurable minimum length:

- `IGRIS_STATIC_MIN_STRING_LENGTH`
- `IGRIS_STATIC_MAX_STRINGS`

Strings include offsets, encoding, and section association when a section range is
known. Extracted strings are classified as URL, IPv4, IPv6, domain, email,
Windows path, Unix path, registry path, command/interpreter indicator,
suspicious keyword, or generic string.

String classifications are observations. A URL, registry path, or suspicious word
can appear in benign installers, security tools, documentation, and test files.

## Import And API Capability Analysis

Imports and API-like string references are normalized into a capability taxonomy:

- process management
- memory management
- filesystem
- registry
- networking
- cryptography
- service management
- system information
- process/thread manipulation
- other

API categories describe capabilities that may be relevant later. A single API is
rarely strong evidence by itself. Benign software can use networking,
cryptography, process APIs, and registry APIs for normal reasons.

## Section Analysis

Phase 2 extends Phase 1 section metadata with observations for:

- unusual section names
- writable plus executable sections
- high section entropy
- large virtual-size to raw-size gaps
- unusual section ordering

These are evidence items, not conclusions. Packed commercial software,
installers, and protectors can produce similar observations.

## Packing And Obfuscation Indicators

Igris records conservative indicators such as high entropy, unusual section
structure, writable executable sections, overlay data, and suspicious section
names. The wording intentionally uses "possible packing indicator" because these
features do not prove packing and do not prove malware.

The high-entropy threshold is configurable with:

```text
IGRIS_STATIC_HIGH_ENTROPY_THRESHOLD
```

## PE Features

Where practical, Phase 2 records:

- TLS directory presence
- overlay presence and size
- import descriptor count
- executable section count
- writable executable section count
- entry-point section
- suspicious entry-point section observation
- resource-directory metadata and hashes

Embedded resources are hashed as byte blobs and are never executed.

## Evidence Model

Each observation is normalized:

```json
{
  "evidence_id": "ev-...",
  "type": "HIGH_ENTROPY_SECTION",
  "source": "section_analysis",
  "severity": "medium",
  "confidence": 0.78,
  "description": "Section has high Shannon entropy.",
  "technical_details": {
    "section": ".packed",
    "entropy": 7.8
  },
  "location": {
    "offset": 512,
    "section": ".packed"
  },
  "related_object": ".packed"
}
```

Severity and confidence are scoped to the observation. They are not malware
scores.

## Feature Vector

The feature vector schema is versioned as:

```text
static-feature-vector/v1
```

It includes file size, section counts, entropy statistics, import counts, API
category counts, string category counts, resource count, overlay size, executable
section count, writable executable section count, and evidence counts.

The feature vector is deterministic and intended for future ML and explainability
systems. Phase 2 does not train or run an ML model.

## API

- `POST /api/v1/samples/{sample_id}/static-analysis`
- `GET /api/v1/samples/{sample_id}/static-analysis`
- `GET /api/v1/samples/{sample_id}/indicators`

The `POST` endpoint is idempotent. If static analysis already exists for a
sample, the stored result is returned.

## Limitations

Phase 2 does not implement sandboxing, dynamic execution, malware verdicts,
similarity analysis, ML, full disassembly, full resource carving, network
lookups, or advanced unpacking.
