# Phase 10: Sample Similarity Analysis

## 1. Overview & Core Objective

Phase 10 introduces multi-level, explainable sample similarity analysis to the Igris platform. The system answers the analytical question:

> *"What known samples or historical analysis records does this sample resemble?"*

### Fundamental Tenet: Similarity $\neq$ Attribution
Similarity is technical evidence of structural and behavioral overlap, **not** proof of common authorship or malicious family membership. High similarity indicates a **possible related cluster** hypothesis. The system strictly avoids making automated or unsupported claims regarding:
- Confirmed malware family attribution
- Threat actor attribution
- Threat campaign or adversary group attribution

---

## 2. Multi-Level Similarity Architecture

To avoid collapsing distinct technical layers into an opaque single score, similarity is evaluated and preserved across three independent dimensions alongside an adaptive overall similarity score:

```
                          ┌─────────────────────────────┐
                          │   Hostile Sample (Target)   │
                          └──────────────┬──────────────┘
                                         │
                         [Feature Extraction & Normalization]
                                         │
                 ┌───────────────────────┼───────────────────────┐
                 ▼                       ▼                       ▼
      ┌────────────────────┐  ┌────────────────────┐  ┌────────────────────┐
      │  File Similarity   │  │  Code Similarity   │  │Behavior Similarity │
      │  (APIs, Strings,   │  │(Functions, Opcodes │  │(Processes, Registry│
      │   Section Profile) │  │ Mnemonic Vector)   │  │ Network, Mutexes)  │
      └──────────┬─────────┘  └──────────┬─────────┘  └──────────┬─────────┘
                 │                       │                       │
                 └───────────────────────┼───────────────────────┘
                                         ▼
                          ┌─────────────────────────────┐
                          │     Adaptive Overall Score  │
                          │   & Explainable Hypothesis  │
                          └─────────────────────────────┘
```

### A. File Similarity
- **Imported APIs**: Jaccard similarity over normalized `dll!function` tokens.
- **Section Profile**: Jaccard similarity over section names combined with average entropy delta across matching sections.
- **Indicator Strings**: Jaccard similarity over normalized, non-trivial strings and IOC patterns.
- **Binary Format**: Compatibility check across PE / ELF format classification.

### B. Code Similarity
- **Function Structural Signatures**: Ratio of function counts and basic block / instruction count signatures.
- **Opcode Frequency Distribution**: Cosine similarity across instruction mnemonic histograms (e.g., `mov`, `push`, `pop`, `call`, `xor`, `cmp`, `sub`, `add`, `test`, `lea`).

### C. Behavior Similarity
- **Spawned Processes**: Jaccard similarity over normalized child process executable names.
- **Registry Modifications**: Jaccard similarity over canonical registry target paths.
- **Network Endpoints**: Jaccard similarity over destination IPs, domains, and port tuples.
- **Mutex Objects**: Jaccard similarity over created synchronization mutex names.

---

## 3. Feature Normalization & Noise Filtering

To ensure similarity reflects genuine technical design rather than incidental build noise, features undergo deterministic normalization prior to comparison:

1. **API Normalization**:
   - Case-folding (`Kernel32.dll` $\rightarrow$ `kernel32.dll`).
   - Normalizing ordinal suffixes (`CreateProcessA@12` $\rightarrow$ `createprocessa`).
   - Standardizing `dll!function` schema.
2. **Noise & Metadata Stripping**:
   - Explicit exclusion of ephemeral identifiers (sample IDs, storage paths, hash digests, UUIDs).
   - Exclusion of compilation timestamps from file-level similarity.
   - Filtering short strings (< 4 characters) and runtime allocator boilerplate.
3. **Behavior Canonicalization**:
   - Normalizing registry root abbreviations (`HKCU\` vs `HKEY_CURRENT_USER\`).
   - Lowercasing network hosts and process image names.

---

## 4. Explainable Scoring & Missing Data Handling

### Adaptive Weighting
When all three evidence layers are available:
$$\text{Overall} = 0.40 \times \text{FileSim} + 0.35 \times \text{CodeSim} + 0.25 \times \text{BehaviorSim}$$

When behavioral analysis has not been executed:
$$\text{Overall} = 0.55 \times \text{FileSim} + 0.45 \times \text{CodeSim}$$

When only static file-level features are present:
$$\text{Overall} = 1.0 \times \text{FileSim}$$

### Handling Unavailable Features
- Missing features never artificially inflate similarity.
- If behavioral analysis was not executed for either sample, `behavior_similarity` is explicitly recorded as `None` (rather than `0.0` or `1.0`), and behavioral categories are marked unobserved in the report.

### Hypothesis and Confidence Classification
- **`possible_related_cluster`**: Assigned when `overall_similarity >= 0.70` with matching cross-layer feature categories.
- **`unrelated`**: Assigned when overall similarity is below threshold.
- **Confidence Rating**:
  - `HIGH`: 3 corroborated evidence layers or near-identical score ($\ge 0.95$).
  - `MEDIUM`: 2 corroborated evidence layers.
  - `LOW`: Single evidence layer or sparse candidate data.

---

## 5. Similarity Index Architecture

The similarity system defines a modular `SimilarityIndex` interface separating feature extraction from storage engines:

- **`SimilarityIndex` (Abstract Interface)**: Supports `index_sample()`, `get_features()`, `list_candidates()`, and `remove()`.
- **`InMemorySimilarityIndex`**: High-performance transient index for unit tests and local evaluation.
- **`RepositorySimilarityIndex`**: Production-ready implementation backed by `SampleMetadataRepository`, extracting and caching normalized feature vectors directly from stored samples.

---

## 6. Schema & API Contracts

### REST API Endpoints

#### 1. Execute Similarity Analysis
- **`POST /api/v1/samples/{sample_id}/similarity`**
- **Query Params**: `max_matches` (default: 20)
- **Response**: `200 OK` with `SimilarityResponse` (and caches result on `sample.similarity_analysis`).

#### 2. Retrieve Cached Similarity Results
- **`GET /api/v1/samples/{sample_id}/similarity/results`**
- **Response**: `200 OK` with `SimilarityResultsResponse` or `404 Not Found` (`similarity_not_found` if not yet analyzed, `sample_not_found` if sample missing).

---

## 7. Versioning & Dataset Identifiers

Every report embeds explicit version identifiers:
- `schema_version`: `"similarity/v1"`
- `feature_version`: `"similarity_features/v1"`
- `scoring_version`: `"similarity_scoring/v1"`

Future modifications to feature extraction or scoring matrices will increment these versions without altering historical similarity records.
