# Igris REST API Reference Manual

The **Igris Malware Analysis & Intelligence Platform** provides a structured, versioned REST API built on FastAPI.

- **Base URL:** `http://127.0.0.1:8000/api/v1`
- **Interactive OpenAPI Documentation:** `http://127.0.0.1:8000/docs`
- **Machine-Readable OpenAPI Schema:** `http://127.0.0.1:8000/openapi.json`

---

## 1. Global Request & Response Conventions

### 1.1 Standard Error Response
All error responses adhere to a consistent JSON envelope with request tracking:
```json
{
  "success": false,
  "error": {
    "code": "sample_not_found",
    "message": "Sample with ID '88a1b2...' does not exist."
  },
  "request_id": "4b68e9f2-2b63-47a2-9b2f-48e02d6b38c1"
}
```

### 1.2 Defensive HTTP Security Headers
Every HTTP response includes:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy: default-src 'self'`

---

## 2. Sample Ingestion & Management

### 2.1 Upload Binary Sample
- **Route:** `POST /api/v1/samples`
- **Content-Type:** `multipart/form-data`
- **Body:** `file` (Binary payload, max 50MB)
- **Status Codes:** `201 Created`, `400 Bad Request`, `413 Payload Too Large`

#### Example Response (`201 Created`):
```json
{
  "sample_id": "88a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef",
  "filename": "benign_tool.exe",
  "safe_filename": "benign_tool.bin",
  "size_bytes": 14336,
  "sha256": "88a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef",
  "detected_format": "pe",
  "status": "completed"
}
```

### 2.2 Retrieve File Intelligence
- **Route:** `GET /api/v1/samples/{sample_id}/file-info`
- **Status Codes:** `200 OK`, `404 Not Found`

---

## 3. Analysis Orchestration & Engine Pipelines

### 3.1 Run Orchestrated Analysis Pipeline
- **Route:** `POST /api/v1/analyses/pipeline`
- **Request Body:**
  ```json
  {
    "sample_id": "88a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef",
    "enabled_stages": ["static", "reverse", "detection", "ml", "behavioral", "similarity", "intelligence", "assessment"]
  }
  ```
- **Status Codes:** `200 OK`, `404 Not Found`

### 3.2 Individual Analysis Endpoints
- `GET /api/v1/analyses/static/{sample_id}`: Strings, sections, imports, overlay data.
- `GET /api/v1/analyses/reverse/{sample_id}`: Capstone disassembly, basic blocks, CFG.
- `GET /api/v1/analyses/detection/{sample_id}`: Static YAML rules & heuristic hits.
- `GET /api/v1/analyses/ml/{sample_id}`: Classifier predictions & SHAP explanations.
- `GET /api/v1/analyses/behavioral/{sample_id}`: Synthetic telemetry process/registry/network graph.
- `GET /api/v1/analyses/similarity/{sample_id}`: SSDEEP / TLSH cluster matches.
- `GET /api/v1/analyses/assessment/{sample_id}`: Epistemological verdict & risk breakdown.

---

## 4. Investigation Workspace & Dossier Reports

### 4.1 Save Workspace State & Bookmarks
- **Route:** `POST /api/v1/investigation/{sample_id}/workspace`
- **Status Codes:** `200 OK`, `400 Bad Request`

### 4.2 Generate & Download Pure PDF Dossier
- **Route:** `GET /api/v1/reports/{report_id}/pdf`
- **Response Content-Type:** `application/pdf`
- **Status Codes:** `200 OK`, `404 Not Found`

---

## 5. Research, Benchmarking & Robustness

### 5.1 Run Evaluation Experiment
- **Route:** `POST /api/v1/experiments/run`
- **Request Body:**
  ```json
  {
    "dataset_name": "synthetic_research_v1",
    "ablation_config": "full_pipeline",
    "split_strategy": "family_stratified"
  }
  ```
- **Status Codes:** `200 OK`, `422 Validation Error`

### 5.2 Run Adversarial Robustness Matrix
- **Route:** `POST /api/v1/robustness/evaluate`
- **Request Body:**
  ```json
  {
    "sample_id": "88a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef",
    "transformations": ["rename", "metadata_strip", "string_obfuscate", "section_inject", "noop_pad"]
  }
  ```
- **Status Codes:** `200 OK`, `404 Not Found`
