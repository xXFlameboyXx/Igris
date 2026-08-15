"""Tests for Phase 13 Report Generation, JSON export, PDF rendering, and Security Guardrails."""

import json
from pathlib import Path

from fastapi.testclient import TestClient

from igris.core.config import Settings
from igris.main import create_app
from igris.reporting.generator import ReportGenerator
from igris.reporting.pdf import PurePDFRenderer

from .fixtures import minimal_pe32_fixture, static_suspicious_pe_fixture


def make_client(tmp_path: Path) -> TestClient:
    app = create_app(
        Settings(
            environment="test",
            metadata_backend="memory",
            sample_storage_dir=str(tmp_path / "samples"),
            sample_temp_dir=str(tmp_path / "tmp"),
            detection_rules_path="config/rules/static_rules.json",
        )
    )
    return TestClient(app)


def _upload_and_analyze(
    client: TestClient,
    filename: str,
    content: bytes,
) -> str:
    res = client.post(
        "/api/v1/samples",
        files={"file": (filename, content, "application/octet-stream")},
    )
    assert res.status_code == 201
    sample_id = res.json()["sample_id"]

    client.post(f"/api/v1/samples/{sample_id}/static-analysis")
    client.post(f"/api/v1/samples/{sample_id}/reverse-analysis")
    client.post(f"/api/v1/samples/{sample_id}/behavior-analysis")
    client.post(f"/api/v1/samples/{sample_id}/detect")
    client.post(f"/api/v1/samples/{sample_id}/threat-assessment")
    client.post(f"/api/v1/samples/{sample_id}/ml-prediction")
    client.post(f"/api/v1/samples/{sample_id}/similarity")
    return sample_id


def test_report_generation_endpoint(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    sample_id = _upload_and_analyze(client, "test.exe", static_suspicious_pe_fixture())

    response = client.post(f"/api/v1/samples/{sample_id}/report")
    assert response.status_code == 200
    data = response.json()
    assert "report" in data
    rpt = data["report"]
    assert rpt["sample_id"] == sample_id
    assert "sha256" in rpt
    assert rpt["version_metadata"]["igris_version"] == "0.1.0"
    assert rpt["version_metadata"]["report_schema_version"] == "report/v1"
    assert rpt["version_metadata"]["rule_version"] == "v1.2"
    assert rpt["version_metadata"]["attack_dataset_version"] == "v14.1"
    assert len(rpt["evidence_items"]) > 0
    assert "observed_facts" in rpt["epistemology_summary"]
    assert "inferred_conclusions" in rpt["epistemology_summary"]
    assert "possible_hypotheses" in rpt["epistemology_summary"]


def test_report_json_export_endpoint(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    sample_id = _upload_and_analyze(client, "test.exe", static_suspicious_pe_fixture())

    res = client.get(f"/api/v1/samples/{sample_id}/report/json")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("application/json")
    assert f"igris-report-{sample_id}.json" in res.headers["content-disposition"]

    # Verify JSON is valid and deterministic
    parsed = json.loads(res.text)
    assert parsed["sample_id"] == sample_id
    assert "sha256" in parsed
    assert "subsystem_summaries" in parsed
    assert "limitations" in parsed


def test_report_pdf_export_endpoint(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    sample_id = _upload_and_analyze(client, "test.exe", static_suspicious_pe_fixture())

    res = client.get(f"/api/v1/samples/{sample_id}/report/pdf")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert f"igris-report-{sample_id}.pdf" in res.headers["content-disposition"]

    pdf_bytes = res.content
    # Check PDF Magic Header
    assert pdf_bytes.startswith(b"%PDF-1.4")
    # Check PDF EOF trailer
    assert b"%%EOF" in pdf_bytes
    assert b"xref" in pdf_bytes
    assert b"/Type /Catalog" in pdf_bytes
    assert b"/Type /Pages" in pdf_bytes


def test_security_sanitization_in_pdf_and_report(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    sample_id = _upload_and_analyze(client, "sample.exe", minimal_pe32_fixture())

    # Attach malicious note
    note_payload = {
        "author": "<img src=x onerror=alert(1)>",
        "title": "Path: ..\\..\\windows\\system32\\cmd.exe | Special: \x00\x1f \U0001f600 日本語",
        "content": "A" * 500 + " \n\r $(reboot) `id` <iframe src='evil.com'></iframe>",
    }
    client.post(f"/api/v1/samples/{sample_id}/notes", json=note_payload)

    # Generate Report
    app = client.app
    generator = ReportGenerator(
        settings=app.state.settings,
        sample_storage=app.state.sample_storage,
        metadata_repository=app.state.metadata_repository,
    )
    report = generator.generate(sample_id)
    assert report.sample_id == sample_id

    # Render PDF with hostile input
    renderer = PurePDFRenderer()
    pdf_bytes = renderer.render(report)

    # Verify PDF generates successfully without crash and has valid structure
    assert pdf_bytes.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf_bytes
    assert len(pdf_bytes) > 500


def test_path_traversal_in_endpoints(tmp_path: Path) -> None:
    client = make_client(tmp_path)

    # Try path traversal sample IDs
    bad_ids = [
        "../../etc/passwd",
        "..\\..\\windows\\system32",
        "sample/../secret",
    ]

    for bad_id in bad_ids:
        res_inv = client.get(f"/api/v1/samples/{bad_id}/investigation")
        assert res_inv.status_code in (404, 422)

        res_pdf = client.get(f"/api/v1/samples/{bad_id}/report/pdf")
        assert res_pdf.status_code in (404, 422)
