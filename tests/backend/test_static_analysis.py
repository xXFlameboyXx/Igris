from pathlib import Path

from fastapi.testclient import TestClient

from igris.core.config import Settings
from igris.main import create_app

from .fixtures import malformed_pe_fixture, minimal_elf64_fixture, static_suspicious_pe_fixture


def make_client(tmp_path: Path) -> TestClient:
    app = create_app(
        Settings(
            environment="test",
            metadata_backend="memory",
            sample_storage_dir=str(tmp_path / "samples"),
            sample_temp_dir=str(tmp_path / "tmp"),
            static_high_entropy_threshold=6.0,
        )
    )
    return TestClient(app)


def upload(client: TestClient, content: bytes, filename: str = "sample.bin") -> str:
    response = client.post(
        "/api/v1/samples",
        files={"file": (filename, content, "application/octet-stream")},
    )
    assert response.status_code == 201, response.text
    return str(response.json()["sample_id"])


def test_static_analysis_requires_existing_sample(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        response = client.post("/api/v1/samples/missing/static-analysis")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "sample_not_found"


def test_static_analysis_must_be_run_before_get(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, b"hello")
        response = client.get(f"/api/v1/samples/{sample_id}/static-analysis")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "static_analysis_not_found"


def test_static_analysis_extracts_strings_api_capabilities_and_indicators(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, static_suspicious_pe_fixture(), "benign-test.exe")
        run_response = client.post(f"/api/v1/samples/{sample_id}/static-analysis")
        get_response = client.get(f"/api/v1/samples/{sample_id}/static-analysis")
        indicators_response = client.get(f"/api/v1/samples/{sample_id}/indicators")

    assert run_response.status_code == 200
    assert get_response.status_code == 200
    assert indicators_response.status_code == 200
    analysis = run_response.json()["analysis"]
    assert analysis == get_response.json()["analysis"]
    assert analysis["status"] == "completed"
    categories = {item["category"] for item in analysis["strings"]}
    expected_categories = {
        "url",
        "ipv4",
        "registry_path",
        "command_interpreter",
        "suspicious_keyword",
    }
    assert expected_categories <= categories
    api_categories = {item["category"] for item in analysis["imports"]}
    assert "memory_management" in api_categories
    assert "process_thread_manipulation" in api_categories
    evidence_types = {item["type"] for item in analysis["evidence"]}
    assert "HIGH_ENTROPY_SECTION" in evidence_types
    assert "EXECUTABLE_WRITABLE_SECTION" in evidence_types
    assert "UNUSUAL_SECTION_NAME" in evidence_types
    assert "OVERLAY_PRESENT" in evidence_types
    assert "RESOURCE_PRESENT" in evidence_types
    assert indicators_response.json()["indicators"] == analysis["evidence"]


def test_static_feature_vector_is_versioned_and_counts_observations(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, static_suspicious_pe_fixture(), "benign-test.exe")
        response = client.post(f"/api/v1/samples/{sample_id}/static-analysis")

    vector = response.json()["analysis"]["feature_vector"]
    assert vector["schema_version"] == "static-feature-vector/v1"
    assert vector["file_size"] == len(static_suspicious_pe_fixture())
    assert vector["number_of_sections"] == 1
    assert vector["resource_count"] == 1
    assert vector["overlay_size"] == 256
    assert vector["writable_executable_section_count"] == 1
    assert vector["import_count"] >= 2
    assert vector["evidence_counts"]["POSSIBLE_PACKING_INDICATOR"] >= 1


def test_benign_networking_api_is_evidence_not_verdict(tmp_path: Path) -> None:
    content = b"This benign tool calls InternetOpenA for updater checks only."
    with make_client(tmp_path) as client:
        sample_id = upload(client, content, "benign.txt")
        response = client.post(f"/api/v1/samples/{sample_id}/static-analysis")

    analysis = response.json()["analysis"]
    assert analysis["feature_vector"]["api_category_counts"]["networking"] == 1
    assert all("malware" not in item["description"].lower() for item in analysis["evidence"])


def test_static_analysis_handles_malformed_pe_without_crashing(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, malformed_pe_fixture(), "malformed.exe")
        response = client.post(f"/api/v1/samples/{sample_id}/static-analysis")

    assert response.status_code == 200
    analysis = response.json()["analysis"]
    assert analysis["status"] == "completed"
    assert analysis["feature_vector"]["number_of_sections"] == 0


def test_static_analysis_on_elf_extracts_sections_without_pe_features(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, minimal_elf64_fixture(), "fixture")
        response = client.post(f"/api/v1/samples/{sample_id}/static-analysis")

    assert response.status_code == 200
    analysis = response.json()["analysis"]
    assert analysis["pe_features"] is None
    assert analysis["feature_vector"]["number_of_sections"] >= 2
    assert analysis["limitations"] == ["PE-only static features are not applicable to this format."]
