from pathlib import Path

from fastapi.testclient import TestClient

from igris.core.config import Settings
from igris.main import create_app

from .fixtures import malformed_pe_fixture, reverse_x86_pe_fixture, unsupported_arm64_pe_fixture


def make_client(tmp_path: Path) -> TestClient:
    app = create_app(
        Settings(
            environment="test",
            metadata_backend="memory",
            sample_storage_dir=str(tmp_path / "samples"),
            sample_temp_dir=str(tmp_path / "tmp"),
            reverse_max_instructions=200,
            reverse_max_functions=16,
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


def test_reverse_analysis_must_be_run_before_get(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, reverse_x86_pe_fixture(), "reverse.exe")
        response = client.get(f"/api/v1/samples/{sample_id}/reverse-analysis")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "reverse_analysis_not_found"


def test_reverse_analysis_extracts_functions_cfg_and_call_graph(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, reverse_x86_pe_fixture(), "reverse.exe")
        run_response = client.post(f"/api/v1/samples/{sample_id}/reverse-analysis")
        get_response = client.get(f"/api/v1/samples/{sample_id}/reverse-analysis")

    assert run_response.status_code == 200
    assert get_response.status_code == 200
    result = run_response.json()["reverse_analysis"]
    assert result == get_response.json()["reverse_analysis"]
    assert result["status"] == "completed"
    assert result["disassembly"]["architecture"] == "x86"
    assert result["disassembly"]["engine"] == "capstone"
    assert result["disassembly"]["instruction_count"] >= 8
    assert len(result["functions"]) >= 2
    entry_function = result["functions"][0]
    assert entry_function["basic_block_count"] >= 2
    assert entry_function["cyclomatic_complexity"] >= 2
    assert "HKCU\\Software\\Igris" in entry_function["referenced_strings"]
    assert "VirtualAlloc" in entry_function["referenced_apis"]
    evidence_types = {item["type"] for item in entry_function["evidence"]}
    assert "STRING_API_CORRELATION" in evidence_types
    assert "SENSITIVE_CAPABILITY_CALL" in evidence_types
    assert result["call_graph"]["edges"]


def test_reverse_analysis_function_and_cfg_endpoints(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, reverse_x86_pe_fixture(), "reverse.exe")
        client.post(f"/api/v1/samples/{sample_id}/reverse-analysis")
        functions_response = client.get(f"/api/v1/samples/{sample_id}/functions")
        function_id = functions_response.json()["functions"][0]["function_id"]
        function_response = client.get(f"/api/v1/samples/{sample_id}/functions/{function_id}")
        cfg_response = client.get(f"/api/v1/samples/{sample_id}/cfg/{function_id}")

    assert functions_response.status_code == 200
    assert function_response.status_code == 200
    assert cfg_response.status_code == 200
    assert function_response.json()["function"]["function_id"] == function_id
    assert cfg_response.json()["cfg"]["function_id"] == function_id
    assert cfg_response.json()["cfg"]["blocks"]


def test_reverse_analysis_is_idempotent(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, reverse_x86_pe_fixture(), "reverse.exe")
        first = client.post(f"/api/v1/samples/{sample_id}/reverse-analysis").json()
        second = client.post(f"/api/v1/samples/{sample_id}/reverse-analysis").json()

    assert first == second


def test_unsupported_architecture_is_graceful(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, unsupported_arm64_pe_fixture(), "arm64.exe")
        response = client.post(f"/api/v1/samples/{sample_id}/reverse-analysis")

    assert response.status_code == 200
    result = response.json()["reverse_analysis"]
    assert result["status"] == "unsupported"
    assert "unsupported architecture" in result["disassembly"]["unsupported_reason"]


def test_malformed_binary_reverse_analysis_does_not_crash(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, malformed_pe_fixture(), "bad.exe")
        response = client.post(f"/api/v1/samples/{sample_id}/reverse-analysis")

    assert response.status_code == 200
    assert response.json()["reverse_analysis"]["status"] == "unsupported"
