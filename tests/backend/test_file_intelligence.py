import hashlib
from pathlib import Path

from fastapi.testclient import TestClient

from igris.analysis.file_intelligence.entropy import shannon_entropy
from igris.analysis.file_intelligence.service import sanitize_filename
from igris.core.config import Settings
from igris.main import create_app

from .fixtures import (
    malformed_elf_fixture,
    malformed_pe_fixture,
    minimal_elf64_fixture,
    minimal_pe32_fixture,
)


def make_client(tmp_path: Path, max_upload_bytes: int = 1024 * 1024) -> TestClient:
    app = create_app(
        Settings(
            environment="test",
            metadata_backend="memory",
            sample_storage_dir=str(tmp_path / "samples"),
            sample_temp_dir=str(tmp_path / "tmp"),
            max_upload_bytes=max_upload_bytes,
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


def test_empty_file_upload(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, b"", "empty.bin")
        response = client.get(f"/api/v1/samples/{sample_id}/file-info")

    assert response.status_code == 200
    payload = response.json()
    assert payload["file"]["size_bytes"] == 0
    assert payload["file"]["detected_format"] == "empty"
    assert payload["file"]["entropy"] == 0.0


def test_text_file_hashes_and_entropy(tmp_path: Path) -> None:
    content = b"hello igris\n"
    expected_sha256 = hashlib.sha256(content).hexdigest()
    expected_sha1 = hashlib.sha1(content, usedforsecurity=False).hexdigest()
    expected_md5 = hashlib.md5(content, usedforsecurity=False).hexdigest()

    with make_client(tmp_path) as client:
        sample_id = upload(client, content, "../evil.txt")
        sample_response = client.get(f"/api/v1/samples/{sample_id}")
        info_response = client.get(f"/api/v1/samples/{sample_id}/file-info")

    assert sample_response.status_code == 200
    assert sample_response.json()["safe_filename"] == "evil.txt"
    payload = info_response.json()
    assert payload["hashes"] == {
        "sha256": expected_sha256,
        "sha1": expected_sha1,
        "md5": expected_md5,
    }
    assert payload["file"]["detected_format"] == "text"
    assert payload["file"]["mime_type"] == "text/plain"
    assert payload["file"]["entropy"] == shannon_entropy([content])


def test_malformed_pe_does_not_crash_api(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, malformed_pe_fixture(), "bad.exe")
        response = client.get(f"/api/v1/samples/{sample_id}/file-info")

    assert response.status_code == 200
    payload = response.json()
    assert payload["file"]["detected_format"] == "pe"
    assert payload["file"]["pe"] is None
    assert payload["file"]["entry_point"]["state"] == "failed"
    assert payload["file"]["parse_errors"]


def test_malformed_elf_does_not_crash_api(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, malformed_elf_fixture(), "bad")
        response = client.get(f"/api/v1/samples/{sample_id}/file-info")

    assert response.status_code == 200
    payload = response.json()
    assert payload["file"]["detected_format"] == "elf"
    assert payload["file"]["elf"] is None
    assert payload["file"]["entry_point"]["state"] == "failed"


def test_valid_pe_fixture_extracts_section_metadata(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, minimal_pe32_fixture(), "fixture.exe")
        response = client.get(f"/api/v1/samples/{sample_id}/file-info")

    assert response.status_code == 200
    payload = response.json()
    assert payload["format"]["detected"] == "pe"
    assert payload["format"]["architecture"] == "x86"
    assert payload["file"]["pe"]["optional_header"]["type"] == "PE32"
    assert payload["file"]["pe"]["entry_point"]["value"] == 0x1000
    assert payload["sections"][0]["name"] == ".text"
    assert payload["sections"][0]["raw_size"] == 0x200
    assert payload["sections"][0]["entropy"] is not None


def test_valid_elf_fixture_extracts_section_metadata(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, minimal_elf64_fixture(), "fixture")
        response = client.get(f"/api/v1/samples/{sample_id}/file-info")

    assert response.status_code == 200
    payload = response.json()
    assert payload["format"]["detected"] == "elf"
    assert payload["format"]["architecture"] == "x86_64"
    assert payload["file"]["elf"]["elf_class"] == "ELF64"
    assert payload["file"]["elf"]["endianness"] == "little"
    assert payload["file"]["elf"]["entry_point"]["value"] == 0x400000
    section_names = {section["name"] for section in payload["sections"]}
    assert ".text" in section_names
    assert ".shstrtab" in section_names


def test_large_file_behavior_allows_incremental_hashing(tmp_path: Path) -> None:
    content = (b"0123456789abcdef" * 70_000)[:1_048_577]
    with make_client(tmp_path, max_upload_bytes=2_000_000) as client:
        sample_id = upload(client, content, "large.bin")
        response = client.get(f"/api/v1/samples/{sample_id}/file-info")

    assert response.status_code == 200
    assert response.json()["file"]["size_bytes"] == len(content)


def test_oversized_upload_is_rejected(tmp_path: Path) -> None:
    with make_client(tmp_path, max_upload_bytes=4) as client:
        response = client.post(
            "/api/v1/samples",
            files={"file": ("too-large.bin", b"12345", "application/octet-stream")},
        )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "upload_too_large"


def test_invalid_request_without_file_returns_validation_error(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        response = client.post("/api/v1/samples", data={})

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_path_traversal_filename_is_sanitized() -> None:
    assert sanitize_filename("..\\..\\secret.exe") == "secret.exe"
    assert sanitize_filename("../../secret.exe") == "secret.exe"


def test_list_samples_empty_and_populated(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        # 1. Fresh database returns empty list
        res_empty = client.get("/api/v1/samples")
        assert res_empty.status_code == 200
        assert res_empty.json() == {"samples": []}

        # 2. Upload samples
        s1 = upload(client, b"sample 1 content", "binary1.exe")
        s2 = upload(client, b"sample 2 content", "binary2.elf")

        # 3. Listing returns both samples with original_filename
        res_populated = client.get("/api/v1/samples")
        assert res_populated.status_code == 200
        samples = res_populated.json()["samples"]
        assert len(samples) == 2
        ids = {s["sample_id"]: s for s in samples}
        assert s1 in ids
        assert s2 in ids
        assert ids[s1]["original_filename"] == "binary1.exe"
        assert ids[s2]["original_filename"] == "binary2.elf"


def test_exe_upload_and_retrieval_contract(tmp_path: Path) -> None:
    """Verify that uploading a PE/EXE file returns a sample whose GET detail contract matches.

    Frontend expectations require root-level original_filename, hashes, and metadata.
    """
    pe_content = minimal_pe32_fixture()
    with make_client(tmp_path) as client:
        upload_resp = client.post(
            "/api/v1/samples",
            files={"file": ("malware_payload.exe", pe_content, "application/x-dosexec")},
        )
        assert upload_resp.status_code == 201
        upload_data = upload_resp.json()
        sample_id = upload_data["sample_id"]
        assert upload_data["sha256"] == hashlib.sha256(pe_content).hexdigest()

        # Retrieve specimen directly via GET /api/v1/samples/{sample_id}
        detail_resp = client.get(f"/api/v1/samples/{sample_id}")
        assert detail_resp.status_code == 200
        detail = detail_resp.json()

        # Ensure root-level specimen contract has original_filename and metadata
        assert detail["sample_id"] == sample_id
        assert detail["original_filename"] == "malware_payload.exe"
        assert detail["safe_filename"] == "malware_payload.exe"
        assert detail["detected_format"] == "pe"
        assert detail["size_bytes"] == len(pe_content)
        assert "hashes" in detail
        assert detail["hashes"]["sha256"] == upload_data["sha256"]
        assert (
            detail["hashes"]["sha1"] == hashlib.sha1(pe_content, usedforsecurity=False).hexdigest()
        )
        assert detail["hashes"]["md5"] == hashlib.md5(pe_content, usedforsecurity=False).hexdigest()
        assert detail["status"] in ("pending", "completed", "running")


def test_delete_sample_success_and_cleanup(tmp_path: Path) -> None:
    pe_content = minimal_pe32_fixture()
    with make_client(tmp_path) as client:
        # 1. Upload sample
        upload_resp = client.post(
            "/api/v1/samples",
            files={"file": ("to_delete.exe", pe_content, "application/x-dosexec")},
        )
        assert upload_resp.status_code == 201
        sample_id = upload_resp.json()["sample_id"]

        # 2. Verify exists
        detail_resp = client.get(f"/api/v1/samples/{sample_id}")
        assert detail_resp.status_code == 200
        list_resp = client.get("/api/v1/samples")
        assert any(s["sample_id"] == sample_id for s in list_resp.json()["samples"])

        # 3. Delete sample
        delete_resp = client.delete(f"/api/v1/samples/{sample_id}")
        assert delete_resp.status_code == 204

        # 4. Verify no longer exists
        get_after = client.get(f"/api/v1/samples/{sample_id}")
        assert get_after.status_code == 404
        assert get_after.json()["error"]["code"] == "sample_not_found"

        # 5. Verify removed from list
        list_after = client.get("/api/v1/samples")
        assert not any(s["sample_id"] == sample_id for s in list_after.json()["samples"])


def test_delete_nonexistent_sample_returns_404(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        delete_resp = client.delete("/api/v1/samples/nonexistent_sample_id_123")
        assert delete_resp.status_code == 404
        assert delete_resp.json()["error"]["code"] == "sample_not_found"


def test_delete_sample_isolation(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        s1 = upload(client, b"sample 1 content", "file1.bin")
        s2 = upload(client, b"sample 2 content", "file2.bin")

        # Delete s1
        del_resp = client.delete(f"/api/v1/samples/{s1}")
        assert del_resp.status_code == 204

        # s1 is gone
        assert client.get(f"/api/v1/samples/{s1}").status_code == 404

        # s2 is completely intact
        res2 = client.get(f"/api/v1/samples/{s2}")
        assert res2.status_code == 200
        assert res2.json()["safe_filename"] == "file2.bin"
        assert res2.json()["size_bytes"] == len(b"sample 2 content")
