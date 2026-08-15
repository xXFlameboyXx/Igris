"""Tests for Phase 13 Investigation Workspace, Evidence Filtering, Bookmarks, and Notes."""

from pathlib import Path

from fastapi.testclient import TestClient

from igris.core.config import Settings
from igris.main import create_app

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


def test_investigation_workspace_endpoint(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    sample_id = _upload_and_analyze(client, "trojan_test.exe", static_suspicious_pe_fixture())

    response = client.get(f"/api/v1/samples/{sample_id}/investigation")
    assert response.status_code == 200
    data = response.json()
    assert "workspace" in data
    ws = data["workspace"]
    assert ws["sample_id"] == sample_id
    assert "sha256" in ws
    assert ws["verdict_summary"]["verdict"] in (
        "HIGHLY_SUSPICIOUS",
        "SUSPICIOUS",
        "UNKNOWN",
        "LIKELY_BENIGN",
    )
    assert ws["coverage"]["static_analysis"] is True
    assert ws["coverage"]["behavior_analysis"] is True
    assert ws["bookmarks"] == []
    assert ws["notes"] == []


def test_investigation_workspace_not_found(tmp_path: Path) -> None:
    client = make_client(tmp_path)

    response = client.get("/api/v1/samples/non-existent-sample/investigation")
    assert response.status_code == 404
    data = response.json()
    assert data["success"] is False
    assert data["error"]["code"] == "sample_not_found"


def test_evidence_filtering_endpoint(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    sample_id = _upload_and_analyze(client, "suspicious.exe", static_suspicious_pe_fixture())

    # Filter by source: STATIC
    res = client.get(f"/api/v1/samples/{sample_id}/evidence?source=STATIC")
    assert res.status_code == 200
    data = res.json()
    assert data["sample_id"] == sample_id
    assert data["total_count"] > 0
    assert data["filtered_count"] > 0
    for item in data["items"]:
        assert item["category"].lower() == "static"

    # Filter by role: SUPPORTING
    res_role = client.get(f"/api/v1/samples/{sample_id}/evidence?role=SUPPORTING")
    assert res_role.status_code == 200
    data_role = res_role.json()
    for item in data_role["items"]:
        assert item["role"] == "SUPPORTING"

    # Filter by observation_level: OBSERVED
    res_obs = client.get(f"/api/v1/samples/{sample_id}/evidence?observation_level=OBSERVED")
    assert res_obs.status_code == 200
    data_obs = res_obs.json()
    for item in data_obs["items"]:
        assert item["observation_level"] == "OBSERVED"

    # Text query search
    first_item_word = data["items"][0]["statement"].split()[0].lower()
    res_query = client.get(f"/api/v1/samples/{sample_id}/evidence?query={first_item_word}")
    assert res_query.status_code == 200
    data_query = res_query.json()
    assert data_query["filtered_count"] > 0
    for item in data_query["items"]:
        text_corpus = (
            f"{item.get('statement', '')} {item.get('source', '')} "
            f"{item.get('source_id', '') or ''} {item.get('provenance', '') or ''}"
        ).lower()
        assert first_item_word in text_corpus


def test_bookmarks_lifecycle(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    sample_id = _upload_and_analyze(client, "benign.exe", minimal_pe32_fixture())

    # 1. Create Bookmark
    bmk_payload = {
        "target_type": "evidence",
        "target_id": "ev-static-1",
        "title": "Section Characteristics",
        "description": "Standard executable section layout.",
        "category": "STATIC",
        "metadata": {"virtual_size": 4096},
    }
    create_res = client.post(f"/api/v1/samples/{sample_id}/bookmarks", json=bmk_payload)
    assert create_res.status_code == 201
    bmk_data = create_res.json()["bookmark"]
    assert bmk_data["bookmark_id"].startswith("bmk-")
    assert bmk_data["title"] == "Section Characteristics"
    assert bmk_data["target_id"] == "ev-static-1"

    bmk_id = bmk_data["bookmark_id"]

    # 2. List Bookmarks
    list_res = client.get(f"/api/v1/samples/{sample_id}/bookmarks")
    assert list_res.status_code == 200
    bmks = list_res.json()["bookmarks"]
    assert len(bmks) == 1
    assert bmks[0]["bookmark_id"] == bmk_id

    # 3. Delete Bookmark
    del_res = client.delete(f"/api/v1/samples/{sample_id}/bookmarks/{bmk_id}")
    assert del_res.status_code == 204

    # 4. Verify Deleted
    list_res_after = client.get(f"/api/v1/samples/{sample_id}/bookmarks")
    assert list_res_after.status_code == 200
    assert len(list_res_after.json()["bookmarks"]) == 0

    # 5. Delete non-existent gives 404
    del_res_404 = client.delete(f"/api/v1/samples/{sample_id}/bookmarks/non-existent")
    assert del_res_404.status_code == 404


def test_analyst_notes_lifecycle_and_verdict_separation(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    sample_id = _upload_and_analyze(client, "sample.exe", static_suspicious_pe_fixture())

    # Capture automated verdict before adding any notes
    inv_before = client.get(f"/api/v1/samples/{sample_id}/investigation").json()
    verdict_before = inv_before["workspace"]["verdict_summary"]["verdict"]
    score_before = inv_before["workspace"]["verdict_summary"]["risk_score"]["score"]

    # 1. Create Analyst Note
    note_payload = {
        "author": "Senior Analyst Alice",
        "title": "C2 Infrastructure Triage",
        "content": (
            "Host connected to suspicious staging domain. Verified with external threat intel."
        ),
        "attached_evidence_ids": ["ev-static-1"],
        "tags": ["c2", "triage"],
    }
    create_res = client.post(f"/api/v1/samples/{sample_id}/notes", json=note_payload)
    assert create_res.status_code == 201
    note_data = create_res.json()["note"]
    assert note_data["note_id"].startswith("note-")
    assert note_data["author"] == "Senior Analyst Alice"
    assert note_data["title"] == "C2 Infrastructure Triage"

    note_id = note_data["note_id"]

    # 2. List Notes
    list_res = client.get(f"/api/v1/samples/{sample_id}/notes")
    assert list_res.status_code == 200
    notes = list_res.json()["notes"]
    assert len(notes) == 1
    assert notes[0]["note_id"] == note_id

    # 3. Update Note
    patch_payload = {
        "title": "C2 Infrastructure Triage [UPDATED]",
        "content": (
            "Host connected to suspicious staging domain. IP resolved to known bulletproof host."
        ),
    }
    patch_res = client.patch(f"/api/v1/samples/{sample_id}/notes/{note_id}", json=patch_payload)
    assert patch_res.status_code == 200
    updated_note = patch_res.json()["note"]
    assert updated_note["title"] == "C2 Infrastructure Triage [UPDATED]"
    assert updated_note["updated_at"] is not None

    # 4. Verify Automated Verdict has NOT been altered by the note
    inv_after = client.get(f"/api/v1/samples/{sample_id}/investigation").json()
    verdict_after = inv_after["workspace"]["verdict_summary"]["verdict"]
    score_after = inv_after["workspace"]["verdict_summary"]["risk_score"]["score"]

    assert verdict_after == verdict_before
    assert score_after == score_before
    assert len(inv_after["workspace"]["notes"]) == 1

    # 5. Delete Note
    del_res = client.delete(f"/api/v1/samples/{sample_id}/notes/{note_id}")
    assert del_res.status_code == 204

    # 6. Verify Deleted
    list_res_after = client.get(f"/api/v1/samples/{sample_id}/notes")
    assert list_res_after.status_code == 200
    assert len(list_res_after.json()["notes"]) == 0
