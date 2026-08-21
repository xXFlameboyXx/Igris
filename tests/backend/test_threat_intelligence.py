from pathlib import Path

from fastapi.testclient import TestClient

from igris.analysis.behavioral.synthetic import SyntheticBehaviorAnalyzer
from igris.core.config import Settings
from igris.intelligence.threat.mapper import load_mapping_dataset
from igris.main import create_app
from igris.schemas.behavior_analysis import SyntheticScenario
from igris.schemas.threat_intelligence import CapabilityCategory

from .fixtures import malformed_pe_fixture, reverse_x86_pe_fixture, static_suspicious_pe_fixture


def make_client(tmp_path: Path) -> TestClient:
    app = create_app(
        Settings(
            environment="test",
            metadata_backend="memory",
            sample_storage_dir=str(tmp_path / "samples"),
            sample_temp_dir=str(tmp_path / "tmp"),
            intelligence_mapping_path="config/intelligence/attack_mappings.json",
            reverse_max_instructions=200,
            reverse_max_functions=16,
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


def assess(client: TestClient, sample_id: str) -> dict[str, object]:
    response = client.post(f"/api/v1/samples/{sample_id}/threat-assessment")
    assert response.status_code == 200, response.text
    return dict(response.json()["threat_assessment"])


def test_mapping_dataset_is_versioned_and_loadable() -> None:
    dataset = load_mapping_dataset(Path("config/intelligence/attack_mappings.json"))

    assert dataset.mapping_version == "attack-mapping/v2"
    assert dataset.attack_version == "ATT&CK Enterprise v16.1"
    assert {rule.capability for rule in dataset.rules} >= {
        CapabilityCategory.EXECUTION,
        CapabilityCategory.PERSISTENCE,
        CapabilityCategory.DEFENSE_EVASION,
        CapabilityCategory.COMMAND_AND_CONTROL,
    }


def test_threat_assessment_must_be_run_before_get(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, b"hello world", "benign.txt")
        response = client.get(f"/api/v1/samples/{sample_id}/threat-assessment")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "threat_assessment_not_found"


def test_insufficient_evidence_does_not_map_to_capabilities(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, b"hello world benign readme", "readme.txt")
        result = assess(client, sample_id)

    assert result["status"] == "insufficient_evidence"
    assert result["capabilities"] == []
    assert result["techniques"] == []
    assert "INSUFFICIENT" not in result["narrative"]
    assert "insufficient" in result["narrative"].lower()


def test_single_evidence_maps_only_to_supported_possible_capability(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, b"powershell.exe", "script-note.txt")
        result = assess(client, sample_id)

    capability_categories = {item["category"] for item in result["capabilities"]}
    technique_ids = {item["technique_id"] for item in result["techniques"]}
    assert capability_categories == {"Execution"}
    assert technique_ids == {"T1059.001"}
    assert result["capabilities"][0]["label"] == "POSSIBLE"
    tech = result["techniques"][0]
    assert tech["subtechnique_id"] == "T1059.001"
    assert tech["subtechnique_name"] == "PowerShell"
    assert "PowerShell" in tech["description"]
    assert "powershell" in tech["hypothesis"].lower()
    assert len(tech["supporting_evidence"]) > 0
    assert any("powershell" in (e.get("value") or "").lower() for e in tech["supporting_evidence"])
    assert "OBSERVED:" in result["narrative"]
    assert "INFERRED:" in result["narrative"]
    assert "POSSIBLE:" in result["narrative"]


def test_multiple_corroborating_evidence_maps_capabilities_and_attack(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, static_suspicious_pe_fixture(), "synthetic.exe")
        first = assess(client, sample_id)
        second_response = client.get(f"/api/v1/samples/{sample_id}/threat-assessment")

    assert second_response.status_code == 200
    assert first == second_response.json()["threat_assessment"]
    capability_categories = {item["category"] for item in first["capabilities"]}
    technique_ids = {item["technique_id"] for item in first["techniques"]}
    assert {
        "Execution",
        "Persistence",
        "Defense Evasion",
        "Credential Access",
        "Command and Control",
    } <= capability_categories
    assert {"T1059.001", "T1547.001", "T1027", "T1555", "T1071.001"} <= technique_ids
    assert all(item["confidence"] < 1.0 for item in first["techniques"])
    assert all(len(item["description"]) > 10 for item in first["techniques"])
    assert all(len(item["how_it_works"]) > 10 for item in first["techniques"])
    assert all(len(item["why_igris_mapped"]) > 5 for item in first["techniques"])
    assert all(len(item["hypothesis"]) > 10 for item in first["techniques"])
    assert "not actor attribution" in first["narrative"]


def test_reverse_engineering_evidence_can_support_process_injection_mapping(
    tmp_path: Path,
) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, reverse_x86_pe_fixture(), "reverse.exe")
        result = assess(client, sample_id)

    technique_ids = {item["technique_id"] for item in result["techniques"]}
    assert "T1055" in technique_ids
    injection = next(item for item in result["techniques"] if item["technique_id"] == "T1055")
    assert injection["source_engine"] == "reverse_analysis"
    assert injection["confidence"] == 0.75
    assert injection["label"] == "INFERRED"
    assert "process" in injection["description"].lower()
    assert "inferred" in injection["hypothesis"].lower()


def test_false_mapping_prevention_requires_correlated_network_evidence(
    tmp_path: Path,
) -> None:
    with make_client(tmp_path) as client:
        url_only_id = upload(client, b"http://example.test/path", "url.txt")
        api_only_id = upload(client, b"InternetOpenA", "api.txt")
        url_only = assess(client, url_only_id)
        api_only = assess(client, api_only_id)

    assert not any(item["technique_id"].startswith("T1071") for item in url_only["techniques"])
    assert not any(item["technique_id"].startswith("T1071") for item in api_only["techniques"])


def test_cached_behavior_evidence_can_support_attack_mapping(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, b"hello world benign readme", "readme.txt")
        repository = client.app.state.metadata_repository
        sample = repository.get(sample_id)
        assert sample is not None
        sample.behavior_analysis = SyntheticBehaviorAnalyzer().analyze(
            sample_id=sample_id,
            scenario=SyntheticScenario.NETWORK_ACTIVITY,
        )
        repository.upsert(sample)
        result = assess(client, sample_id)

    techniques = {item["technique_id"]: item for item in result["techniques"]}
    assert "T1071" in techniques
    assert techniques["T1071"]["source_engine"] == "behavior_analysis"
    assert techniques["T1071"]["confidence"] == 0.55
    node_sources = {
        node["details"].get("source")
        for node in result["evidence_graph"]["nodes"]
        if node["node_type"] == "Observation"
    }
    assert "synthetic_behavior_analysis" in node_sources


def test_suspicious_looking_benign_case_stays_hypothetical(tmp_path: Path) -> None:
    content = b"Benign updater uses InternetOpenA for http://example.test release notes."
    with make_client(tmp_path) as client:
        sample_id = upload(client, content, "updater-note.txt")
        result = assess(client, sample_id)

    techniques = {item["technique_id"]: item for item in result["techniques"]}
    assert "T1071.001" in techniques
    assert techniques["T1071.001"]["confidence"] == 0.62
    assert "not actor attribution" in result["narrative"]


def test_evidence_graph_preserves_observation_indicator_capability_technique_chain(
    tmp_path: Path,
) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, reverse_x86_pe_fixture(), "reverse.exe")
        result = assess(client, sample_id)
        relationships_response = client.get(f"/api/v1/samples/{sample_id}/evidence-relationships")

    assert relationships_response.status_code == 200
    graph = relationships_response.json()["evidence_graph"]
    node_types = {node["node_type"] for node in graph["nodes"]}
    edge_types = {edge["relationship"] for edge in graph["edges"]}
    assert {"Observation", "Indicator", "Capability", "ATTACKTechnique"} <= node_types
    assert {
        "produces_indicator",
        "supports_capability",
        "maps_to_attack_technique",
    } <= edge_types
    assert graph == result["evidence_graph"]


def test_phase_5_detail_endpoints_return_cached_assessment_parts(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, static_suspicious_pe_fixture(), "synthetic.exe")
        result = assess(client, sample_id)
        capabilities = client.get(f"/api/v1/samples/{sample_id}/capabilities")
        mappings = client.get(f"/api/v1/samples/{sample_id}/attack-mappings")
        narrative = client.get(f"/api/v1/samples/{sample_id}/narrative")

    assert capabilities.status_code == 200
    assert mappings.status_code == 200
    assert narrative.status_code == 200
    assert capabilities.json()["capabilities"] == result["capabilities"]
    assert mappings.json()["techniques"] == result["techniques"]
    assert narrative.json()["narrative"] == result["narrative"]


def test_malformed_input_is_handled_without_execution(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, malformed_pe_fixture(), "bad.exe")
        result = assess(client, sample_id)

    assert result["status"] in {"completed", "insufficient_evidence"}
    assert "sandbox" in " ".join(result["limitations"])
