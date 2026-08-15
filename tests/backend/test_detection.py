import json
from pathlib import Path

from fastapi.testclient import TestClient

from igris.analysis.behavioral.synthetic import SyntheticBehaviorAnalyzer
from igris.core.config import Settings
from igris.detection.rules import RuleEngine
from igris.main import create_app
from igris.schemas.behavior_analysis import SyntheticScenario
from igris.schemas.static_analysis import StaticAnalysisResult

from .fixtures import malformed_pe_fixture, static_suspicious_pe_fixture


def make_client(tmp_path: Path, rules_path: Path | None = None) -> TestClient:
    app = create_app(
        Settings(
            environment="test",
            metadata_backend="memory",
            sample_storage_dir=str(tmp_path / "samples"),
            sample_temp_dir=str(tmp_path / "tmp"),
            detection_rules_path=str(rules_path or Path("config/rules/static_rules.json")),
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


def detect(client: TestClient, sample_id: str) -> dict[str, object]:
    response = client.post(f"/api/v1/samples/{sample_id}/detect")
    assert response.status_code == 200, response.text
    return dict(response.json()["detection"])


def test_detection_requires_existing_sample(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        response = client.post("/api/v1/samples/missing/detect")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "sample_not_found"


def test_detection_must_be_run_before_get(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, b"hello world", "benign.txt")
        response = client.get(f"/api/v1/samples/{sample_id}/detection")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "detection_not_found"


def test_clearly_benign_text_has_benign_detection(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, b"hello world benign readme", "readme.txt")
        result = detect(client, sample_id)

    assert result["status"] == "BENIGN"
    assert result["heuristic_score"] == 0.0
    assert result["triggered_rules"] == []
    assert result["heuristics"] == []
    assert "not a statistical probability" in result["limitations"][0]


def test_suspicious_looking_benign_networking_is_not_overclaimed(tmp_path: Path) -> None:
    content = b"This benign updater references InternetOpenA and example.test documentation."
    with make_client(tmp_path) as client:
        sample_id = upload(client, content, "updater-note.txt")
        result = detect(client, sample_id)

    assert result["status"] == "UNKNOWN"
    assert result["heuristic_score"] < 1.5
    assert result["triggered_rules"] == []
    assert "probability" in result["limitations"][0]
    assert "malware" not in str(result["explanation"]).lower()


def test_multiple_suspicious_indicators_trigger_rules_and_high_assessment(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, static_suspicious_pe_fixture(), "synthetic.exe")
        first = detect(client, sample_id)
        second_response = client.get(f"/api/v1/samples/{sample_id}/detection")

    assert second_response.status_code == 200
    second = second_response.json()["detection"]
    assert first == second
    assert first["status"] == "HIGHLY_SUSPICIOUS"
    assert first["heuristic_score"] >= 5.0
    rule_ids = {rule["rule_id"] for rule in first["triggered_rules"]}
    assert "IGRIS-RULE-0002" in rule_ids
    assert "IGRIS-RULE-0003" in rule_ids
    heuristic_ids = {item["heuristic_id"] for item in first["heuristics"]}
    assert "HEUR-PROC-001" in heuristic_ids
    assert "HEUR-OBF-001" in heuristic_ids
    assert first["score_breakdown"]["rule_contributions"]
    assert first["score_breakdown"]["heuristic_contributions"]
    assert first["score_breakdown"]["evidence_contributions"]


def test_detection_is_idempotent(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, static_suspicious_pe_fixture(), "synthetic.exe")
        first = client.post(f"/api/v1/samples/{sample_id}/detect").json()
        second = client.post(f"/api/v1/samples/{sample_id}/detect").json()

    assert first == second


def test_detection_consumes_cached_behavior_without_running_it(tmp_path: Path) -> None:
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
        result = detect(client, sample_id)

    assert result["status"] == "UNKNOWN"
    assert result["behavior_evidence"]
    behavior_sources = {
        item["source"] for item in result["score_breakdown"]["evidence_contributions"]
    }
    assert "behavior_evidence" in behavior_sources
    heuristic_ids = {item["heuristic_id"] for item in result["heuristics"]}
    assert "HEUR-BEH-BEHAVIOR_NETWORK_ACTIVITY" in heuristic_ids
    assert "Behavior evidence is consumed only" in result["limitations"][2]
    assert "cached behavior evidence" in result["explanation"]


def test_rule_engine_loads_reloadable_declarative_rules(tmp_path: Path) -> None:
    rules_path = tmp_path / "rules.json"
    rules_path.write_text(
        json.dumps(
            [
                {
                    "rule_id": "TEST-RULE-1",
                    "name": "Any String Evidence",
                    "description": "Test rule for rule engine.",
                    "severity": "low",
                    "confidence": 0.5,
                    "conditions": [
                        {
                            "field": "string_counts.url",
                            "operator": ">=",
                            "value": 1,
                        }
                    ],
                    "evidence": "URL strings are present.",
                    "version": "1.0.0",
                    "contribution": 0.4,
                }
            ]
        ),
        encoding="utf-8",
    )
    engine = RuleEngine.from_path(rules_path)

    with make_client(tmp_path) as client:
        sample_id = upload(client, b"http://example.test/", "url.txt")
        static_response = client.post(f"/api/v1/samples/{sample_id}/static-analysis")

    analysis = StaticAnalysisResult.model_validate(static_response.json()["analysis"])
    triggered = engine.evaluate(analysis)
    assert len(triggered) == 1
    assert triggered[0].rule_id == "TEST-RULE-1"


def test_invalid_rule_file_fails_closed(tmp_path: Path) -> None:
    rules_path = tmp_path / "rules.json"
    rules_path.write_text('[{"rule_id": "missing-fields"}]', encoding="utf-8")

    try:
        RuleEngine.from_path(rules_path)
    except Exception as exc:
        assert "Detection rules failed validation" in str(exc)
    else:
        raise AssertionError("invalid rules should fail validation")


def test_malformed_pe_detection_completes_without_execution(tmp_path: Path) -> None:
    with make_client(tmp_path) as client:
        sample_id = upload(client, malformed_pe_fixture(), "malformed.exe")
        result = detect(client, sample_id)

    assert result["run_status"] == "completed"
    assert result["status"] in {"BENIGN", "UNKNOWN", "SUSPICIOUS", "HIGHLY_SUSPICIOUS"}
    assert result["engine_version"] == "heuristic-detection/v1"
