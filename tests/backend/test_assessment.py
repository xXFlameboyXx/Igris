"""Comprehensive tests for Phase 11 explainable malware assessment."""

from pathlib import Path

from fastapi.testclient import TestClient

from igris.core.config import Settings
from igris.intelligence.assessment.engine import AssessmentEngine
from igris.main import create_app
from igris.schemas.assessment import (
    AssessmentVerdict,
    RiskLevel,
)
from igris.schemas.file_intelligence import HashSet, Sample

from .fixtures import minimal_pe32_fixture, static_suspicious_pe_fixture


def make_client(tmp_path: Path) -> TestClient:
    """Create isolated FastAPI test client using local temporary storage."""
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
    run_static: bool = True,
    run_reverse: bool = True,
    run_behavior: bool = True,
    run_detection: bool = True,
    run_ml: bool = True,
    run_similarity: bool = True,
) -> str:
    """Helper to upload a sample and trigger selected analysis subsystems."""
    res = client.post(
        "/api/v1/samples",
        files={"file": (filename, content, "application/octet-stream")},
    )
    assert res.status_code == 201
    sample_id = res.json()["sample_id"]

    if run_static:
        client.post(f"/api/v1/samples/{sample_id}/static-analysis")
    if run_reverse:
        client.post(f"/api/v1/samples/{sample_id}/reverse-analysis")
    if run_behavior:
        client.post(f"/api/v1/samples/{sample_id}/behavior-analysis")
    if run_detection:
        client.post(f"/api/v1/samples/{sample_id}/detect")
    if run_ml:
        client.post(f"/api/v1/samples/{sample_id}/ml-prediction")
    if run_similarity:
        client.post(f"/api/v1/samples/{sample_id}/similarity")

    return sample_id


def test_insufficient_evidence_yields_unknown_verdict() -> None:
    """Verify that an unanalyzed sample evaluates to UNKNOWN, not BENIGN."""
    sample = Sample(
        sample_id="empty-sample-01",
        original_filename="raw_sample.bin",
        safe_filename="sample_empty.bin",
        hashes=HashSet(
            sha256="0" * 64,
            sha1="0" * 40,
            md5="0" * 32,
        ),
        storage_ref="storage/raw_sample.bin",
        size_bytes=1024,
        status="pending",
    )

    engine = AssessmentEngine()
    assessment = engine.assess(sample)

    assert assessment.verdict == AssessmentVerdict.UNKNOWN
    assert assessment.risk_level == RiskLevel.UNKNOWN
    assert assessment.risk_score.score == 0
    assert len(assessment.evidence_summary.uncertainties) >= 4
    assert any("not been executed" in u.reason for u in assessment.evidence_summary.uncertainties)


def test_strong_corroborated_malicious_evidence(tmp_path: Path) -> None:
    """Verify sample with multi-layer malicious indicators yields HIGHLY_SUSPICIOUS."""
    client = make_client(tmp_path)
    sample_id = _upload_and_analyze(client, "suspicious.exe", static_suspicious_pe_fixture())

    res_verdict = client.get(f"/api/v1/samples/{sample_id}/verdict")
    assert res_verdict.status_code == 200
    v_data = res_verdict.json()["verdict"]

    assert v_data["verdict"] in ("SUSPICIOUS", "HIGHLY_SUSPICIOUS")
    assert v_data["risk_score"]["score"] >= 50
    assert v_data["confidence"]["detection_confidence"] in ("MEDIUM", "HIGH")
    assert v_data["confidence"]["evidence_quality"] == "HIGH"
    assert v_data["confidence"]["attribution_scope"] == "cluster_only"


def test_epistemological_separation_observed_inferred_possible(tmp_path: Path) -> None:
    """Verify strict separation between Observed, Inferred, and Possible findings."""
    client = make_client(tmp_path)
    sample_id = _upload_and_analyze(client, "suspicious.exe", static_suspicious_pe_fixture())

    res_exp = client.get(f"/api/v1/samples/{sample_id}/explanation")
    assert res_exp.status_code == 200
    exp_data = res_exp.json()["explanation"]

    assert len(exp_data["observed_findings"]) > 0
    assert len(exp_data["supporting_arguments"]) > 0
    assert len(exp_data["limitations"]) >= 3

    # Check evidence-summary endpoint counts
    res_summary = client.get(f"/api/v1/samples/{sample_id}/evidence-summary")
    assert res_summary.status_code == 200
    summary_data = res_summary.json()["evidence_summary"]

    assert summary_data["total_evidence_count"] > 0
    assert summary_data["observed_count"] >= 1
    assert summary_data["supporting_count"] >= 1


def test_missing_behavioral_telemetry_handling(tmp_path: Path) -> None:
    """Verify unexecuted behavioral analysis is marked UNAVAILABLE and not treated as benign."""
    client = make_client(tmp_path)
    sample_id = _upload_and_analyze(
        client,
        "static_only.exe",
        static_suspicious_pe_fixture(),
        run_behavior=False,
    )

    res_verdict = client.get(f"/api/v1/samples/{sample_id}/verdict")
    assert res_verdict.status_code == 200
    v_data = res_verdict.json()["verdict"]

    assert v_data["confidence"]["behavioral_confidence"] == "UNAVAILABLE"
    assert any("behavior" in u.lower() for u in v_data["risk_score"]["unknown_factors"])


def test_clean_sample_verdict(tmp_path: Path) -> None:
    """Verify clean benign binary yields LIKELY_BENIGN or BENIGN with low risk score."""
    client = make_client(tmp_path)
    sample_id = _upload_and_analyze(client, "benign.exe", minimal_pe32_fixture())

    res_verdict = client.get(f"/api/v1/samples/{sample_id}/verdict")
    assert res_verdict.status_code == 200
    v_data = res_verdict.json()["verdict"]

    assert v_data["verdict"] in ("BENIGN", "LIKELY_BENIGN")
    assert v_data["risk_score"]["score"] < 35
    assert len(v_data["risk_score"]["mitigating_factors"]) >= 1


def test_attribution_guardrails_cluster_only(tmp_path: Path) -> None:
    """Verify attribution confidence strictly refers to clusters, never confirmed actors."""
    client = make_client(tmp_path)
    sample_id = _upload_and_analyze(client, "target.exe", static_suspicious_pe_fixture())

    res_verdict = client.get(f"/api/v1/samples/{sample_id}/verdict")
    v_data = res_verdict.json()["verdict"]

    assert v_data["confidence"]["attribution_scope"] == "cluster_only"
    lims = " ".join(v_data["limitations"]).lower()
    assert "never" in lims or "does not" in lims
    assert "malware family" in lims or "actor" in lims


def test_api_404_error_handling(tmp_path: Path) -> None:
    """Verify appropriate 404 responses for nonexistent sample IDs."""
    client = make_client(tmp_path)

    r_v = client.get("/api/v1/samples/nonexistent-id/verdict")
    assert r_v.status_code == 404
    assert r_v.json()["error"]["code"] == "sample_not_found"

    r_e = client.get("/api/v1/samples/nonexistent-id/explanation")
    assert r_e.status_code == 404

    r_s = client.get("/api/v1/samples/nonexistent-id/evidence-summary")
    assert r_s.status_code == 404


def test_cache_invalidation_on_new_analysis(tmp_path: Path) -> None:
    """Verify re-running static or behavioral analysis clears cached assessment."""
    client = make_client(tmp_path)
    sample_id = _upload_and_analyze(
        client, "test.exe", static_suspicious_pe_fixture(), run_behavior=False
    )

    # First fetch verdict (cached with behavioral UNAVAILABLE)
    r1 = client.get(f"/api/v1/samples/{sample_id}/verdict").json()["verdict"]
    assert r1["confidence"]["behavioral_confidence"] == "UNAVAILABLE"

    # Now run behavioral analysis (triggers invalidation)
    client.post(f"/api/v1/samples/{sample_id}/behavior-analysis")

    # Fetch verdict again (recomputed with behavioral HIGH)
    r2 = client.get(f"/api/v1/samples/{sample_id}/verdict").json()["verdict"]
    assert r2["confidence"]["behavioral_confidence"] == "HIGH"


def test_contradiction_detection_in_narrative_and_summary(tmp_path: Path) -> None:
    """Verify that contradictory evidence surfaces in narrative and disagreements."""
    client = make_client(tmp_path)
    sample_id = _upload_and_analyze(client, "contra.exe", static_suspicious_pe_fixture())

    res_sum = client.get(f"/api/v1/samples/{sample_id}/evidence-summary")
    assert res_sum.status_code == 200
    sum_data = res_sum.json()["evidence_summary"]

    # Supporting and contradicting evidence are both preserved
    assert sum_data["supporting_count"] >= 1
    assert "disagreements" in sum_data

    res_exp = client.get(f"/api/v1/samples/{sample_id}/explanation")
    assert res_exp.status_code == 200
    exp_data = res_exp.json()["explanation"]
    assert len(exp_data["supporting_arguments"]) >= 1
    assert len(exp_data["contradicting_arguments"]) >= 1


def test_risk_score_deterministic_formula() -> None:
    """Verify risk score bounded calculation and formula transparency."""
    engine = AssessmentEngine()
    sample = Sample(
        sample_id="formula-test",
        original_filename="calc.bin",
        safe_filename="calc.bin",
        hashes=HashSet(sha256="1" * 64, sha1="1" * 40, md5="1" * 32),
        storage_ref="storage/calc.bin",
        size_bytes=2048,
        status="pending",
    )
    assessment = engine.assess(sample)
    assert assessment.risk_score.score == 0
    assert assessment.risk_score.formula != ""
    assert assessment.risk_score.score <= 100
    assert assessment.risk_score.score >= 0
