"""Comprehensive tests for Phase 10 sample similarity analysis."""

from pathlib import Path

from fastapi.testclient import TestClient

from igris.analysis.similarity.features import (
    normalize_api_name,
    normalize_string_token,
)
from igris.analysis.similarity.index import InMemorySimilarityIndex
from igris.analysis.similarity.metrics import (
    calculate_behavior_similarity,
    compare_samples,
)
from igris.core.config import Settings
from igris.main import create_app
from igris.schemas.similarity import (
    NormalizedSampleFeatures,
    SectionFeature,
    SimilarityConfidence,
    SimilarityHypothesis,
)

from .fixtures import minimal_elf64_fixture, minimal_pe32_fixture, static_suspicious_pe_fixture


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


def _upload_and_analyze(client: TestClient, filename: str, content: bytes) -> str:
    """Helper to upload a sample and trigger analysis pipeline."""
    res = client.post(
        "/api/v1/samples",
        files={"file": (filename, content, "application/octet-stream")},
    )
    assert res.status_code == 201
    sample_id = res.json()["sample_id"]

    client.post(f"/api/v1/samples/{sample_id}/static-analysis")
    client.post(f"/api/v1/samples/{sample_id}/reverse-analysis")
    client.post(f"/api/v1/samples/{sample_id}/behavior-analysis")
    return sample_id


def test_api_and_string_normalization() -> None:
    """Verify API and string token normalization removes noise and standardizes schema."""
    assert normalize_api_name("KERNEL32.DLL", "CreateProcessA@12") == "kernel32.dll!createprocessa"
    assert normalize_api_name("ws2_32", "WSAStartup") == "ws2_32.dll!wsastartup"
    assert normalize_api_name(None, "RegOpenKeyExA") == "regopenkeyexa"

    # Noise filtering
    assert normalize_string_token("abc") is None  # < 4 chars
    assert normalize_string_token("12345678-1234-1234-1234-123456789abc") is None  # UUID
    dummy_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert normalize_string_token(dummy_sha) is None  # SHA256
    assert normalize_string_token("  Powershell.exe  ") == "powershell.exe"


def test_identical_sample_self_similarity() -> None:
    """Verify comparing identical sample profiles yields 1.0 similarity across all dimensions."""
    f1 = NormalizedSampleFeatures(
        sample_id="sample-alpha",
        sha256="aaa111",
        detected_format="pe",
        imported_apis=["kernel32.dll!createprocessa", "advapi32.dll!regsetvalueexa"],
        interesting_strings=["powershell.exe", "http://evil.example/c2"],
        sections=[
            SectionFeature(name=".text", entropy=6.5, size_ratio=0.7, is_executable=True),
            SectionFeature(name=".data", entropy=3.2, size_ratio=0.3, is_writable=True),
        ],
        function_count=4,
        function_signatures=["blocks:3|instrs:25|calls:2", "blocks:5|instrs:40|calls:1"],
        opcode_distribution={"mov": 20, "push": 10, "call": 5, "xor": 3},
        behavior_processes=["cmd.exe", "powershell.exe"],
        behavior_registry_keys=["hkcu\\software\\microsoft\\windows\\currentversion\\run"],
        behavior_network_targets=["192.168.1.100:443"],
        behavior_mutexes=["test_mutex_01"],
        has_static=True,
        has_reverse=True,
        has_behavior=True,
    )

    match = compare_samples(f1, f1, target_filename="sample_alpha.exe")
    assert match.overall_similarity == 1.0
    assert match.file_similarity == 1.0
    assert match.code_similarity == 1.0
    assert match.behavior_similarity == 1.0
    assert match.hypothesis == SimilarityHypothesis.POSSIBLE_RELATED_CLUSTER
    assert match.confidence == SimilarityConfidence.HIGH
    assert len(match.matching_feature_categories) >= 4


def test_renamed_sample_similarity() -> None:
    """Verify identical binary content with different filenames preserves maximal similarity."""
    f1 = NormalizedSampleFeatures(
        sample_id="sample-orig",
        sha256="hash123",
        detected_format="pe",
        imported_apis=["kernel32.dll!virtualallocex", "kernel32.dll!createremotethread"],
        interesting_strings=["svchost.exe", "injected_payload"],
        sections=[SectionFeature(name=".text", entropy=6.8, size_ratio=0.8, is_executable=True)],
        function_count=2,
        opcode_distribution={"mov": 15, "call": 4, "jmp": 2},
        has_static=True,
        has_reverse=True,
        has_behavior=False,
    )

    # Identical features, different sample_id / target filename
    f2 = f1.model_copy(update={"sample_id": "sample-renamed"})
    match = compare_samples(f1, f2, target_filename="renamed_malware.exe")

    assert match.overall_similarity >= 0.95
    assert match.file_similarity >= 0.95
    assert match.code_similarity >= 0.95
    assert match.hypothesis == SimilarityHypothesis.POSSIBLE_RELATED_CLUSTER


def test_structurally_similar_vs_unrelated_ranking() -> None:
    """Verify structurally related samples rank significantly higher than unrelated binaries."""
    query = NormalizedSampleFeatures(
        sample_id="query",
        sha256="q111",
        detected_format="pe",
        imported_apis=["ws2_32.dll!wsastartup", "ws2_32.dll!connect", "ws2_32.dll!send"],
        interesting_strings=["http://beacon.test/api", "user-agent: igris"],
        sections=[SectionFeature(name=".text", entropy=6.2, size_ratio=0.6, is_executable=True)],
        function_count=10,
        opcode_distribution={"mov": 50, "push": 30, "call": 15, "xor": 10},
        behavior_processes=["rundll32.exe"],
        behavior_network_targets=["10.0.0.1:8080"],
        has_static=True,
        has_reverse=True,
        has_behavior=True,
    )

    # Structurally similar: shares 2/3 APIs, network target, similar opcodes
    similar_candidate = NormalizedSampleFeatures(
        sample_id="candidate-sim",
        sha256="sim222",
        detected_format="pe",
        imported_apis=["ws2_32.dll!wsastartup", "ws2_32.dll!connect", "kernel32.dll!sleep"],
        interesting_strings=["http://beacon.test/v2", "user-agent: igris"],
        sections=[SectionFeature(name=".text", entropy=6.3, size_ratio=0.65, is_executable=True)],
        function_count=12,
        opcode_distribution={"mov": 55, "push": 32, "call": 16, "xor": 12},
        behavior_processes=["rundll32.exe"],
        behavior_network_targets=["10.0.0.1:8080"],
        has_static=True,
        has_reverse=True,
        has_behavior=True,
    )

    # Unrelated: ELF binary with math imports, no network, no shared opcodes/sections
    unrelated_candidate = NormalizedSampleFeatures(
        sample_id="candidate-unrelated",
        sha256="unrelated333",
        detected_format="elf",
        imported_apis=["libm.so!sin", "libm.so!cos", "libc.so!printf"],
        interesting_strings=["calculating fast fourier transform"],
        sections=[SectionFeature(name=".rodata", entropy=2.1, size_ratio=0.2)],
        function_count=3,
        opcode_distribution={"fld": 20, "fmul": 15, "fstp": 15},
        behavior_processes=["math_calc"],
        has_static=True,
        has_reverse=True,
        has_behavior=True,
    )

    sim_match = compare_samples(query, similar_candidate, target_filename="beacon_v2.exe")
    unrelated_match = compare_samples(query, unrelated_candidate, target_filename="math_tool.elf")

    assert sim_match.overall_similarity > 0.70
    assert sim_match.hypothesis == SimilarityHypothesis.POSSIBLE_RELATED_CLUSTER

    assert unrelated_match.overall_similarity < 0.25
    assert unrelated_match.hypothesis == SimilarityHypothesis.UNRELATED
    assert sim_match.overall_similarity > unrelated_match.overall_similarity + 0.40


def test_missing_behavior_analysis_graceful_handling() -> None:
    """Verify missing behavioral analysis does not inflate similarity or crash."""
    f1 = NormalizedSampleFeatures(
        sample_id="s1",
        sha256="hash1",
        detected_format="pe",
        imported_apis=["kernel32.dll!exitprocess"],
        sections=[SectionFeature(name=".text", entropy=5.0, size_ratio=0.5)],
        has_static=True,
        has_reverse=False,
        has_behavior=False,
    )
    f2 = NormalizedSampleFeatures(
        sample_id="s2",
        sha256="hash2",
        detected_format="pe",
        imported_apis=["kernel32.dll!exitprocess"],
        sections=[SectionFeature(name=".text", entropy=5.0, size_ratio=0.5)],
        has_static=True,
        has_reverse=False,
        has_behavior=True,
        behavior_processes=["explorer.exe"],
    )

    beh_sim, beh_cats, shared, diffs = calculate_behavior_similarity(f1, f2)
    assert beh_sim is None
    assert len(beh_cats) == 0

    match = compare_samples(f1, f2)
    assert match.behavior_similarity is None
    assert match.file_similarity > 0.80


def test_attribution_safety_guardrails() -> None:
    """Verify similarity reports emit possible clusters, never confirmed attribution."""
    f1 = NormalizedSampleFeatures(
        sample_id="mal1",
        sha256="h1",
        detected_format="pe",
        imported_apis=["kernel32.dll!createprocessa"],
        has_static=True,
    )
    match = compare_samples(f1, f1)

    # Hypothesis must be POSSIBLE_RELATED_CLUSTER or UNRELATED
    assert match.hypothesis in (
        SimilarityHypothesis.POSSIBLE_RELATED_CLUSTER,
        SimilarityHypothesis.UNRELATED,
    )
    assert "family" not in match.hypothesis.value.lower()
    assert "actor" not in match.hypothesis.value.lower()


def test_in_memory_and_repository_similarity_index() -> None:
    """Verify SimilarityIndex implementations correctly store and retrieve candidate features."""
    index = InMemorySimilarityIndex()
    f1 = NormalizedSampleFeatures(sample_id="s1", sha256="h1")
    f2 = NormalizedSampleFeatures(sample_id="s2", sha256="h2")

    index.index_sample(f1)
    index.index_sample(f2)

    assert index.get_features("s1") == f1
    assert len(index.list_candidates(exclude_sample_id="s1")) == 1
    assert index.list_candidates(exclude_sample_id="s1")[0].sample_id == "s2"

    index.remove("s2")
    assert len(index.list_candidates(exclude_sample_id="s1")) == 0


def test_api_similarity_workflow_and_caching(tmp_path: Path) -> None:
    """Verify complete end-to-end API POST and GET flow with ranking and caching."""
    client = make_client(tmp_path)

    # 1. Upload two related samples (suspicious PE and variant) and one unrelated ELF
    sample1_bytes = static_suspicious_pe_fixture()
    sample2_bytes = bytearray(sample1_bytes)
    sample2_bytes[0x200] = 0x55  # Modify one code byte to yield distinct SHA-256

    sample1_id = _upload_and_analyze(client, "suspicious1.exe", bytes(sample1_bytes))
    sample2_id = _upload_and_analyze(client, "suspicious2.exe", bytes(sample2_bytes))
    sample3_id = _upload_and_analyze(client, "tool.elf", minimal_elf64_fixture())

    # 2. Trigger similarity analysis for sample1
    res_post = client.post(f"/api/v1/samples/{sample1_id}/similarity")
    assert res_post.status_code == 200
    report = res_post.json()["similarity"]

    assert report["sample_id"] == sample1_id
    assert report["total_candidates_evaluated"] >= 2
    assert len(report["matches"]) >= 2

    # Top match should be sample2 (modified variant PE)
    top_match = report["matches"][0]
    assert top_match["target_sample_id"] == sample2_id
    assert top_match["overall_similarity"] >= 0.80
    assert top_match["hypothesis"] == "possible_related_cluster"

    # Lower ranked match should be sample3 (ELF)
    last_match = report["matches"][-1]
    assert last_match["target_sample_id"] == sample3_id
    assert last_match["overall_similarity"] < top_match["overall_similarity"]

    # 3. Retrieve cached results via GET
    res_get = client.get(f"/api/v1/samples/{sample1_id}/similarity/results")
    assert res_get.status_code == 200
    get_report = res_get.json()["similarity"]
    assert get_report["sample_id"] == sample1_id
    assert len(get_report["matches"]) == len(report["matches"])


def test_api_similarity_error_handling(tmp_path: Path) -> None:
    """Verify appropriate 404 responses for nonexistent samples and uncomputed similarity."""
    client = make_client(tmp_path)

    # Nonexistent sample POST
    r_bad_post = client.post("/api/v1/samples/nonexistent-id/similarity")
    assert r_bad_post.status_code == 404
    assert r_bad_post.json()["error"]["code"] == "sample_not_found"

    # Nonexistent sample GET
    r_bad_get = client.get("/api/v1/samples/nonexistent-id/similarity/results")
    assert r_bad_get.status_code == 404
    assert r_bad_get.json()["error"]["code"] == "sample_not_found"

    # Valid sample before similarity is run
    res = client.post(
        "/api/v1/samples",
        files={"file": ("unrun.exe", minimal_pe32_fixture(), "application/octet-stream")},
    )
    sample_id = res.json()["sample_id"]

    r_not_run = client.get(f"/api/v1/samples/{sample_id}/similarity/results")
    assert r_not_run.status_code == 404
    assert r_not_run.json()["error"]["code"] == "similarity_not_found"
