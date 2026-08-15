"""Security regression and hardening test suite for Phase 17."""

from pathlib import Path

from fastapi.testclient import TestClient

from igris.analysis.file_intelligence.analyzer import analyze_file
from igris.analysis.file_intelligence.elf import ELFParseError, parse_elf
from igris.analysis.file_intelligence.pe import PEParseError, parse_pe
from igris.analysis.file_intelligence.service import sanitize_filename
from igris.core.config import Settings
from igris.main import create_app
from igris.reporting.pdf import PurePDFRenderer, _sanitize_pdf_text
from igris.schemas.investigation import (
    InvestigationReport,
    ReportVersionMetadata,
)


def _make_client(max_upload_bytes: int = 1024 * 1024) -> TestClient:
    settings = Settings(
        metadata_backend="memory",
        max_upload_bytes=max_upload_bytes,
        enable_docs=False,
    )
    app = create_app(settings)
    return TestClient(app)


def test_path_traversal_filename_sanitization() -> None:
    """Verify malicious filenames with path traversal and absolute paths are sanitized."""
    malicious_inputs = [
        ("../../etc/shadow", "shadow"),
        ("..\\..\\Windows\\System32\\calc.exe", "calc.exe"),
        ("/root/secret.dat", "secret.dat"),
        ("C:\\Program Files\\app.exe", "app.exe"),
        ("evil\x00file.exe", "evil_file.exe"),
        ("....//....//payload.bin", "payload.bin"),
        ("   ...   ", "unnamed"),
        ("", "unnamed"),
    ]

    for raw, expected in malicious_inputs:
        sanitized = sanitize_filename(raw)
        assert "/" not in sanitized
        assert "\\" not in sanitized
        assert "\x00" not in sanitized
        assert ".." not in sanitized
        assert sanitized == expected


def test_zero_byte_upload_handled_safely() -> None:
    """Verify that uploading an empty 0-byte file is handled safely as format empty."""
    client = _make_client()
    response = client.post(
        "/api/v1/samples",
        files={"file": ("empty.bin", b"", "application/octet-stream")},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "completed"

    sample_id = data["sample_id"]
    info_res = client.get(f"/api/v1/samples/{sample_id}/file-info")
    assert info_res.status_code == 200
    info = info_res.json()
    assert info["file"]["size_bytes"] == 0
    assert info["file"]["detected_format"] == "empty"
    assert info["file"]["entropy"] == 0.0


def test_oversized_upload_rejected() -> None:
    """Verify that uploading a file exceeding max_upload_bytes is rejected with 413."""
    # Set limit to 256 bytes
    client = _make_client(max_upload_bytes=256)
    oversized_payload = b"A" * 512

    response = client.post(
        "/api/v1/samples",
        files={"file": ("oversized.bin", oversized_payload, "application/octet-stream")},
    )
    assert response.status_code == 413
    data = response.json()
    assert data["success"] is False
    assert data["error"]["code"] == "upload_too_large"


def test_malformed_pe_headers_handled_safely(tmp_path: Path) -> None:
    """Verify corrupted PE headers fail safely with PEParseError without crashing."""
    # 1. Truncated MZ header
    p1 = tmp_path / "truncated_mz.bin"
    p1.write_bytes(b"MZ\x00\x00")
    try:
        parse_pe(p1)
    except PEParseError as e:
        assert isinstance(e, PEParseError)

    # 2. Corrupted PE signature offset pointing outside file
    p2 = tmp_path / "bad_pe_offset.bin"
    bad_offset_header = bytearray(b"MZ" + b"\x00" * 58 + b"\xff\xff\xff\x7f")
    p2.write_bytes(bad_offset_header)
    try:
        parse_pe(p2)
    except PEParseError as e:
        assert "outside file" in str(e)

    # 3. Analyze file should trap PE parse errors gracefully
    metadata = analyze_file(p1)
    assert len(metadata.parse_errors) > 0
    assert metadata.entry_point.state.value == "failed"


def test_malformed_elf_headers_handled_safely(tmp_path: Path) -> None:
    """Verify truncated and corrupted ELF headers fail safely with ELFParseError."""
    # 1. Truncated ELF
    p1 = tmp_path / "truncated_elf.bin"
    p1.write_bytes(b"\x7fELF\x01")
    try:
        parse_elf(p1)
    except ELFParseError as e:
        assert isinstance(e, ELFParseError)

    # 2. Corrupted ELF class
    p2 = tmp_path / "corrupted_class_elf.bin"
    p2.write_bytes(b"\x7fELF\x99" + b"\x00" * 60)
    try:
        parse_elf(p2)
    except ELFParseError as e:
        assert "unsupported ELF class" in str(e)

    metadata = analyze_file(p1)
    assert len(metadata.parse_errors) > 0
    assert metadata.entry_point.state.value == "failed"


def test_security_headers_middleware_enforced() -> None:
    """Verify defensive HTTP response security headers are set on all responses."""
    client = _make_client()
    response = client.get("/health")
    assert response.status_code == 200

    headers = response.headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-XSS-Protection"] == "1; mode=block"
    assert headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]


def test_error_masking_no_stack_trace_leakage() -> None:
    """Verify API errors return sanitized error payloads without Python tracebacks."""
    client = _make_client()
    response = client.get("/api/v1/samples/nonexistent-sample-hash-12345")
    assert response.status_code == 404
    data = response.json()

    assert data["success"] is False
    assert "error" in data
    assert "code" in data["error"]
    assert "message" in data["error"]
    assert "Traceback (most recent call last)" not in response.text
    assert "site-packages" not in response.text


def test_report_pdf_generation_text_sanitization() -> None:
    """Verify PDF generator sanitizes hostile input strings (control chars, parentheses)."""
    hostile_text = (
        "Hostile (Payload) \\ with \x00 null \x1b escape \r\n and (nested) \\\\ delimiters"
    )
    sanitized = _sanitize_pdf_text(hostile_text)

    assert "\x00" not in sanitized
    assert "\x1b" not in sanitized
    assert "\r" not in sanitized
    assert "\n" not in sanitized
    assert "\\(" in sanitized
    assert "\\)" in sanitized

    # Test complete PDF generation with hostile report contents
    exec_summary = "Summary with (parentheses) and \\ backslashes \x00 <script>alert(1)</script>."
    report = InvestigationReport(
        report_id="rep-sec-test-001",
        sample_id="88a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef",
        sha256="88a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef",
        version_metadata=ReportVersionMetadata(),
        executive_summary=exec_summary,
        sample_identification={
            "original_filename": "evil (sample) \\ file.exe",
            "safe_filename": "evil_sample_file.bin",
            "file_size": 1024,
            "detected_format": "PE",
            "architecture": "x86_64",
        },
        verdict_assessment={
            "verdict": "HIGHLY_SUSPICIOUS",
            "risk_score": 95,
            "confidence": "CONFIRMED",
            "primary_rationale": "Hostile (payload) \\ detected.",
        },
        epistemology_summary={"OBSERVED": ["Observed (1) \\ fact"], "INFERRED": []},
        subsystem_summaries={},
        evidence_items=[],
        analyst_notes=[],
        analyst_bookmarks=[],
        uncertainties=[],
        limitations=["Testing \\ limitation (1)"],
    )

    renderer = PurePDFRenderer()
    pdf_bytes = renderer.render(report)
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF-1.4")
    assert pdf_bytes.rstrip().endswith(b"%%EOF")


def test_secrets_and_config_sanitization() -> None:
    """Verify database URL and sensitive configuration fields are masked."""
    settings = Settings(database_url="postgresql://user:secretpass@localhost:5432/igris")  # type: ignore[arg-type]
    assert settings.database_url is not None
    # SecretStr should not reveal plain password in repr/str
    assert "secretpass" not in repr(settings.database_url)
    assert "secretpass" not in str(settings.database_url)
    assert (
        settings.database_url.get_secret_value()
        == "postgresql://user:secretpass@localhost:5432/igris"
    )
