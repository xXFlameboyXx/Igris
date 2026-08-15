"""Application service for Phase 1 sample ingestion and file intelligence."""

import hashlib
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from fastapi import UploadFile, status

from igris.analysis.file_intelligence.analyzer import analyze_file
from igris.analysis.file_intelligence.entropy import CHUNK_SIZE, EntropyCalculator
from igris.core.config import Settings
from igris.core.errors import AppError
from igris.schemas.file_intelligence import (
    AnalysisStatus,
    FileInfoResponse,
    HashSet,
    Sample,
    SampleCreateResponse,
    SampleResponse,
)
from igris.storage.binary import LocalSampleStorage
from igris.storage.metadata import SampleMetadataRepository

SAFE_FILENAME_PATTERN = re.compile(r"[^A-Za-z0-9._-]+")


class FileIntelligenceService:
    """Coordinate safe sample storage and Phase 1 metadata analysis."""

    def __init__(
        self,
        *,
        settings: Settings,
        sample_storage: LocalSampleStorage,
        metadata_repository: SampleMetadataRepository,
    ) -> None:
        self.settings = settings
        self.sample_storage = sample_storage
        self.metadata_repository = metadata_repository
        Path(settings.sample_temp_dir).mkdir(parents=True, exist_ok=True)

    async def ingest(self, upload: UploadFile) -> SampleCreateResponse:
        original_filename = upload.filename or "unnamed"
        safe_filename = sanitize_filename(original_filename)
        temp_path = self._new_temp_path()

        try:
            hashes, size_bytes, entropy = await self._stream_to_temp(upload, temp_path)
            existing = self.metadata_repository.get_by_sha256(hashes.sha256)
            if existing is not None:
                _unlink_if_exists(temp_path)
                return SampleCreateResponse(
                    sample_id=existing.sample_id,
                    sha256=existing.hashes.sha256,
                    status=existing.status,
                )

            stored = self.sample_storage.store_temp_file(temp_path)
            now = datetime.now(UTC)
            file_metadata = analyze_file(stored.path)
            file_metadata.entropy = entropy
            sample = Sample(
                sample_id=hashes.sha256,
                original_filename=original_filename,
                safe_filename=safe_filename,
                content_type_supplied=upload.content_type,
                hashes=hashes,
                storage_ref=stored.storage_ref,
                size_bytes=size_bytes,
                status=AnalysisStatus.COMPLETED,
                file_metadata=file_metadata,
                created_at=now,
                updated_at=now,
            )
            self.metadata_repository.upsert(sample)
            return SampleCreateResponse(
                sample_id=sample.sample_id,
                sha256=sample.hashes.sha256,
                status=sample.status,
            )
        except AppError:
            _unlink_if_exists(temp_path)
            raise
        except Exception as exc:
            _unlink_if_exists(temp_path)
            raise AppError(
                "Sample ingestion failed",
                code="sample_ingestion_failed",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                details={"reason": str(exc)},
            ) from exc
        finally:
            await upload.close()

    def list_samples(self) -> list[SampleResponse]:
        samples = self.metadata_repository.list_all()
        return [SampleResponse.from_sample(s) for s in samples]

    def get_sample(self, sample_id: str) -> SampleResponse:
        sample = self.metadata_repository.get(sample_id)
        if sample is None:
            raise AppError("Sample not found", code="sample_not_found", status_code=404)
        return SampleResponse.from_sample(sample)

    def get_file_info(self, sample_id: str) -> FileInfoResponse:
        sample = self.metadata_repository.get(sample_id)
        if sample is None:
            raise AppError("Sample not found", code="sample_not_found", status_code=404)
        if sample.file_metadata is None:
            raise AppError(
                "File metadata is not available",
                code="file_info_not_available",
                status_code=409,
            )

        file_metadata = sample.file_metadata
        sections = []
        imports = []
        exports = []
        resources = []
        if file_metadata.pe is not None:
            sections = file_metadata.pe.sections
            imports = file_metadata.pe.imports
            exports = file_metadata.pe.exports
            resources = file_metadata.pe.resources
        elif file_metadata.elf is not None:
            sections = file_metadata.elf.sections

        return FileInfoResponse(
            sample=SampleResponse.from_sample(sample),
            file=file_metadata,
            hashes=sample.hashes,
            format={
                "detected": file_metadata.detected_format,
                "architecture": file_metadata.architecture,
                "mime_type": file_metadata.mime_type,
            },
            sections=sections,
            imports=imports,
            exports=exports,
            resources=resources,
        )

    async def _stream_to_temp(
        self, upload: UploadFile, temp_path: Path
    ) -> tuple[HashSet, int, float]:
        sha256 = hashlib.sha256()
        sha1 = hashlib.sha1(usedforsecurity=False)
        md5 = hashlib.md5(usedforsecurity=False)
        entropy = EntropyCalculator()
        size_bytes = 0

        with temp_path.open("wb") as destination:
            while chunk := await upload.read(CHUNK_SIZE):
                size_bytes += len(chunk)
                if size_bytes > self.settings.max_upload_bytes:
                    raise AppError(
                        "Uploaded file exceeds configured size limit",
                        code="upload_too_large",
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                        details={"max_upload_bytes": self.settings.max_upload_bytes},
                    )
                sha256.update(chunk)
                sha1.update(chunk)
                md5.update(chunk)
                entropy.update(chunk)
                destination.write(chunk)

        return (
            HashSet(sha256=sha256.hexdigest(), sha1=sha1.hexdigest(), md5=md5.hexdigest()),
            size_bytes,
            entropy.digest(),
        )

    def _new_temp_path(self) -> Path:
        temp_dir = Path(self.settings.sample_temp_dir)
        temp_dir.mkdir(parents=True, exist_ok=True)
        file_descriptor, path = tempfile.mkstemp(
            prefix="igris-upload-", suffix=".tmp", dir=temp_dir
        )
        os.close(file_descriptor)
        if os.name != "nt":
            os.chmod(path, 0o600)
        return Path(path)


def sanitize_filename(filename: str) -> str:
    basename = Path(filename.replace("\\", "/")).name
    sanitized = SAFE_FILENAME_PATTERN.sub("_", basename).strip("._ ")
    return sanitized[:128] or "unnamed"


def _unlink_if_exists(path: Path) -> None:
    try:
        if path.exists():
            path.unlink()
    except OSError:
        pass
