"""Storage factory helpers."""

from pathlib import Path

from igris.core.config import Settings
from igris.storage.binary import LocalSampleStorage
from igris.storage.metadata import (
    InMemorySampleMetadataRepository,
    JsonSampleMetadataRepository,
    PostgresSampleMetadataRepository,
    SampleMetadataRepository,
)


def build_sample_storage(settings: Settings) -> LocalSampleStorage:
    return LocalSampleStorage(Path(settings.sample_storage_dir))


def build_metadata_repository(settings: Settings) -> SampleMetadataRepository:
    if settings.metadata_backend == "memory":
        return InMemorySampleMetadataRepository()
    if settings.metadata_backend == "postgres":
        if settings.database_url is None:
            msg = "IGRIS_DATABASE_URL is required when IGRIS_METADATA_BACKEND=postgres"
            raise ValueError(msg)
        return PostgresSampleMetadataRepository(settings.database_url.get_secret_value())
    return JsonSampleMetadataRepository(Path(settings.metadata_storage_file))
