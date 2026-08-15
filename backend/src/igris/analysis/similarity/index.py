"""Phase 10 Similarity Index abstraction and storage implementations."""

from abc import ABC, abstractmethod

from igris.analysis.similarity.features import extract_similarity_features
from igris.schemas.similarity import NormalizedSampleFeatures
from igris.storage.metadata import SampleMetadataRepository


class SimilarityIndex(ABC):
    """Abstract interface for sample similarity index and candidate retrieval."""

    @abstractmethod
    def index_sample(self, features: NormalizedSampleFeatures) -> None:
        """Store or update normalized features for a sample."""

    @abstractmethod
    def get_features(self, sample_id: str) -> NormalizedSampleFeatures | None:
        """Retrieve indexed features for a sample by ID."""

    @abstractmethod
    def list_candidates(
        self, exclude_sample_id: str | None = None
    ) -> list[NormalizedSampleFeatures]:
        """Return all available candidate feature profiles for comparison."""

    @abstractmethod
    def remove(self, sample_id: str) -> None:
        """Remove a sample from the similarity index."""


class InMemorySimilarityIndex(SimilarityIndex):
    """In-memory similarity index for testing and transient caching."""

    def __init__(self) -> None:
        self._index: dict[str, NormalizedSampleFeatures] = {}

    def index_sample(self, features: NormalizedSampleFeatures) -> None:
        self._index[features.sample_id] = features

    def get_features(self, sample_id: str) -> NormalizedSampleFeatures | None:
        return self._index.get(sample_id)

    def list_candidates(
        self, exclude_sample_id: str | None = None
    ) -> list[NormalizedSampleFeatures]:
        return [f for sid, f in self._index.items() if sid != exclude_sample_id]

    def remove(self, sample_id: str) -> None:
        self._index.pop(sample_id, None)


class RepositorySimilarityIndex(SimilarityIndex):
    """Repository-backed similarity index dynamically referencing SampleMetadataRepository."""

    def __init__(self, metadata_repository: SampleMetadataRepository) -> None:
        self.metadata_repository = metadata_repository
        self._cached_features: dict[str, NormalizedSampleFeatures] = {}

    def index_sample(self, features: NormalizedSampleFeatures) -> None:
        self._cached_features[features.sample_id] = features

    def get_features(self, sample_id: str) -> NormalizedSampleFeatures | None:
        if sample_id in self._cached_features:
            return self._cached_features[sample_id]
        sample = self.metadata_repository.get(sample_id)
        if sample is None:
            return None
        features = extract_similarity_features(sample)
        self._cached_features[sample_id] = features
        return features

    def list_candidates(
        self, exclude_sample_id: str | None = None
    ) -> list[NormalizedSampleFeatures]:
        samples = self.metadata_repository.list_all()
        candidates: list[NormalizedSampleFeatures] = []
        for s in samples:
            if s.sample_id == exclude_sample_id:
                continue
            if s.sample_id in self._cached_features:
                candidates.append(self._cached_features[s.sample_id])
            else:
                feat = extract_similarity_features(s)
                self._cached_features[s.sample_id] = feat
                candidates.append(feat)
        return candidates

    def remove(self, sample_id: str) -> None:
        self._cached_features.pop(sample_id, None)
