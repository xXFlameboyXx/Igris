"""Phase 10 sample similarity analysis package."""

from igris.analysis.similarity.features import extract_similarity_features
from igris.analysis.similarity.index import (
    InMemorySimilarityIndex,
    RepositorySimilarityIndex,
    SimilarityIndex,
)
from igris.analysis.similarity.metrics import compare_samples
from igris.analysis.similarity.service import SimilarityService

__all__ = [
    "InMemorySimilarityIndex",
    "RepositorySimilarityIndex",
    "SimilarityIndex",
    "SimilarityService",
    "compare_samples",
    "extract_similarity_features",
]
