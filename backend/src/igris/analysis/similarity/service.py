"""Phase 10 sample similarity application service."""

from datetime import UTC, datetime

from igris.analysis.similarity.features import extract_similarity_features
from igris.analysis.similarity.index import RepositorySimilarityIndex, SimilarityIndex
from igris.analysis.similarity.metrics import compare_samples
from igris.core.config import Settings
from igris.core.errors import AppError
from igris.schemas.similarity import (
    SampleSimilarityMatch,
    SimilarityHypothesis,
    SimilarityReport,
    SimilarityResponse,
    SimilarityResultsResponse,
)
from igris.storage.binary import LocalSampleStorage
from igris.storage.metadata import SampleMetadataRepository


class SimilarityService:
    """Orchestrates feature extraction, similarity indexing, multi-level scoring, and caching."""

    def __init__(
        self,
        settings: Settings,
        sample_storage: LocalSampleStorage,
        metadata_repository: SampleMetadataRepository,
        similarity_index: SimilarityIndex | None = None,
    ) -> None:
        self.settings = settings
        self.sample_storage = sample_storage
        self.metadata_repository = metadata_repository
        self.index = similarity_index or RepositorySimilarityIndex(metadata_repository)

    def run(self, sample_id: str, max_matches: int = 20) -> SimilarityResponse:
        """Run deterministic similarity analysis against all available candidate samples."""
        sample = self.metadata_repository.get(sample_id)
        if sample is None:
            raise AppError(
                code="sample_not_found",
                message=f"Sample '{sample_id}' not found.",
                status_code=404,
            )

        query_features = extract_similarity_features(sample)
        self.index.index_sample(query_features)

        candidates = self.index.list_candidates(exclude_sample_id=sample_id)
        matches: list[SampleSimilarityMatch] = []

        for candidate_features in candidates:
            cand_sample = self.metadata_repository.get(candidate_features.sample_id)
            cand_filename = cand_sample.original_filename if cand_sample else "unknown"
            match = compare_samples(
                query_features=query_features,
                candidate_features=candidate_features,
                target_filename=cand_filename,
            )
            matches.append(match)

        # Sort matches descending by overall similarity and file similarity
        matches.sort(
            key=lambda m: (m.overall_similarity, m.file_similarity, m.code_similarity),
            reverse=True,
        )
        ranked_matches = matches[:max_matches]

        cluster_matches = [
            m
            for m in ranked_matches
            if m.hypothesis == SimilarityHypothesis.POSSIBLE_RELATED_CLUSTER
        ]
        summary = (
            f"Evaluated {len(candidates)} candidate sample(s). "
            f"Identified {len(cluster_matches)} possible related cluster match(es)."
        )
        limitations = [
            (
                "Similarity scores reflect technical feature overlap and do NOT establish "
                "malware family attribution, threat actor identity, or campaign membership."
            ),
            (
                "Results are dependent on upstream static, reverse engineering, "
                "and behavioral analysis artifacts."
            ),
        ]

        report = SimilarityReport(
            sample_id=sample_id,
            sha256=sample.hashes.sha256,
            created_at=datetime.now(UTC),
            schema_version="similarity/v1",
            feature_version="similarity_features/v1",
            scoring_version="similarity_scoring/v1",
            total_candidates_evaluated=len(candidates),
            matches=ranked_matches,
            summary=summary,
            limitations=limitations,
            provenance="similarity_engine:v1",
        )

        # Cache on sample record
        sample.similarity_analysis = report
        sample.malware_assessment = None
        self.metadata_repository.upsert(sample)

        return SimilarityResponse(similarity=report)

    def get(self, sample_id: str) -> SimilarityResultsResponse:
        """Retrieve previously cached similarity analysis results."""
        sample = self.metadata_repository.get(sample_id)
        if sample is None:
            raise AppError(
                code="sample_not_found",
                message=f"Sample '{sample_id}' not found.",
                status_code=404,
            )

        if sample.similarity_analysis is None:
            raise AppError(
                code="similarity_not_found",
                message=f"Similarity analysis has not been run for sample '{sample_id}'.",
                status_code=404,
            )

        return SimilarityResultsResponse(similarity=sample.similarity_analysis)
