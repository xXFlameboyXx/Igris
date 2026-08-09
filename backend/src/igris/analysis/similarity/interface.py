"""Similarity analysis interface marker."""

from igris.analysis.interfaces import Analyzer


class SimilarityAnalyzer(Analyzer):
    """Future interface for similarity and clustering workflows."""

    kind = "similarity"

