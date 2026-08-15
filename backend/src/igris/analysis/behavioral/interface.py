"""Behavioral analysis interface marker."""

from igris.analysis.interfaces import Analyzer


class BehavioralAnalyzer(Analyzer):
    """Future interface for sandbox-only behavioral analysis."""

    kind = "behavioral"
