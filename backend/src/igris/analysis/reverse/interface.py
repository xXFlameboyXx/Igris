"""Reverse engineering interface marker."""

from igris.analysis.interfaces import Analyzer


class ReverseEngineeringAnalyzer(Analyzer):
    """Future interface for reverse-engineering workflows."""

    kind = "reverse"
