"""Static analysis interface marker."""

from igris.analysis.interfaces import Analyzer


class StaticAnalyzer(Analyzer):
    """Future interface for static file inspection that never executes samples."""

    kind = "static"

