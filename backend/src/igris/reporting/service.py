"""Phase 13: Report Generation Application Service."""

from igris.core.config import Settings
from igris.reporting.generator import ReportGenerator
from igris.reporting.pdf import PurePDFRenderer
from igris.schemas.investigation import InvestigationReport
from igris.storage.binary import LocalSampleStorage
from igris.storage.metadata import SampleMetadataRepository


class ReportingService:
    """Orchestrates investigation report compilation, JSON serialization, and PDF rendering."""

    def __init__(
        self,
        settings: Settings,
        sample_storage: LocalSampleStorage,
        metadata_repository: SampleMetadataRepository,
        generator: ReportGenerator | None = None,
        pdf_renderer: PurePDFRenderer | None = None,
    ) -> None:
        self.settings = settings
        self.sample_storage = sample_storage
        self.metadata_repository = metadata_repository
        self.generator = generator or ReportGenerator(
            settings=settings,
            sample_storage=sample_storage,
            metadata_repository=metadata_repository,
        )
        self.pdf_renderer = pdf_renderer or PurePDFRenderer()

    def generate_report(self, sample_id: str) -> InvestigationReport:
        """Generate a complete, structured investigation report."""
        return self.generator.generate(sample_id)

    def get_report_json(self, sample_id: str) -> str:
        """Return machine-readable deterministic JSON formatted investigation report."""
        report = self.generate_report(sample_id)
        return report.model_dump_json(indent=2)

    def get_report_pdf(self, sample_id: str) -> bytes:
        """Render a formatted, multi-page PDF investigation report."""
        report = self.generate_report(sample_id)
        return self.pdf_renderer.render(report)
