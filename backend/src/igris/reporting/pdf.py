"""Pure Python, zero-dependency, deterministic PDF generator for Igris investigation reports."""

import re
from typing import Any

from igris.schemas.investigation import InvestigationReport


def _sanitize_pdf_text(text: Any) -> str:
    """Sanitize and escape text for safe inclusion in PDF content streams."""
    if text is None:
        return ""
    s = str(text)
    # Remove control characters except tab and newline
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", "", s)
    # Replace newlines with spaces for single-line text
    s = s.replace("\r", " ").replace("\n", " ")
    # Escape PDF string literals
    s = s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    # Keep within standard printable ASCII for PDF Type 1 standard fonts
    return "".join(c if ord(c) < 128 else f"&#{ord(c)};" for c in s)


def _wrap_text(text: str, max_chars: int = 80) -> list[str]:
    """Wrap long text into multiple lines of at most max_chars length."""
    words = text.split(" ")
    lines: list[str] = []
    current_line = ""

    for word in words:
        if not word:
            continue
        if len(current_line) + len(word) + 1 <= max_chars:
            current_line = f"{current_line} {word}".strip()
        else:
            if current_line:
                lines.append(current_line)
            current_line = word

    if current_line:
        lines.append(current_line)

    return lines or [""]


class PDFPage:
    """Represents a single PDF page with drawing streams."""

    def __init__(self, width: float = 595.28, height: float = 841.89) -> None:
        self.width = width
        self.height = height
        self.commands: list[str] = []

    def add_rect(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        fill_rgb: tuple[float, float, float] | None = None,
        stroke_rgb: tuple[float, float, float] | None = None,
        line_width: float = 1.0,
    ) -> None:
        self.commands.append("q")
        if fill_rgb:
            self.commands.append(f"{fill_rgb[0]:.3f} {fill_rgb[1]:.3f} {fill_rgb[2]:.3f} rg")
        if stroke_rgb:
            self.commands.append(f"{stroke_rgb[0]:.3f} {stroke_rgb[1]:.3f} {stroke_rgb[2]:.3f} RG")
            self.commands.append(f"{line_width:.2f} w")
        self.commands.append(f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re")
        if fill_rgb and stroke_rgb:
            self.commands.append("B")
        elif fill_rgb:
            self.commands.append("f")
        elif stroke_rgb:
            self.commands.append("S")
        self.commands.append("Q")

    def add_text(
        self,
        x: float,
        y: float,
        text: str,
        font: str = "F1",
        size: float = 10.0,
        rgb: tuple[float, float, float] = (0.1, 0.15, 0.2),
    ) -> None:
        sanitized = _sanitize_pdf_text(text)
        self.commands.append("BT")
        self.commands.append(f"{rgb[0]:.3f} {rgb[1]:.3f} {rgb[2]:.3f} rg")
        self.commands.append(f"/{font} {size:.1f} Tf")
        self.commands.append(f"{x:.2f} {y:.2f} Td")
        self.commands.append(f"({sanitized}) Tj")
        self.commands.append("ET")

    def render_stream(self) -> bytes:
        return "\n".join(self.commands).encode("latin-1", errors="replace")


class PurePDFRenderer:
    """Renders structured investigation reports to secure, standards-compliant PDF bytes."""

    def render(self, report: InvestigationReport) -> bytes:
        pages: list[PDFPage] = []

        # Margin & Layout bounds (A4: 595.28 x 841.89)
        margin_left = 40.0
        margin_right = 555.28
        margin_top = 800.0
        margin_bottom = 50.0
        page_width = 595.28

        curr_page = PDFPage()
        pages.append(curr_page)
        curr_y = margin_top

        def check_page_break(needed_height: float) -> None:
            nonlocal curr_page, curr_y
            if curr_y - needed_height < margin_bottom:
                curr_page = PDFPage()
                pages.append(curr_page)
                curr_y = margin_top

        # =====================================================================
        # 1. Header Banner & Branding
        # =====================================================================
        curr_page.add_rect(
            margin_left, curr_y - 4, margin_right - margin_left, 36, fill_rgb=(0.06, 0.09, 0.15)
        )
        curr_page.add_text(
            margin_left + 12,
            curr_y + 12,
            "IGRIS MALWARE ASSESSMENT DOSSIER",
            font="F2",
            size=14,
            rgb=(0.22, 0.74, 0.97),
        )
        curr_page.add_text(
            margin_right - 140,
            curr_y + 14,
            f"CONFIDENTIAL • {report.version_metadata.report_schema_version}",
            font="F1",
            size=8,
            rgb=(0.6, 0.7, 0.8),
        )
        curr_y -= 46

        # =====================================================================
        # 2. Verdict & Risk Stamp Card
        # =====================================================================
        verdict = report.verdict_assessment.get("verdict", "UNKNOWN")
        risk_level = report.verdict_assessment.get("risk_level", "UNKNOWN")
        risk_score_raw = report.verdict_assessment.get("risk_score", 0)
        risk_score_dict = risk_score_raw if isinstance(risk_score_raw, dict) else {}
        if isinstance(risk_score_raw, dict):
            risk_score = risk_score_raw.get("score", 0)
        else:
            try:
                risk_score = int(risk_score_raw)
            except (ValueError, TypeError):
                risk_score = 0

        # Background card color based on verdict
        card_fill = (0.95, 0.96, 0.98)
        border_rgb = (0.2, 0.5, 0.8)
        if verdict == "HIGHLY_SUSPICIOUS":
            card_fill = (0.98, 0.92, 0.92)
            border_rgb = (0.8, 0.15, 0.15)
        elif verdict == "SUSPICIOUS":
            card_fill = (0.99, 0.95, 0.90)
            border_rgb = (0.9, 0.45, 0.1)
        elif verdict == "BENIGN":
            card_fill = (0.92, 0.98, 0.94)
            border_rgb = (0.1, 0.6, 0.3)

        curr_page.add_rect(
            margin_left,
            curr_y - 44,
            margin_right - margin_left,
            50,
            fill_rgb=card_fill,
            stroke_rgb=border_rgb,
            line_width=1.5,
        )
        curr_page.add_text(
            margin_left + 12,
            curr_y - 12,
            f"VERDICT: {verdict}    [ RISK: {risk_level} ]",
            font="F2",
            size=13,
            rgb=(0.1, 0.1, 0.15),
        )
        formula_text = risk_score_dict.get("formula", "min(100, max(0, sum(pos) - 0.5*sum(mit)))")
        curr_page.add_text(
            margin_left + 12,
            curr_y - 30,
            f"Evidence Risk Score: {risk_score} / 100  |  Formula: {formula_text}",
            font="F1",
            size=9,
            rgb=(0.3, 0.35, 0.4),
        )
        curr_page.add_text(
            margin_right - 130,
            curr_y - 18,
            f"Score: {risk_score}/100",
            font="F2",
            size=16,
            rgb=border_rgb,
        )
        curr_y -= 64

        # =====================================================================
        # 3. Sample Identification Table
        # =====================================================================
        check_page_break(90)
        curr_page.add_text(
            margin_left,
            curr_y,
            "1. Sample Identification",
            font="F2",
            size=12,
            rgb=(0.02, 0.4, 0.7),
        )
        curr_page.add_rect(
            margin_left, curr_y - 4, margin_right - margin_left, 1, fill_rgb=(0.02, 0.4, 0.7)
        )
        curr_y -= 18

        ident = report.sample_identification
        curr_page.add_text(
            margin_left,
            curr_y,
            f"Original Filename: {ident.get('original_filename', 'N/A')}",
            font="F2",
            size=9,
        )
        curr_page.add_text(
            margin_left + 260,
            curr_y,
            f"File Size: {ident.get('size_bytes', 0):,} bytes",
            font="F1",
            size=9,
        )
        curr_y -= 14

        curr_page.add_text(
            margin_left, curr_y, f"SHA-256: {ident.get('sha256', 'N/A')}", font="F3", size=8.5
        )
        curr_y -= 14

        fmt_str = (
            f"Format: {ident.get('detected_format', 'PE').upper()} "
            f"({ident.get('architecture', 'x86_64')})"
        )
        curr_page.add_text(
            margin_left,
            curr_y,
            fmt_str,
            font="F1",
            size=9,
        )
        curr_page.add_text(
            margin_left + 260,
            curr_y,
            f"Ingested At: {ident.get('created_at', 'N/A')}",
            font="F1",
            size=9,
        )
        curr_y -= 24

        # =====================================================================
        # 4. Executive Summary
        # =====================================================================
        check_page_break(70)
        curr_page.add_text(
            margin_left, curr_y, "2. Executive Summary", font="F2", size=12, rgb=(0.02, 0.4, 0.7)
        )
        curr_page.add_rect(
            margin_left, curr_y - 4, margin_right - margin_left, 1, fill_rgb=(0.02, 0.4, 0.7)
        )
        curr_y -= 18

        for line in _wrap_text(report.executive_summary, max_chars=95):
            check_page_break(14)
            curr_page.add_text(
                margin_left, curr_y, line, font="F1", size=9.5, rgb=(0.15, 0.15, 0.2)
            )
            curr_y -= 14
        curr_y -= 12

        # =====================================================================
        # 5. Epistemological Findings Breakdown
        # =====================================================================
        check_page_break(80)
        curr_page.add_text(
            margin_left,
            curr_y,
            "3. Epistemological Findings Breakdown",
            font="F2",
            size=12,
            rgb=(0.02, 0.4, 0.7),
        )
        curr_page.add_rect(
            margin_left, curr_y - 4, margin_right - margin_left, 1, fill_rgb=(0.02, 0.4, 0.7)
        )
        curr_y -= 18

        # Observed
        obs = report.epistemology_summary.get("observed_facts", [])
        curr_page.add_text(
            margin_left,
            curr_y,
            f"3.1 Directly Observed Facts ({len(obs)})",
            font="F2",
            size=10,
            rgb=(0.0, 0.35, 0.65),
        )
        curr_y -= 14
        for item in obs or ["None recorded."]:
            for line in _wrap_text(f"• [OBSERVED] {item}", max_chars=92):
                check_page_break(14)
                curr_page.add_text(margin_left + 8, curr_y, line, font="F1", size=8.5)
                curr_y -= 13
        curr_y -= 6

        # Inferred
        inf = report.epistemology_summary.get("inferred_conclusions", [])
        check_page_break(30)
        curr_page.add_text(
            margin_left,
            curr_y,
            f"3.2 Inferred Analytical Deductions & Rule Triggers ({len(inf)})",
            font="F2",
            size=10,
            rgb=(0.4, 0.2, 0.6),
        )
        curr_y -= 14
        for item in inf or ["None recorded."]:
            for line in _wrap_text(f"• [INFERRED] {item}", max_chars=92):
                check_page_break(14)
                curr_page.add_text(margin_left + 8, curr_y, line, font="F1", size=8.5)
                curr_y -= 13
        curr_y -= 6

        # Possible Hypotheses
        pos = report.epistemology_summary.get("possible_hypotheses", [])
        check_page_break(30)
        curr_page.add_text(
            margin_left,
            curr_y,
            f"3.3 Potential Cluster Hypotheses ({len(pos)})",
            font="F2",
            size=10,
            rgb=(0.25, 0.25, 0.6),
        )
        curr_y -= 14
        for item in pos or ["None recorded."]:
            for line in _wrap_text(f"• [POSSIBLE] {item}", max_chars=92):
                check_page_break(14)
                curr_page.add_text(margin_left + 8, curr_y, line, font="F1", size=8.5)
                curr_y -= 13
        curr_y -= 14

        # =====================================================================
        # 6. Multi-Layer Traceable Evidence Matrix
        # =====================================================================
        check_page_break(70)
        curr_page.add_text(
            margin_left,
            curr_y,
            f"4. Traceable Evidence Matrix ({len(report.evidence_items)})",
            font="F2",
            size=12,
            rgb=(0.02, 0.4, 0.7),
        )
        curr_page.add_rect(
            margin_left, curr_y - 4, margin_right - margin_left, 1, fill_rgb=(0.02, 0.4, 0.7)
        )
        curr_y -= 18

        for ev in report.evidence_items:
            check_page_break(34)
            curr_page.add_rect(
                margin_left,
                curr_y - 22,
                margin_right - margin_left,
                24,
                fill_rgb=(0.96, 0.97, 0.99),
                stroke_rgb=(0.85, 0.88, 0.92),
                line_width=0.5,
            )
            curr_page.add_text(
                margin_left + 6,
                curr_y - 8,
                f"[{ev.category}] [{ev.observation_level}] [{ev.role}]",
                font="F2",
                size=8,
                rgb=(0.02, 0.35, 0.65),
            )
            curr_page.add_text(
                margin_left + 160,
                curr_y - 8,
                f"ID: {ev.evidence_id}  |  Prov: {ev.provenance}",
                font="F3",
                size=7.5,
                rgb=(0.4, 0.45, 0.5),
            )

            lines = _wrap_text(ev.statement, max_chars=95)
            curr_page.add_text(
                margin_left + 6, curr_y - 19, lines[0], font="F1", size=8, rgb=(0.1, 0.1, 0.15)
            )
            curr_y -= 28

        curr_y -= 10

        # =====================================================================
        # 7. Analyst-Authored Notes (Strict Separation)
        # =====================================================================
        check_page_break(70)
        curr_page.add_text(
            margin_left,
            curr_y,
            f"5. Analyst-Authored Notes ({len(report.analyst_notes)})",
            font="F2",
            size=12,
            rgb=(0.6, 0.2, 0.0),
        )
        curr_page.add_rect(
            margin_left, curr_y - 4, margin_right - margin_left, 1, fill_rgb=(0.6, 0.2, 0.0)
        )
        curr_y -= 18

        curr_page.add_text(
            margin_left,
            curr_y,
            "[NOTE: The content below is authored by human analysts "
            "and is stored strictly separate from automated evidence.]",
            font="F2",
            size=8,
            rgb=(0.5, 0.3, 0.1),
        )
        curr_y -= 14

        if report.analyst_notes:
            for note in report.analyst_notes:
                check_page_break(40)
                curr_page.add_rect(
                    margin_left,
                    curr_y - 28,
                    margin_right - margin_left,
                    32,
                    fill_rgb=(0.99, 0.97, 0.94),
                    stroke_rgb=(0.85, 0.7, 0.5),
                    line_width=0.5,
                )
                curr_page.add_text(
                    margin_left + 6,
                    curr_y - 8,
                    f"Author: {note.author}  •  Title: {note.title}",
                    font="F2",
                    size=8.5,
                    rgb=(0.4, 0.15, 0.0),
                )
                curr_page.add_text(
                    margin_right - 140,
                    curr_y - 8,
                    note.created_at.strftime("%Y-%m-%d %H:%M UTC"),
                    font="F1",
                    size=7.5,
                    rgb=(0.5, 0.4, 0.3),
                )

                note_lines = _wrap_text(note.content, max_chars=95)
                curr_page.add_text(
                    margin_left + 6,
                    curr_y - 20,
                    note_lines[0],
                    font="F1",
                    size=8,
                    rgb=(0.15, 0.1, 0.05),
                )
                curr_y -= 36
        else:
            curr_page.add_text(
                margin_left,
                curr_y,
                "No analyst notes attached to this investigation.",
                font="F1",
                size=8.5,
                rgb=(0.5, 0.5, 0.5),
            )
            curr_y -= 14

        curr_y -= 10

        # =====================================================================
        # 8. Analytical Limitations & Attribution Guardrails
        # =====================================================================
        check_page_break(70)
        curr_page.add_text(
            margin_left,
            curr_y,
            "6. Analytical Limitations & Attribution Guardrails",
            font="F2",
            size=12,
            rgb=(0.02, 0.4, 0.7),
        )
        curr_page.add_rect(
            margin_left, curr_y - 4, margin_right - margin_left, 1, fill_rgb=(0.02, 0.4, 0.7)
        )
        curr_y -= 18

        for lim in report.limitations:
            for line in _wrap_text(f"[GUARDRAIL] {lim}", max_chars=92):
                check_page_break(14)
                curr_page.add_text(
                    margin_left + 6, curr_y, line, font="F1", size=8, rgb=(0.3, 0.35, 0.4)
                )
                curr_y -= 13

        # =====================================================================
        # 9. Page Numbers & Footers Across All Pages
        # =====================================================================
        total_pages = len(pages)
        for idx, page in enumerate(pages, start=1):
            page.add_rect(
                margin_left, 36, margin_right - margin_left, 0.5, fill_rgb=(0.7, 0.75, 0.8)
            )
            page.add_text(
                margin_left,
                24,
                "IGRIS v0.1.0 • Explainable Malware Intelligence",
                font="F1",
                size=7.5,
                rgb=(0.5, 0.55, 0.6),
            )
            page.add_text(
                page_width / 2 - 30,
                24,
                f"Page {idx} of {total_pages}",
                font="F1",
                size=8,
                rgb=(0.3, 0.35, 0.4),
            )
            page.add_text(
                margin_right - 140,
                24,
                f"SHA-256: {report.sha256[:16]}…",
                font="F3",
                size=7.5,
                rgb=(0.5, 0.55, 0.6),
            )

        # =====================================================================
        # 10. Assemble PDF Binary Structure
        # =====================================================================
        return self._assemble_pdf(pages)

    def _assemble_pdf(self, pages: list[PDFPage]) -> bytes:
        """Serialize pages into standards-compliant PDF 1.4 byte stream."""
        objects: list[bytes] = []

        # Object 1: Catalog
        objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")

        # Object 2: Pages tree placeholder (computed after kids)
        # Objects 3, 4, 5: Font definitions (F1: Helvetica, F2: Helvetica-Bold, F3: Courier)
        font_f1 = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
        font_f2 = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"
        font_f3 = b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>"

        # Start object numbering
        # Obj 1: Catalog
        # Obj 2: Pages
        # Obj 3: F1, Obj 4: F2, Obj 5: F3
        # For each page i:
        #   Obj (6 + 2*i): Page dict
        #   Obj (7 + 2*i): Contents stream
        num_pages = len(pages)
        kids_refs = []
        page_and_stream_objects = []

        for i, page in enumerate(pages):
            page_obj_num = 6 + 2 * i
            stream_obj_num = 7 + 2 * i
            kids_refs.append(f"{page_obj_num} 0 R")

            stream_data = page.render_stream()
            stream_obj = (
                f"<< /Length {len(stream_data)} >>\nstream\n".encode("latin-1")
                + stream_data
                + b"\nendstream"
            )

            page_obj = (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {page.width:.2f} {page.height:.2f}] "
                f"/Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> "
                f"/Contents {stream_obj_num} 0 R >>"
            ).encode("latin-1")

            page_and_stream_objects.append((page_obj, stream_obj))

        pages_tree = f"<< /Type /Pages /Kids [{' '.join(kids_refs)}] /Count {num_pages} >>".encode(
            "latin-1"
        )

        all_objs = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            pages_tree,
            font_f1,
            font_f2,
            font_f3,
        ]

        for p_obj, s_obj in page_and_stream_objects:
            all_objs.append(p_obj)
            all_objs.append(s_obj)

        # Build output with cross-reference table
        output = bytearray()
        output.extend(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

        offsets = []
        for i, obj_bytes in enumerate(all_objs, start=1):
            offsets.append(len(output))
            output.extend(f"{i} 0 obj\n".encode("latin-1"))
            output.extend(obj_bytes)
            output.extend(b"\nendobj\n")

        xref_offset = len(output)
        output.extend(f"xref\n0 {len(all_objs) + 1}\n".encode("latin-1"))
        output.extend(b"0000000000 65535 f \n")
        for offset in offsets:
            output.extend(f"{offset:010d} 00000 n \n".encode("latin-1"))

        trailer = (
            f"trailer\n<< /Size {len(all_objs) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode("latin-1")
        output.extend(trailer)

        return bytes(output)
