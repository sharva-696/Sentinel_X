import io
import xml.sax.saxutils as saxutils
from typing import Dict, Any, List, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
    HRFlowable,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas


def safe_xml(val: Any) -> str:
    """Escapes user and firmware input for ReportLab's XML-based Paragraph parser."""
    if val is None:
        return ""
    # saxutils escapes &, <, >. We also escape quotes if needed.
    return saxutils.escape(str(val))


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas that accumulates pages and renders total page counts
    ('Page X of Y') and professional running headers on all pages.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Running Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(36, 756, "Sentinel-X ESP32 Security Assessment Report")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(36, 750, 576, 750)

        # Running Footer (all pages)
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(36, 42, 576, 42)
        self.drawString(36, 30, "CONFIDENTIAL — ESP32 SECURITY ASSESSMENT REPORT")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(576, 30, page_str)
        self.restoreState()


def get_severity_color(severity: str) -> colors.HexColor:
    sev = str(severity).strip().capitalize()
    mapping = {
        "Critical": colors.HexColor("#b91c1c"),
        "High": colors.HexColor("#ea580c"),
        "Medium": colors.HexColor("#ca8a04"),
        "Low": colors.HexColor("#0284c7"),
        "Informational": colors.HexColor("#475569"),
    }
    return mapping.get(sev, colors.HexColor("#475569"))


def get_severity_bg_color(severity: str) -> colors.HexColor:
    sev = str(severity).strip().capitalize()
    mapping = {
        "Critical": colors.HexColor("#fef2f2"),
        "High": colors.HexColor("#fff7ed"),
        "Medium": colors.HexColor("#fefce8"),
        "Low": colors.HexColor("#f0f9ff"),
        "Informational": colors.HexColor("#f8fafc"),
    }
    return mapping.get(sev, colors.HexColor("#f8fafc"))


def generate_pdf_report(data: Dict[str, Any]) -> bytes:
    """
    Generates a high-quality, professional, downloadable PDF assessment report.
    Consumes the canonical data structure produced by data_loader.py.
    
    Guarantees:
    - Strict XML escaping on all dynamic and firmware-derived fields.
    - Two-pass 'Page X of Y' page numbering.
    - Repeated table headers across multiple pages (repeatRows=1).
    - Wrapping all cell content in Paragraph flowables to prevent text clipping.
    - Zero remote network dependencies.
    """
    buffer = io.BytesIO()
    
    # 540 pt printable width (letter = 612 x 792, margins = 36 pt left/right)
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=46,
        bottomMargin=46,
    )

    base_styles = getSampleStyleSheet()

    # Custom typography styles
    style_title = ParagraphStyle(
        "ReportTitle",
        parent=base_styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=2,
    )
    style_sub = ParagraphStyle(
        "ReportSub",
        parent=base_styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=12,
    )
    style_h2 = ParagraphStyle(
        "SectionHeading",
        parent=base_styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True,
    )
    style_h3 = ParagraphStyle(
        "SubSectionHeading",
        parent=base_styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True,
    )
    style_body = ParagraphStyle(
        "ReportBody",
        parent=base_styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=4,
    )
    style_body_bold = ParagraphStyle(
        "ReportBodyBold",
        parent=style_body,
        fontName="Helvetica-Bold",
    )
    style_code = ParagraphStyle(
        "ReportCode",
        parent=base_styles["Code"],
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#0f172a"),
    )
    style_evidence = ParagraphStyle(
        "EvidenceSnippet",
        parent=base_styles["Code"],
        fontName="Courier",
        fontSize=7,
        leading=9.5,
        textColor=colors.HexColor("#0f172a"),
    )
    style_callout = ParagraphStyle(
        "CalloutText",
        parent=style_body,
        fontName="Helvetica-Oblique",
        fontSize=8,
        leading=11.5,
        textColor=colors.HexColor("#0369a1"),
    )
    style_table_header = ParagraphStyle(
        "TableHeader",
        parent=style_body,
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#475569"),
    )

    story = []

    # =========================================================================
    # A. Header & Cover Metadata
    # =========================================================================
    story.append(Paragraph("Sentinel-X", style_title))
    story.append(Paragraph("ESP32 Embedded Device Security Assessment Platform", style_sub))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0284c7"), spaceAfter=10))

    meta_table_data = [
        [
            Paragraph("<b>Assessment ID:</b>", style_body),
            Paragraph(f"<code>{safe_xml(data['assessment_id'])}</code>", style_body),
            Paragraph("<b>Execution Status:</b>", style_body),
            Paragraph(f"<b>{safe_xml(data['status'])}</b>", style_body),
        ],
        [
            Paragraph("<b>Target File:</b>", style_body),
            Paragraph(f"{safe_xml(data['filename'])} ({safe_xml(data['file_size_formatted'])})", style_body),
            Paragraph("<b>Assessment Date:</b>", style_body),
            Paragraph(safe_xml(data['created_at']), style_body),
        ],
        [
            Paragraph("<b>SHA-256 Hash:</b>", style_body),
            Paragraph(f"<code>{safe_xml(data['sha256'])}</code>", style_body),
            Paragraph("<b>Report Generated:</b>", style_body),
            Paragraph(safe_xml(data['generated_at']), style_body),
        ],
        [
            Paragraph("<b>Detected Format:</b>", style_body),
            Paragraph(f"<code>{safe_xml(data['image_type'])}</code>", style_body),
            Paragraph("<b>Hardware Mode:</b>", style_body),
            Paragraph(
                "Offline Firmware Analysis" if data["is_offline_analysis"] else "Hardware Connected",
                style_body
            ),
        ],
    ]
    meta_table = Table(meta_table_data, colWidths=[90, 200, 100, 150])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # Optional Device Details if interrogated
    device = data["device"]
    if device:
        story.append(Paragraph("Interrogated ESP32 Device Specifications", style_h3))
        dev_data = [
            [
                Paragraph("<b>Port:</b>", style_body), Paragraph(f"<code>{safe_xml(device.get('port'))}</code>", style_body),
                Paragraph("<b>Chip Model:</b>", style_body), Paragraph(f"<b>{safe_xml(device.get('chip_type'))}</b>", style_body),
            ],
            [
                Paragraph("<b>MAC Address:</b>", style_body), Paragraph(f"<code>{safe_xml(device.get('mac_address'))}</code>", style_body),
                Paragraph("<b>Flash Size:</b>", style_body), Paragraph(f"{safe_xml(device.get('flash_size') or 'N/A')}", style_body),
            ],
        ]
        dev_table = Table(dev_data, colWidths=[80, 190, 80, 190])
        dev_table.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(dev_table)
        story.append(Spacer(1, 10))

    # Partition Table if present
    partitions = data.get("partitions", [])
    if partitions:
        story.append(Paragraph("Partition Table Structure", style_h3))
        part_data = [[
            Paragraph("Label", style_table_header),
            Paragraph("Type", style_table_header),
            Paragraph("Subtype", style_table_header),
            Paragraph("Offset", style_table_header),
            Paragraph("Size", style_table_header),
            Paragraph("Flags", style_table_header),
        ]]
        for p in partitions:
            part_data.append([
                Paragraph(f"<code>{safe_xml(p.get('label'))}</code>", style_code),
                Paragraph(safe_xml(p.get("type")), style_body),
                Paragraph(safe_xml(p.get("subtype")), style_body),
                Paragraph(f"<code>0x{p.get('offset', 0):06x}</code>", style_code),
                Paragraph(f"{p.get('size_bytes', 0) // 1024} KB", style_body),
                Paragraph(safe_xml(p.get("flags", "None")), style_body),
            ])
        part_table = Table(part_data, colWidths=[100, 80, 90, 90, 80, 100], repeatRows=1)
        part_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(part_table)
        story.append(Spacer(1, 10))

    # =========================================================================
    # B. Executive Summary & Risk Summary Table
    # =========================================================================
    story.append(Paragraph("Executive Summary", style_h2))
    counts = data["summary_counts"]

    summary_metric_data = [
        [
            Paragraph("<b>Risk Score</b>", style_table_header),
            Paragraph("<b>Risk Band</b>", style_table_header),
            Paragraph("<b>Total Unique</b>", style_table_header),
            Paragraph("<b>Critical</b>", style_table_header),
            Paragraph("<b>High</b>", style_table_header),
            Paragraph("<b>Medium</b>", style_table_header),
            Paragraph("<b>Low</b>", style_table_header),
        ],
        [
            Paragraph(f"<font size='12'><b>{data['risk_score']} / 100</b></font>", style_body),
            Paragraph(f"<b>{safe_xml(data['risk_rating'])}</b>", style_body),
            Paragraph(f"<font size='12'><b>{data['total_findings']}</b></font>", style_body),
            Paragraph(f"<font color='#b91c1c' size='11'><b>{counts['Critical']}</b></font>", style_body),
            Paragraph(f"<font color='#ea580c' size='11'><b>{counts['High']}</b></font>", style_body),
            Paragraph(f"<font color='#ca8a04' size='11'><b>{counts['Medium']}</b></font>", style_body),
            Paragraph(f"<font color='#0284c7' size='11'><b>{counts['Low']}</b></font>", style_body),
        ]
    ]
    summary_table = Table(summary_metric_data, colWidths=[80, 80, 80, 75, 75, 75, 75])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 8))

    advisory_box = [
        [Paragraph(
            "<b>Defensive Indicator Notice:</b> All findings represent potential indicators identified through static heuristics, "
            "pattern matching, and configuration analysis. Static detection does not constitute confirmed exploitability. "
            "Each indicator should be manually audited against production device environments.",
            style_callout
        )]
    ]
    advisory_table = Table(advisory_box, colWidths=[540])
    advisory_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0f9ff")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#0284c7")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(advisory_table)
    story.append(Spacer(1, 12))

    # =========================================================================
    # C. Assessment Methodology
    # =========================================================================
    story.append(Paragraph("Assessment Methodology", style_h2))
    method_text = (
        "Sentinel-X performs evidence-based, defensive static analysis of ESP32 firmware binaries. "
        "The analysis pipeline executes the following safe operations:<br/>"
        "&bull; <b>Image Header Validation:</b> Parses the 24-byte ESP magic (<code>0xE9</code>), memory segments, entry addresses, and SPI configuration.<br/>"
        "&bull; <b>Partition Inspection:</b> Audits dual OTA redundancy and NVS partitions.<br/>"
        "&bull; <b>Printable String Extraction:</b> Indexes ASCII and UTF-8 strings with byte-level offsets across flash sections.<br/>"
        "&bull; <b>Secret Scanning & Entropy Analysis:</b> Evaluates regular expression rules and Shannon entropy for sensitive tokens.<br/>"
        "&bull; <b>Deduplication & Offset Aggregation:</b> Computes cryptographic fingerprints to collapse duplicates while tracking all spatial offsets.<br/>"
        "&bull; <b>Deterministic Risk Scoring:</b> Bounded 0–100 risk calculation using severity weights, confidence factors, and occurrence dampening."
    )
    story.append(Paragraph(method_text, style_body))
    story.append(Spacer(1, 6))

    guarantee_box = [
        [Paragraph(
            "<b>Scope Guarantee:</b> Sentinel-X strictly excludes destructive operations. It does not flash firmware, alter eFuses, "
            "execute code on host or microcontroller, or perform dynamic penetration testing.",
            style_body
        )]
    ]
    guarantee_table = Table(guarantee_box, colWidths=[540])
    guarantee_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(guarantee_table)
    story.append(Spacer(1, 14))

    # =========================================================================
    # D. Detailed Security Findings
    # =========================================================================
    findings: List[Dict[str, Any]] = data["findings"]
    story.append(Paragraph(f"Detailed Security Findings ({len(findings)})", style_h2))

    if findings:
        for idx, f in enumerate(findings, 1):
            finding_flowables = []
            
            # 1. Finding Header Table
            sev_color = get_severity_color(f["severity"])
            sev_bg = get_severity_bg_color(f["severity"])
            header_table_data = [
                [
                    Paragraph(f"<b>#{idx}. {safe_xml(f['title'])}</b> <font color='#64748b'>[{safe_xml(f['rule_id'])}]</font>", style_body_bold),
                    Paragraph(f"<font color='{sev_color.hexval()}'><b>{safe_xml(f['severity'].upper())}</b></font>", style_body_bold),
                ]
            ]
            header_table = Table(header_table_data, colWidths=[440, 100])
            header_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), sev_bg),
                ("BOX", (0, 0), (-1, -1), 1, sev_color),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("ALIGN", (1, 0), (1, 0), "RIGHT"),
            ]))
            finding_flowables.append(header_table)

            # 2. Metadata details
            add_offsets = f.get("additional_offsets", [])
            add_offsets_str = ", ".join(safe_xml(o) for o in add_offsets) if add_offsets else "None"

            meta_details = [
                [
                    Paragraph("<b>Category:</b>", style_body), Paragraph(safe_xml(f["category"]), style_body),
                    Paragraph("<b>Confidence:</b>", style_body), Paragraph(safe_xml(f["confidence"]), style_body),
                ],
                [
                    Paragraph("<b>Primary Offset:</b>", style_body), Paragraph(f"<code>{safe_xml(f['byte_offset'])}</code>", style_code),
                    Paragraph("<b>Section:</b>", style_body), Paragraph(safe_xml(f["section"]), style_body),
                ],
                [
                    Paragraph("<b>Occurrences (N):</b>", style_body), Paragraph(f"{f.get('total_occurrences', 1)} total", style_body),
                    Paragraph("<b>Additional:</b>", style_body), Paragraph(f"<code>{add_offsets_str}</code>", style_code),
                ],
            ]
            details_table = Table(meta_details, colWidths=[80, 190, 80, 190])
            details_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            finding_flowables.append(details_table)

            # 3. Sanitized Evidence snippet
            evidence_snippet = safe_xml(f.get("evidence_masked", ""))
            evidence_data = [
                [Paragraph("<b>Sanitized Evidence Context:</b>", style_body)],
                [Paragraph(f"<code>{evidence_snippet}</code>", style_evidence)],
            ]
            evidence_table = Table(evidence_data, colWidths=[540])
            evidence_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 1), (-1, 1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]))
            finding_flowables.append(evidence_table)

            # 4. Context rows
            if f.get("rationale"):
                finding_flowables.append(Paragraph(f"<b>Security Rationale:</b> {safe_xml(f['rationale'])}", style_body))
            if f.get("false_positive_cases"):
                finding_flowables.append(Paragraph(f"<b>False Positive Cases:</b> {safe_xml(f['false_positive_cases'])}", style_body))
            if f.get("remediation"):
                finding_flowables.append(Paragraph(f"<b>Remediation:</b> {safe_xml(f['remediation'])}", style_body))
            if f.get("verification_limitations"):
                finding_flowables.append(Paragraph(f"<b>Limitations:</b> {safe_xml(f['verification_limitations'])}", style_body))

            finding_flowables.append(Spacer(1, 10))

            # Keep short findings together
            story.append(KeepTogether(finding_flowables))
    else:
        clean_box = [
            [Paragraph("<b>No Static Indicators Detected:</b> The automated scanner detected zero hardcoded secrets or insecure configuration patterns in this firmware artifact.", style_body)]
        ]
        clean_table = Table(clean_box, colWidths=[540])
        clean_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ecfdf5")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#059669")),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(clean_table)
        story.append(Spacer(1, 12))

    # =========================================================================
    # E. Risk Score Explanation & Breakdown
    # =========================================================================
    story.append(Paragraph("Risk Scoring Methodology & Breakdown", style_h2))
    score_desc = (
        "The Sentinel-X Risk Score is an explainable heuristic derived deterministically from the deduplicated findings. "
        "Each finding contributes points according to its base severity weight and confidence multiplier, dampened for repetitive flash occurrences:<br/>"
        "<code>Finding Points = Base Weight &times; Confidence Multiplier &times; (1.0 + 0.2 &times; min(N - 1, 5))</code><br/>"
        "<code>Final Score = min(100, round(&sum; Finding Points))</code>"
    )
    story.append(Paragraph(score_desc, style_body))
    story.append(Spacer(1, 6))

    score_items = data["score_breakdown"].get("items", [])
    if score_items:
        score_table_data = [[
            Paragraph("Rule ID", style_table_header),
            Paragraph("Title", style_table_header),
            Paragraph("Severity", style_table_header),
            Paragraph("Confidence", style_table_header),
            Paragraph("Occurrences (N)", style_table_header),
            Paragraph("Multiplier", style_table_header),
            Paragraph("Points", style_table_header),
        ]]
        for item in score_items:
            score_table_data.append([
                Paragraph(f"<code>{safe_xml(item.get('rule_id'))}</code>", style_code),
                Paragraph(safe_xml(item.get("title")), style_body),
                Paragraph(safe_xml(item.get("severity")), style_body),
                Paragraph(f"{safe_xml(item.get('confidence'))} ({item.get('confidence_factor', 0.8):.1f})", style_body),
                Paragraph(str(item.get("occurrences", 1)), style_body),
                Paragraph(f"{item.get('multiplier', 1.0)}x", style_body),
                Paragraph(f"<b>{item.get('calculated_points', 0.0)}</b>", style_body),
            ])
        score_table = Table(score_table_data, colWidths=[70, 160, 60, 80, 60, 50, 60], repeatRows=1)
        score_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(score_table)
        story.append(Spacer(1, 8))

    disclaimer_text = data["score_breakdown"].get("disclaimer", "")
    story.append(Paragraph(f"<i>{safe_xml(disclaimer_text)}</i>", style_sub))
    story.append(Spacer(1, 10))

    # =========================================================================
    # F. Limitations & Defensive Recommendations
    # =========================================================================
    story.append(Paragraph("Limitations & Defensive Recommendations", style_h2))
    limitations_text = (
        "<b>Assessment Limitations:</b><br/>"
        "&bull; <b>Static Analysis Scope:</b> String pattern matching cannot detect obfuscated, dynamically assembled, or encrypted credentials.<br/>"
        "&bull; <b>Encrypted Firmware:</b> Binaries compiled with Flash Encryption enabled cannot be analyzed statically without physical device key extraction.<br/>"
        "&bull; <b>Exploitability Verification:</b> Static detections represent potential indicators and require manual auditing against production environments.<br/>"
        "&bull; <b>Offline Hardware Boundaries:</b> Offline analysis cannot inspect runtime UART outputs, physical pin strapping, or eFuse configuration bits.<br/><br/>"
        "<b>Defensive Recommendations for ESP32 Systems:</b><br/>"
        "&bull; <b>Enable Hardware Security Features:</b> Activate ESP32 Flash Encryption and Secure Boot v2 in production builds.<br/>"
        "&bull; <b>Use Encrypted NVS:</b> Store Wi-Fi credentials and API tokens in NVS partitions encrypted with keys stored in eFuses.<br/>"
        "&bull; <b>Leverage Hardware Cryptography:</b> Use ESP32 Digital Signature (DS) and HMAC peripherals for mutual TLS authentication.<br/>"
        "&bull; <b>Dual OTA Partitions:</b> Configure <code>ota_0</code> and <code>ota_1</code> with an <code>otadata</code> slot for verified, rollback-safe remote updates."
    )
    story.append(Paragraph(limitations_text, style_body))

    # Build the document
    doc.build(story, canvasmaker=NumberedCanvas)
    return buffer.getvalue()
