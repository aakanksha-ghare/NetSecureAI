
from html import escape
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def generate_pdf_report(report: dict[str, Any]) -> bytes:
    """Generate a PDF document from a structured NetSecureAI report."""
    if not isinstance(report, dict):
        raise TypeError("report must be a dictionary.")

    metadata = report.get("report_metadata")
    device = report.get("device")
    summary = report.get("summary")
    findings = report.get("findings")

    if not all(
        isinstance(value, dict)
        for value in (metadata, device, summary)
    ):
        raise ValueError(
            "Report must contain report_metadata, device, and summary objects."
        )

    if not isinstance(findings, list):
        raise ValueError("Report findings must be a list.")

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="NetSecureAI Compliance Audit Report",
        author="NetSecureAI",
    )

    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            alignment=TA_CENTER,
            textColor=colors.HexColor("#163A5F"),
            spaceAfter=8,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SectionHeading",
            parent=styles["Heading2"],
            textColor=colors.HexColor("#163A5F"),
            spaceBefore=12,
            spaceAfter=6,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SmallText",
            parent=styles["BodyText"],
            fontSize=8,
            leading=10,
            wordWrap="CJK",
        )
    )

    def paragraph(value: Any, style: str = "BodyText") -> Paragraph:
        """Escape arbitrary report text before placing it in a PDF."""
        text = escape(str(value if value is not None else "Not available"))
        text = text.replace("\n", "<br/>")
        return Paragraph(text, styles[style])

    story = [
        paragraph("NetSecureAI", "ReportTitle"),
        paragraph("Network Security Compliance Audit", "Heading2"),
        paragraph(
            f"Generated: {metadata.get('generated_at', 'Not available')}"
        ),
        Spacer(1, 8),
        paragraph("Device Information", "SectionHeading"),
    ]

    device_rows = [
        ["Field", "Value"],
        ["Vendor", str(device.get("vendor", "Not available"))],
        ["Device type", str(device.get("device_type", "Not available"))],
    ]

    device_table = Table(device_rows, colWidths=[45 * mm, 115 * mm])
    device_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#163A5F")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.extend([device_table, Spacer(1, 10)])
    story.append(paragraph("Compliance Summary", "SectionHeading"))

    rate = summary.get("compliance_rate_percent")
    rate_text = f"{rate}%" if rate is not None else "Not calculable"

    summary_rows = [
        ["Metric", "Result"],
        ["Total findings", str(summary.get("total_findings", 0))],
        ["Passed", str(summary.get("passed", 0))],
        ["Failed", str(summary.get("failed", 0))],
        ["Unknown", str(summary.get("unknown", 0))],
        ["Compliance rate (conclusive findings)", rate_text],
    ]

    summary_table = Table(summary_rows, colWidths=[90 * mm, 70 * mm])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#163A5F")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.extend([summary_table, Spacer(1, 8)])

    story.append(paragraph("Technical Severity Counts", "SectionHeading"))
    severity_counts = summary.get("severity_counts", {})
    for severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        story.append(
            paragraph(
                f"{severity}: {severity_counts.get(severity, 0)}"
            )
        )

    story.append(paragraph("Assessed Risk Counts", "SectionHeading"))
    risk_counts = summary.get("assessed_risk_counts", {})
    for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "NOT_ASSESSED"):
        story.append(paragraph(f"{level}: {risk_counts.get(level, 0)}"))

    story.append(
        paragraph(
            metadata.get(
                "assessment_note",
                "Framework mappings do not establish full framework compliance.",
            ),
            "SmallText",
        )
    )

    story.append(paragraph("Detailed Findings", "SectionHeading"))

    if not findings:
        story.append(paragraph("No findings were provided for this report."))
    else:
        for index, finding in enumerate(findings, start=1):
            if not isinstance(finding, dict):
                raise ValueError("Each finding must be a dictionary.")

            story.append(
                paragraph(
                    f"{index}. {finding.get('rule_id', 'Unknown rule')} — "
                    f"{finding.get('title', 'Untitled finding')}",
                    "Heading3",
                )
            )

            for label, key in (
                ("Status", "status"),
                ("Technical severity", "severity"),
                ("Description", "description"),
                ("Evidence", "evidence"),
                ("Source lines", "source_lines"),
                ("Remediation", "remediation"),
            ):
                value = finding.get(key, "Not available")
                if isinstance(value, list):
                    value = ", ".join(str(item) for item in value) or "None"
                story.append(
                    paragraph(f"<b>{escape(label)}:</b> {escape(str(value))}")
                )

            risk = finding.get("risk_assessment")
            if isinstance(risk, dict):
                risk_text = (
                    f"Level={risk.get('level')}; "
                    f"score={risk.get('score')}; "
                    f"likelihood={risk.get('likelihood')}; "
                    f"impact={risk.get('impact')}; "
                    f"rationale={risk.get('rationale')}"
                )
            else:
                risk_text = "Not assessed"

            story.append(paragraph(f"<b>Assessed risk:</b> {risk_text}"))

            mappings = finding.get("framework_mappings", [])
            if mappings:
                story.append(paragraph("<b>Related framework controls:</b>"))
                for mapping in mappings:
                    if not isinstance(mapping, dict):
                        continue
                    story.append(
                        paragraph(
                            f"{mapping.get('framework', 'Unknown framework')} — "
                            f"{mapping.get('control_id', 'Unknown control')}: "
                            f"{mapping.get('control_title', 'Untitled control')}",
                            "SmallText",
                        )
                    )
                    if mapping.get("rationale"):
                        story.append(
                            paragraph(
                                f"Rationale: {mapping['rationale']}",
                                "SmallText",
                            )
                        )

            evidence_hash = finding.get("evidence_hash")
            if isinstance(evidence_hash, dict):
                story.append(
                    paragraph(
                        f"<b>Evidence hash:</b> "
                        f"{evidence_hash.get('algorithm', 'Unknown')} "
                        f"{evidence_hash.get('digest', 'Unavailable')}",
                        "SmallText",
                    )
                )

            story.append(Spacer(1, 8))

    configuration_hash = report.get("configuration_hash")
    if isinstance(configuration_hash, dict):
        story.append(paragraph("Configuration Integrity", "SectionHeading"))
        story.append(
            paragraph(
                f"Algorithm: {configuration_hash.get('algorithm', 'Unknown')}"
            )
        )
        story.append(
            paragraph(
                f"Digest: {configuration_hash.get('digest', 'Unavailable')}",
                "SmallText",
            )
        )

    evidence_record = report.get("evidence_record")
    if isinstance(evidence_record, dict):
        story.append(paragraph("Evidence Record", "SectionHeading"))
        story.append(
            paragraph(
                f"Record ID: {evidence_record.get('record_id', 'Unavailable')}",
                "SmallText",
            )
        )
        story.append(
            paragraph(
                f"Created at: {evidence_record.get('created_at', 'Unavailable')}",
                "SmallText",
            )
        )

    document.build(story)
    return buffer.getvalue()
