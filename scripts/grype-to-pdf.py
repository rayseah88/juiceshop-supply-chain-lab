#!/usr/bin/env python3
"""
Generate a professional PDF report from Grype vulnerability scan results.

This script reads Grype's JSON output and creates a comprehensive PDF report
with vulnerability details, statistics, and executive summary.
"""

import json
import argparse
import sys
from datetime import datetime
from collections import defaultdict
from pathlib import Path

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer,
        PageBreak, Image
    )
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
except ImportError:
    print("Error: reportlab not found. Install with: pip install reportlab")
    sys.exit(1)


class GrypePDFReport:
    def __init__(self, grype_json_file, sbom_file=None):
        """Initialize the PDF report generator."""
        self.grype_json_file = grype_json_file
        self.sbom_file = sbom_file
        self.grype_data = self._load_json(grype_json_file)
        self.sbom_data = self._load_json(sbom_file) if sbom_file else None
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _load_json(self, filepath):
        """Load and parse JSON file."""
        if not filepath:
            return None
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load {filepath}: {e}")
            return None

    def _setup_custom_styles(self):
        """Setup custom paragraph styles for the report."""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=12,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))

        self.styles.add(ParagraphStyle(
            name='CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))

        self.styles.add(ParagraphStyle(
            name='CriticalVuln',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#d32f2f'),
            fontSize=10,
            fontName='Helvetica-Bold'
        ))

        self.styles.add(ParagraphStyle(
            name='HighVuln',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#f57c00'),
            fontSize=10,
            fontName='Helvetica-Bold'
        ))

        self.styles.add(ParagraphStyle(
            name='MediumVuln',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#fbc02d'),
            fontSize=10,
            fontName='Helvetica-Bold'
        ))

    def _get_severity_color(self, severity):
        """Get color for severity level."""
        severity = severity.lower() if severity else 'unknown'
        colors_map = {
            'critical': colors.HexColor('#d32f2f'),
            'high': colors.HexColor('#f57c00'),
            'medium': colors.HexColor('#fbc02d'),
            'low': colors.HexColor('#388e3c'),
            'negligible': colors.HexColor('#757575'),
            'unknown': colors.HexColor('#9e9e9e')
        }
        return colors_map.get(severity, colors.HexColor('#9e9e9e'))

    def _get_severity_sort_order(self, severity):
        """Get sort order for severity levels."""
        order_map = {
            'critical': 0,
            'high': 1,
            'medium': 2,
            'low': 3,
            'negligible': 4,
            'unknown': 5
        }
        return order_map.get(severity.lower() if severity else 'unknown', 5)

    def _calculate_statistics(self):
        """Calculate vulnerability statistics from Grype data."""
        stats = {
            'total': 0,
            'by_severity': defaultdict(int),
            'by_status': defaultdict(int),
            'packages_affected': set(),
            'vulnerabilities': []
        }

        if not self.grype_data or 'matches' not in self.grype_data:
            return stats

        for match in self.grype_data.get('matches', []):
            vuln = match.get('vulnerability', {})
            metadata = match.get('metadata', {})
            artifact = match.get('artifact', {})

            severity = vuln.get('severity', 'unknown')
            status = vuln.get('fix_state', 'unknown')

            stats['total'] += 1
            stats['by_severity'][severity] += 1
            stats['by_status'][status] += 1

            if 'name' in artifact:
                stats['packages_affected'].add(artifact['name'])

            stats['vulnerabilities'].append({
                'id': vuln.get('id', 'N/A'),
                'package': artifact.get('name', 'Unknown'),
                'severity': severity,
                'description': vuln.get('description', 'No description available'),
                'published': vuln.get('published', 'Unknown'),
                'status': status,
                'fix_versions': artifact.get('version', 'Unknown')
            })

        # Sort vulnerabilities by severity
        stats['vulnerabilities'].sort(
            key=lambda x: self._get_severity_sort_order(x['severity'])
        )

        return stats

    def _build_title_page(self):
        """Build the title page of the report."""
        elements = []

        # Title
        elements.append(Spacer(1, 0.5 * inch))
        title = Paragraph("Grype Vulnerability Report", self.styles['CustomTitle'])
        elements.append(title)

        # Subtitle
        elements.append(Spacer(1, 0.2 * inch))
        subtitle = Paragraph(
            "Supply Chain Security Assessment",
            self.styles['Heading2']
        )
        elements.append(subtitle)

        # Metadata
        elements.append(Spacer(1, 0.4 * inch))
        metadata = [
            f"<b>Report Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"<b>Repository:</b> rayseah88/juiceshop-supply-chain-lab",
            f"<b>Scan Tool:</b> Grype",
        ]
        for line in metadata:
            elements.append(Paragraph(line, self.styles['Normal']))
            elements.append(Spacer(1, 0.1 * inch))

        return elements

    def _build_executive_summary(self, stats):
        """Build executive summary section."""
        elements = []

        elements.append(Paragraph("Executive Summary", self.styles['CustomHeading']))
        elements.append(Spacer(1, 0.2 * inch))

        # Summary statistics
        summary_text = f"""
        <b>Total Vulnerabilities Found:</b> {stats['total']}<br/>
        <b>Affected Packages:</b> {len(stats['packages_affected'])}<br/>
        <b>Scan Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
        """
        elements.append(Paragraph(summary_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.2 * inch))

        # Severity breakdown
        elements.append(Paragraph("Vulnerabilities by Severity", self.styles['Heading3']))
        severity_data = [['Severity', 'Count']]
        total = 0
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown']:
            count = stats['by_severity'].get(severity.lower(), 0)
            severity_data.append([severity, str(count)])
            total += count

        if total > 0:
            severity_table = Table(severity_data, colWidths=[3 * inch, 1 * inch])
            severity_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(severity_table)

        elements.append(PageBreak())
        return elements

    def _build_vulnerability_details(self, stats):
        """Build detailed vulnerability section."""
        elements = []

        elements.append(Paragraph("Detailed Vulnerability Report", self.styles['CustomHeading']))
        elements.append(Spacer(1, 0.2 * inch))

        if stats['total'] == 0:
            elements.append(Paragraph(
                "No vulnerabilities found in the scan.",
                self.styles['Normal']
            ))
            return elements

        # Create vulnerability table
        vuln_data = [
            ['ID', 'Package', 'Severity', 'Description']
        ]

        for vuln in stats['vulnerabilities'][:50]:  # Limit to first 50 for readability
            description = vuln['description'][:80] + '...' if len(vuln['description']) > 80 else vuln['description']
            vuln_data.append([
                vuln['id'],
                vuln['package'][:20] + '...' if len(vuln['package']) > 20 else vuln['package'],
                vuln['severity'].upper(),
                description
            ])

        vuln_table = Table(vuln_data, colWidths=[1.2 * inch, 1.5 * inch, 1 * inch, 2 * inch])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')])
        ]))

        elements.append(vuln_table)
        elements.append(Spacer(1, 0.2 * inch))

        if stats['total'] > 50:
            elements.append(Paragraph(
                f"<i>Showing first 50 of {stats['total']} vulnerabilities. "
                f"See grype-results.json for complete details.</i>",
                self.styles['Normal']
            ))

        elements.append(PageBreak())
        return elements

    def _build_recommendations(self):
        """Build recommendations section."""
        elements = []

        elements.append(Paragraph("Recommendations", self.styles['CustomHeading']))
        elements.append(Spacer(1, 0.2 * inch))

        recommendations = [
            "1. <b>Immediate Action:</b> Address all Critical and High severity vulnerabilities immediately.",
            "2. <b>Dependency Updates:</b> Keep all dependencies up to date with the latest security patches.",
            "3. <b>Monitoring:</b> Implement continuous monitoring of supply chain dependencies.",
            "4. <b>Documentation:</b> Review and document any accepted risks for known vulnerabilities.",
            "5. <b>Testing:</b> Run comprehensive tests after updating dependencies.",
            "6. <b>Audit:</b> Conduct regular security audits of the software supply chain.",
        ]

        for rec in recommendations:
            elements.append(Paragraph(rec, self.styles['Normal']))
            elements.append(Spacer(1, 0.1 * inch))

        elements.append(PageBreak())
        return elements

    def _build_metadata_section(self):
        """Build technical metadata section."""
        elements = []

        elements.append(Paragraph("Technical Details", self.styles['CustomHeading']))
        elements.append(Spacer(1, 0.2 * inch))

        # Grype version and scan info
        grype_meta = self.grype_data.get('metadata', {}) if self.grype_data else {}
        
        metadata_text = f"""
        <b>Scan Timestamp:</b> {datetime.now().isoformat()}<br/>
        <b>Tool:</b> Grype<br/>
        <b>Scan Type:</b> Directory Scan (node_modules)<br/>
        <b>Report Format:</b> PDF<br/>
        """

        if self.sbom_data:
            sbom_meta = self.sbom_data.get('metadata', {})
            metadata_text += f"<b>SBOM Format:</b> SPDX JSON<br/>"

        elements.append(Paragraph(metadata_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.2 * inch))

        # Disclaimer
        elements.append(Paragraph("Disclaimer", self.styles['Heading3']))
        disclaimer_text = """
        This report is generated automatically and should be reviewed by security professionals.
        Vulnerabilities listed may have updates or fixes available. Always verify information
        through official security advisories and CVE databases.
        """
        elements.append(Paragraph(disclaimer_text, self.styles['Normal']))

        return elements

    def generate(self, output_path):
        """Generate the PDF report."""
        print(f"Generating PDF report: {output_path}")

        # Create PDF document
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch
        )

        # Build elements
        elements = []

        # Title page
        elements.extend(self._build_title_page())
        elements.append(PageBreak())

        # Calculate statistics
        stats = self._calculate_statistics()

        # Executive summary
        elements.extend(self._build_executive_summary(stats))

        # Vulnerability details
        elements.extend(self._build_vulnerability_details(stats))

        # Recommendations
        elements.extend(self._build_recommendations())

        # Technical details
        elements.extend(self._build_metadata_section())

        # Build PDF
        try:
            doc.build(elements)
            print(f"✓ PDF report generated successfully: {output_path}")
            return True
        except Exception as e:
            print(f"✗ Error generating PDF: {e}")
            return False


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Generate PDF report from Grype vulnerability scan results'
    )
    parser.add_argument(
        '--input',
        required=True,
        help='Path to Grype JSON output file'
    )
    parser.add_argument(
        '--output',
        required=True,
        help='Path for output PDF file'
    )
    parser.add_argument(
        '--sbom',
        help='Path to SBOM file (optional)'
    )

    args = parser.parse_args()

    # Validate input file exists
    if not Path(args.input).exists():
        print(f"Error: Input file not found: {args.input}")
        sys.exit(1)

    # Generate report
    report = GrypePDFReport(args.input, args.sbom)
    success = report.generate(args.output)

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
