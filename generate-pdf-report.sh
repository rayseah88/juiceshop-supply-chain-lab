#!/bin/bash
# Generate PDF report from Grype scan results

set -e

echo "=== Grype PDF Report Generation ==="
echo ""

# Check if Python script exists
if [ ! -f "scripts/grype-to-pdf.py" ]; then
    echo "❌ Error: scripts/grype-to-pdf.py not found"
    exit 1
fi

# Check if Grype results exist
if [ ! -f "grype-results.json" ]; then
    echo "❌ Error: grype-results.json not found"
    exit 1
fi

echo "✓ Found grype-results.json"
echo "✓ Found scripts/grype-to-pdf.py"
echo ""

# Install dependencies
echo "Installing Python dependencies..."
pip install -q reportlab pyyaml

# Generate PDF report
echo "Generating PDF report..."
python scripts/grype-to-pdf.py \
    --input grype-results.json \
    --output grype-vulnerability-report.pdf

# Verify output
if [ -f "grype-vulnerability-report.pdf" ]; then
    echo ""
    echo "✓ PDF Report Generated Successfully!"
    echo ""
    ls -lh grype-vulnerability-report.pdf
    echo ""
    echo "Report Details:"
    file grype-vulnerability-report.pdf
    echo ""
    echo "Available for download at:"
    echo "  → https://github.com/rayseah88/juiceshop-supply-chain-lab/blob/master/grype-vulnerability-report.pdf"
else
    echo "❌ Error: PDF generation failed"
    exit 1
fi
