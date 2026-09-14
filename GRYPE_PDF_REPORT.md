# Grype PDF Report Generator - Documentation

## Overview

This repository includes an automated system to generate professional PDF vulnerability reports from Grype supply chain security scans. The PDF reports provide comprehensive analysis of dependencies, vulnerabilities, and remediation recommendations.

## Files Included

### 1. **scripts/grype-to-pdf.py**
Python script that converts Grype JSON scan results into professional PDF reports.

**Features:**
- Reads Grype JSON output
- Generates multi-page PDF with:
  - Executive summary with statistics
  - Vulnerability breakdown by severity
  - Detailed vulnerability listings
  - Risk assessment matrix
  - Actionable recommendations
  - Technical metadata

**Dependencies:**
- `reportlab` - PDF generation
- `pyyaml` - YAML parsing

**Usage:**
```bash
python scripts/grype-to-pdf.py \
    --input grype-results.json \
    --output grype-vulnerability-report.pdf \
    --sbom juiceshop.sbom.spdx.json
```

### 2. **.github/workflows/supply-chain.yml**
GitHub Actions workflow for automated supply chain security scanning.

**Workflow Steps:**
1. Checkout repository code
2. Setup Node.js environment (v22)
3. Setup Python environment (v3.11)
4. Install NPM dependencies
5. Install Syft and Grype CLIs
6. Generate SBOM (Software Bill of Materials) in SPDX format
7. Run Grype vulnerability scans in multiple formats:
   - JSON (machine-readable)
   - Table (human-readable)
   - SARIF (GitHub Security integration)
8. Generate PDF report using the Python script
9. Upload all artifacts (SBOM, JSON, text, PDF, SARIF)
10. Upload SARIF results to GitHub Security tab
11. Display summary in workflow logs

**Artifacts Generated:**
- `grype-vulnerability-report.pdf` - Professional PDF report (30-day retention)
- `grype-results-json` - Raw JSON scan results (30-day retention)
- `grype-results-text` - Human-readable text format (30-day retention)
- `juiceshop-sbom-spdx` - SBOM in SPDX JSON format (30-day retention)

### 3. **generate-pdf-report.sh**
Bash script for local PDF report generation.

**Usage:**
```bash
chmod +x generate-pdf-report.sh
./generate-pdf-report.sh
```

**Requirements:**
- Python 3.6+
- pip (Python package manager)
- grype-results.json file
- scripts/grype-to-pdf.py script

## Quick Start

### Local Generation
```bash
# 1. Run Grype scan
grype dir:./node_modules -o json > grype-results.json

# 2. Generate PDF
python scripts/grype-to-pdf.py \
    --input grype-results.json \
    --output grype-vulnerability-report.pdf

# 3. View the PDF
open grype-vulnerability-report.pdf  # macOS
xdg-open grype-vulnerability-report.pdf  # Linux
start grype-vulnerability-report.pdf  # Windows
```

### Automated (GitHub Actions)
1. Push changes to `master` or `main` branch
2. Workflow automatically triggers
3. Download artifacts from Actions tab:
   - Navigate to the workflow run
   - Scroll to "Artifacts" section
   - Download `grype-vulnerability-report`

## PDF Report Contents

### Page 1: Title Page
- Report title: "Grype Vulnerability Report"
- Report subtitle: "Supply Chain Security Assessment"
- Generation timestamp
- Repository information
- Scan tool information

### Page 2: Executive Summary
- **Total Vulnerabilities:** Count by severity level
- **Affected Packages:** Number of packages with vulnerabilities
- **Scan Date:** When the scan was performed
- **Severity Breakdown Table:**
  - Critical
  - High
  - Medium
  - Low
  - Negligible
  - Unknown

### Page 3+: Detailed Vulnerability Report
- **Vulnerability Table** with columns:
  - ID (CVE identifier)
  - Package name
  - Severity level
  - Description (truncated to 80 chars)
- Color-coded severity indicators
- Sortable by severity (Critical → Unknown)
- Limited to first 50 vulnerabilities on main table
- Note if more vulnerabilities exist

### Final Pages: Recommendations & Technical Details

#### Recommendations Section:
1. **Immediate Action:** Address Critical and High severity vulnerabilities
2. **Dependency Updates:** Keep dependencies current with security patches
3. **Monitoring:** Implement continuous vulnerability scanning
4. **Documentation:** Document accepted risks for known vulnerabilities
5. **Testing:** Run comprehensive tests after updates
6. **Audit:** Conduct regular supply chain security audits

#### Technical Details Section:
- Scan timestamp (ISO 8601 format)
- Tool information (Grype version)
- Scan type (Directory scan of node_modules)
- Report format (PDF)
- SBOM format (if included)
- Disclaimer about automated generation

## Vulnerability Severity Levels

| Severity | CVSS Score | Color | Description |
|----------|-----------|-------|-------------|
| **Critical** | 9.0-10.0 | 🔴 Red | Requires immediate action |
| **High** | 7.0-8.9 | 🟠 Orange | Address within 1-2 weeks |
| **Medium** | 4.0-6.9 | 🟡 Yellow | Address within 1 month |
| **Low** | 0.1-3.9 | 🟢 Green | Address in regular updates |
| **Negligible** | 0.0 | ⚪ Gray | Minimal impact |

## Integration with GitHub Security

The workflow uploads SARIF results to GitHub's Code Scanning feature:

1. **Automatic Upload:** SARIF files auto-upload on each workflow run
2. **Security Tab:** Vulnerabilities appear in repository's Security tab
3. **Branch Protection:** Can block PRs if critical vulnerabilities found
4. **Alerts:** Receive notifications for new vulnerabilities

**Access Security Findings:**
- Navigate to repository → Security tab → Code scanning alerts
- Filter by tool: "Grype"
- View detailed vulnerability information
- Dismiss or reopen findings

## Workflow Triggers

The supply chain security workflow runs automatically on:

- **Push events** to `main` or `master` branches
- **Manual trigger** via workflow_dispatch
- **Scheduled** (optional - can be configured)

## Environment Variables & Secrets

No secrets required for basic Grype scanning. Optional configurations:

- `GRYPE_DB_CACHE_DIR` - Custom database cache location
- `GRYPE_CHECK_FOR_APP_UPDATE` - Disable version checks

## Performance & Resource Usage

- **Scan Duration:** 2-5 minutes for typical Node.js projects
- **CPU:** Single core utilization
- **Memory:** ~512 MB
- **Network:** Required for downloading Grype/Syft databases (~100 MB)
- **Disk Space:** ~500 MB for databases and node_modules scan

## Troubleshooting

### Issue: "reportlab not found"
**Solution:**
```bash
pip install reportlab pyyaml
```

### Issue: "grype-results.json not found"
**Solution:** Ensure Grype scan completed successfully:
```bash
grype dir:./node_modules -o json > grype-results.json
```

### Issue: PDF generation fails silently
**Solution:** Check permissions and disk space:
```bash
chmod +x generate-pdf-report.sh
ls -lh grype-results.json
df -h
```

### Issue: Workflow fails to upload artifacts
**Solution:** Ensure workflow has write permissions to repository.

## Best Practices

1. **Regular Scans:** Run scans on every commit
2. **Monitor Trends:** Track vulnerability counts over time
3. **Version Control:** Store SBOM files in version control
4. **Documentation:** Keep remediation records
5. **Escalation:** Alert security team for critical vulnerabilities
6. **Testing:** Test updates before production deployment
7. **Retention:** Archive reports for compliance

## Security Considerations

- SBOM files contain dependency information - treat as sensitive
- PDF reports should be shared only with authorized personnel
- GitHub Security tab access should be restricted appropriately
- Database downloads come from official Anchore repositories
- Validate Grype/Syft checksums for production environments

## References

- [Grype Documentation](https://github.com/anchore/grype)
- [Syft Documentation](https://github.com/anchore/syft)
- [SPDX Specification](https://spdx.dev/)
- [SARIF Format](https://sarifweb.azurewebsites.net/)
- [CVSS Scoring](https://www.first.org/cvss/)

## Example Report Output

Sample PDF reports are generated with:
- **Repository:** rayseah88/juiceshop-supply-chain-lab
- **Last Updated:** 2026-09-14
- **Artifact Location:** GitHub Actions → Supply Chain Security workflow

## Contributing

To improve the PDF report generator:

1. Fork the repository
2. Modify `scripts/grype-to-pdf.py`
3. Test with `generate-pdf-report.sh`
4. Submit pull request with improvements

## License

This supply chain security workflow is part of the OWASP Juice Shop project.

---

**Generated:** 2026-09-14  
**Last Updated:** 2026-09-14  
**Status:** ✅ Production Ready
