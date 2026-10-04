# Deep-analysis PDF export

## Scope

The sibling dashboard serves `assets/report-pdf.js` and `assets/report-pdf.css`.
The PDF button is next to the existing reanalysis button. Original tabs, analysis
records and evidence remain unchanged. No backend, API keys, LLM calls or external
document service are required. Nothing is uploaded during export.

PDF generation uses local, lazily loaded pdfmake 0.2.20 (MIT) and Nanum Gothic
Regular/Bold (OFL). Sources and licenses are stored under `dashboard/assets/pdf/`.
First export downloads approximately 5.6 MB of static assets; later exports reuse
loaded fonts and the PDF engine. Browser memory and CPU usage grow with report size.

## Content contract

- Report-specific model allowlists substantive fields. No source/evidence objects,
  raw tool logs, article links, or reference lists are copied into the PDF.
- Explicit source lines and footnote markers are removed from narrative text.
  Technical URLs, full hashes and query/command syntax remain intact.
- Existing uncertainty, failed research, query rejection and missing dynamic
  analysis are retained. Export never performs or claims new analysis.
- Informational articles use review-oriented headings; empty threat appendices are
  omitted. Multi-incident results remain separate.
- Cover, automatic table of contents, dated analysis, body sections, searchable
  Korean text, full indicators, and detection material form the report.
- Validated flow data is redrawn as PDF-native phase diagrams, retaining explicit
  transitions and independent capabilities, without source quotations.
- No Financial Security Institute logo, authorship or institutional identity is used.

## Verification

```powershell
node --test tests/check_report_pdf.cjs
node tests/build_report_pdf_browser_check.cjs
# Serve sibling dashboard on http://127.0.0.1:8086, then use Playwright CLI:
npx --yes --package @playwright/cli playwright-cli -s=report-pdf open http://127.0.0.1:8086/
npx --yes --package @playwright/cli playwright-cli -s=report-pdf run-code --filename tmp/pdfs/browser-check.js
npx --yes --package @playwright/cli playwright-cli -s=report-pdf run-code --filename tests/report_pdf_states_browser.js
npx --yes --package @playwright/cli playwright-cli -s=report-pdf run-code --filename tests/report_pdf_long_browser.js
python tests/check_report_pdf_output.py
```

Browser fixtures intercept the production insights API. Generated example contains
explicitly labelled test data, not new intelligence findings. Inspect PDFs with
Poppler and pypdf; screenshots alone cannot verify text completeness. Check font
retry, disabled pending/failed exports, duplicate clicks, article switching, and
320/390/768/1440 px layouts. No production record is changed by these tests.
