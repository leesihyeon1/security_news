# Article Flow Diagrams

The base analysis requests a `[흐름도 데이터]` JSON section before `[조사 대상]`.
This shares the existing model call; there is no image API or extra model request.
It adds input/output tokens to that call. The machine section is removed before
displaying, deciding, or investigating the article.

`scripts/analysis_flow.py` checks article eligibility, verbatim source excerpts
for each node and edge, field bounds, unique identifiers, connectedness, phase
order and cycles. Capabilities must be terminal branches, not sequential events.
Quote matching checks provenance, not semantic entailment or independent truth.
The diagram and evidence drawer therefore explicitly identify the article basis.

Policy, product/event, general and multi-incident articles are excluded. A
technical informational article may supply an architecture graph; vulnerability
articles may supply an exploitation-mechanism graph. Incomplete, unsupported or
ungrounded output records a skip reason without breaking the normal report.
No graph is fabricated from numbered paragraphs in old analyses.

The worker stores `analysis_flow` in the insight record and analysis cache.
The sibling dashboard renders this versioned data as SVG with local Lucide icons
(vendored 0.468.0 distribution, retaining its license header). Text is escaped;
model-authored HTML, SVG, JavaScript and image URLs are never executed. Download
uses browser SVG/Canvas to produce SVG or 2x PNG, without contacting an image API.

The existing four report tabs are unchanged. The diagram is a full-width section
in the analysis tab, with expansion, downloads, and collapsed source evidence.
Legacy records remain unchanged until explicitly reanalyzed. No automatic batch
regeneration, remote write, or deployment is part of this change.

## Offline Verification

- `python -m pytest tests/test_analysis_flow.py tests/test_analysis_grounding.py tests/test_analysis_targets.py tests/test_informational_briefing.py -q`
- `node tests/check_analysis_flow_ui.cjs`
- `node tests/build_analysis_flow_preview.cjs`

The last command produces `output/analysis-flow-preview.html` using the user's
provided ten-step ClickFix example. Its source URL is deliberately an example
domain, not a claim that the article was fetched or independently verified.
The generated file is self-contained and is not published with the dashboard.

Browser checks: open the generated preview, then run
`playwright-cli run-code --filename tests/analysis_flow_browser_checks.js`.
The integration check expects the dashboard at `http://127.0.0.1:8086/`, mocks
all production API calls, and exercises desktop/mobile, text bounds, tab
isolation, dialog focus, dark theme, and both downloads.
