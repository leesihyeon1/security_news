# Project workflow

This repository owns collection, classification, Korean AI reports, and dashboard
JSON generation. The sibling `boannews_vercel_deploy` owns the static dashboard
and the separate `click-tracker` API. Keep both paths explicit when working across
repositories. Never assume a successful push proves the dashboard renders.

## Select skills by task

Skills are installed under the user's Codex skills directory. Load only relevant
SKILL.md files and references, not the whole collection.

| Change | Skill and scope |
| --- | --- |
| Python parsing, aggregation, retries, or test failures | `python-testing-patterns`; focused tests with mocked time/network |
| AI prompt, model, Korean output, or summary quality | `llm-evaluation`; start with saved outputs and the offline checker below |
| Dashboard interactions or responsive layout | `playwright`; exercise the changed flow at desktop/mobile sizes |
| UI design or accessibility review | `web-design-guidelines`; apply to changed UI files |
| Requested security review or substantive security boundary change | `security-best-practices`; relevant Python/JS references only |
| Requested Vercel deployment | `vercel-deploy`; preserve the existing Git-linked projects and root directories |

Small copy/config edits need no specialist skill unless the behavior warrants it.
Do not run every skill or the entire test suite for every edit. Escalate checking
when shared behavior changes or focused checks reveal a problem. Report existing
test failures; do not silently exclude them or call an excluded suite fully green.

## Low-cost validation

- Run `python scripts/check_dashboard_quality.py --repo ../boannews_vercel_deploy`
  for generated data or summary changes. It is read-only, uses the standard
  library, makes no model/network calls, and exits nonzero on errors.
- Use the project's actual Python interpreter if `python` is not on PATH.
- For AI changes, begin with saved representative outputs. Live model comparisons
  are for requested regeneration/evaluation or when offline evidence is insufficient;
  start with a small sample and do not launch unbounded retries or sweeps.
- Preserve `[총평]`, `[핵심 위협 TOP 3]`, `[권고 조치]` and Korean explanatory
  prose; proper names and CVE identifiers may remain in their original form.
- Old narratives must not be assigned to a new reporting period without checking
  their source period. Header/language checks do not prove factual correctness.
- Public exports omit internal asset ownership and PIR context. Review prose as
  well as structured fields. Do not dump credentials or full internal events.
- Production deploys must be within the user's request. Keep preview work linked
  to the correct project; do not create a replacement site or use a claim deployment
  for this existing production dashboard. Check the dashboard's deployment status
  separately from click-tracker. State any unverified live-browser result.
- On Windows, use the installed Node/Python tools. Shell wrappers from skills may
  need Git Bash; do not assume Bash or install global dependencies unnecessarily.
