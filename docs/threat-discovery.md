# AI Discovery

`scripts/threat_discovery.py` finds emerging threats in the collected articles and
publishes `dashboard/data/threat-discovery.json` for the dashboard's AI Discovery tab.

## Pipeline

| Step | Who | What |
| --- | --- | --- |
| 1 탐색 | code | Every detector runs over the last 7 days: spikes in threat actors, malware and products against the previous 4 weeks, and actively exploited CVEs reported by several outlets. Signals that share most of their articles are merged into one candidate. |
| 2 가설 | model | States what is happening as claims, each citing evidence articles. A claim without a valid citation is discarded. |
| 3 검토 | model | A separate skeptical pass judges every claim (yes / partial / no), whether the articles describe one event, and whether it is new or escalating. |
| 4 확정 | model | Writes the verdict, summary, who is affected, actions and detection points from the surviving claims only. |
| 5 검증 | code | Rules the model cannot override: reviewer rejection, mixed events, retrospective or promotional topics, too few supported claims, fewer than three outlets, and any CVE not present in the evidence (that text is dropped). |

Verdicts: `confirmed`, `watch`, `rejected`, or `unreviewed` when the model was unavailable
(numbers only). Rejected candidates stay in the output so the page can show why.

## Inputs and privacy

Only public article fields are sent to the model: source, date, title and the public summary.
Triage levels, importance scores, matched assets and PIRs are never read.

## Running

`tasks\daily_report.bat` runs `threat_discovery.py --push` last. Results are cached per
candidate (the set of evidence articles), so only new or changed candidates call the model:
three calls each, at most 12 candidates. With the current NVIDIA model a call takes about
40-110 seconds.

```powershell
python scripts\threat_discovery.py --no-model --output preview.json   # statistics only
python scripts\threat_discovery.py --output preview.json              # with the model, no push
```

Detection thresholds are constants at the top of the script (`MIN_ARTICLES`, `MIN_SOURCES`,
`SPIKE_RATIO`, `MAX_CANDIDATES`). Model text is an analysis, not a fact: the page always shows
the evidence articles and the review trail next to it.
