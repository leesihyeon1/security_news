"""Offline regression checks for deep-analysis records.

The evaluator never calls an LLM or an external intelligence service. It is used
with saved records or synthetic fixtures before changing prompts or routing.
"""

import json
import sys


def _text(record):
    return json.dumps(record or {}, ensure_ascii=False).lower()


def evaluate(record, *, required=(), forbidden_blocklist=(), informational=False,
             require_unverified_pattern=False):
    text = _text(record)
    checks = []
    for value in required:
        value = str(value)
        checks.append({"name": "required:" + value, "passed": value.lower() in text})
    blocklists = ((record or {}).get("investigation") or {}).get("response", {}).get("blocklists") or []
    blocked = {str(value).lower() for row in blocklists for value in row.get("values") or []}
    for value in forbidden_blocklist:
        checks.append({"name": "not_blocklisted:" + str(value),
                       "passed": str(value).lower() not in blocked})
    if informational:
        investigation = (record or {}).get("investigation") or {}
        route = investigation.get("route") or {}
        response = investigation.get("response") or {}
        checks.extend([
            {"name": "informational_route", "passed": route.get("primary") in ("", None)},
            {"name": "informational_no_kql", "passed": not response.get("kql")},
            {"name": "informational_no_blocklists", "passed": not blocklists},
        ])
    if require_unverified_pattern:
        patterns = ((record or {}).get("investigation") or {}).get("patterns") or []
        checks.append({"name": "pattern_scope_marked",
                       "passed": any(p.get("validation_status") == "candidate" or
                                     p.get("unverified") for p in patterns)})
    passed = sum(1 for item in checks if item["passed"])
    return {"passed": passed == len(checks) if checks else True,
            "score": passed / len(checks) if checks else 1.0,
            "checks": checks}


def evaluate_many(cases):
    results = [evaluate(item.get("record"), **(item.get("expect") or {}))
               for item in cases or []]
    return {"cases": len(results), "passed": sum(1 for item in results if item["passed"]),
            "results": results}


def main(argv=None):
    path = (argv or sys.argv[1:])[0]
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    print(json.dumps(evaluate_many(payload), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
