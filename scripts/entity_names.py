"""Conservative entity aliases shared by report and trending aggregation."""

import re
from collections import Counter
from common_utils import normalize_threat_actor

ALIASES = {
    "chosen brick": "Chosen Brick",
    "clop": "Clop",
    "clop ransomware": "Clop",
    "cisco identity services engine": "Cisco Identity Services Engine",
    "cisco identity services engine (ise)": "Cisco Identity Services Engine",
    "waterplum": "WaterPlum",
    "waterplum (contagious interview)": "WaterPlum",
}


def canonical_name(value):
    value = re.sub(r"\s+", " ", value.strip())
    if re.fullmatch(r"WaterPlum\s*\(.*\)", value, re.I):
        return "WaterPlum"
    return ALIASES.get(value.casefold(), value)


def entity_names(value):
    # Parentheses can contain alias lists; do not count aliases as separate actors.
    parts, start, depth = [], 0, 0
    for index, char in enumerate(value or ""):
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        elif char in ",;" and depth == 0:
            parts.append(value[start:index])
            start = index + 1
    parts.append((value or "")[start:])
    return [canonical_name(part) for part in parts if part.strip()]


def count_entities(events, field):
    counts, labels = Counter(), {}
    for event in events:
        names = entity_names(event.get(field) or "")
        if field == "threat_actor":
            names = [normalize_threat_actor(name) for name in names]
        for name in names:
            labels.setdefault(name.casefold(), name)
        counts.update({name.casefold() for name in names})
    return Counter({labels[key]: count for key, count in counts.items()})
