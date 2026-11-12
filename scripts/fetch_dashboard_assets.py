"""Fetch pinned, redistributable map assets. No package install scripts are executed."""

import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen

from intelligence_dashboard import ENTITY_ROWS

EMOJI_REV = "1ffb34c752ecf5d402f04cfb4b392c77f57c54bc"


def download(url):
    with urlopen(Request(url, headers={"User-Agent": "SecurityIntelligence-assets/1.0"}), timeout=30) as response:
        return response.read(5_000_000)


def fetch(output):
    output.mkdir(parents=True, exist_ok=True)
    assets = []
    def save(name, url, license_name):
        payload = download(url)
        if name.endswith(".svg") and (b"<svg" not in payload or b"<script" in payload.lower()):
            raise ValueError("Invalid SVG: " + name)
        if name.endswith(".png") and not payload.startswith(b"\x89PNG\r\n\x1a\n"):
            raise ValueError("Invalid PNG: " + name)
        (output / name).write_bytes(payload)
        assets.append({"file": name, "source": url, "license": license_name,
                       "sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)})
    catalog = json.loads(download("https://raw.githubusercontent.com/devicons/devicon/v2.16.0/devicon.json"))
    for key, *_ in ENTITY_ROWS:
        if key in {"mcp", "vscodemarketplace", "githubactions", "entraid"}:
            continue
        versions = next(row["versions"]["svg"] for row in catalog if row["name"] == key)
        variant = "original" if "original" in versions else "original-wordmark"
        save(key + ".svg", "https://raw.githubusercontent.com/devicons/devicon/v2.16.0/icons/" + key + "/" + key + "-" + variant + ".svg", "Devicon MIT; brand trademarks retained")
    for title in ["Shield", "Laptop", "Locked", "Cloud", "Globe with meridians", "File cabinet", "Toolbox", "Electric plug"]:
        basename = title.lower().replace(" ", "_")
        save(basename + ".png", "https://raw.githubusercontent.com/microsoft/fluentui-emoji/" + EMOJI_REV + "/assets/" + quote(title) + "/3D/" + basename + "_3d.png", "Microsoft Fluent Emoji MIT")
    for name, url in [
        ("DEVICON-LICENSE.txt", "https://raw.githubusercontent.com/devicons/devicon/v2.16.0/LICENSE"),
        ("FLUENT-EMOJI-LICENSE.txt", "https://raw.githubusercontent.com/microsoft/fluentui-emoji/" + EMOJI_REV + "/LICENSE"),
        ("cytoscape-3.33.1.min.js", "https://cdn.jsdelivr.net/npm/cytoscape@3.33.1/dist/cytoscape.min.js"),
        ("CYTOSCAPE-LICENSE.txt", "https://cdn.jsdelivr.net/npm/cytoscape@3.33.1/LICENSE"),
        ("chart-4.4.8.umd.js", "https://cdn.jsdelivr.net/npm/chart.js@4.4.8/dist/chart.umd.js"),
        ("CHART-LICENSE.txt", "https://cdn.jsdelivr.net/npm/chart.js@4.4.8/LICENSE.md"),
    ]:
        save(name, url, "MIT")
    (output / "manifest.json").write_text(json.dumps(assets, indent=2), encoding="utf-8")
    print("Downloaded", len(assets), "assets with licenses and SHA-256 manifest")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    fetch(parser.parse_args().output)
