import argparse
import datetime
import hashlib
import json
import pathlib
import re
import urllib.request


def load_json(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def fetch_json(url):
    request = urllib.request.Request(url, headers={"User-Agent": "SOMCP-Blutter-Matrix/1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def version_tuple(value):
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", value or "")
    return tuple(map(int, match.groups())) if match else None


def analysis_mode(dart_version, config):
    value = version_tuple(dart_version)
    analysis = version_tuple(config["analysisMinimumDart"])
    legacy = version_tuple(config["legacyNoAnalysisMinimumDart"])
    if value is None:
        return "unresolved"
    if value >= analysis:
        return "analysis"
    if value >= legacy:
        return "no_analysis"
    return "unsupported"


def release_rows(archive, config):
    channels = set(config["channels"])
    rows = []
    for release in archive.get("releases", []):
        if release.get("channel") not in channels:
            continue
        dart_version = release.get("dart_sdk_version")
        rows.append({
            "flutterVersion": release.get("version"),
            "channel": release.get("channel"),
            "frameworkRevision": release.get("hash"),
            "dartVersion": dart_version,
            "archive": release.get("archive"),
            "archiveSha256": release.get("sha256"),
            "analysisMode": analysis_mode(dart_version, config),
            "status": "indexed",
            "reason": None,
        })
    rows.sort(key=lambda item: version_tuple(item.get("flutterVersion")) or (0, 0, 0))
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="tools/blutter-matrix/matrix-config.json")
    parser.add_argument("--archive")
    parser.add_argument("--output", default="build/blutter-matrix/index.json")
    args = parser.parse_args()
    config = load_json(args.config)
    archive = load_json(args.archive) if args.archive else fetch_json(config["flutterArchiveUrl"])
    rows = release_rows(archive, config)
    payload = {
        "schemaVersion": 1,
        "matrixVersion": config["matrixVersion"],
        "generatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "blutterCommit": config["blutterCommit"],
        "targetAbi": config["targetAbi"],
        "sourceSha256": hashlib.sha256(json.dumps(archive, sort_keys=True).encode()).hexdigest(),
        "releases": rows,
    }
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
