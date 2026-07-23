import argparse
import hashlib
import json
import pathlib
import re


def slug(value):
    return re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").lower()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="build/blutter-matrix/resolved.json")
    parser.add_argument("--output", default="build/blutter-matrix/build-plan.json")
    args = parser.parse_args()
    matrix = json.loads(pathlib.Path(args.input).read_text(encoding="utf-8"))
    unique = {}
    coverage = []
    for release in matrix["releases"]:
        item = dict(release)
        dart_revision = item.get("dartRevision")
        snapshot_hash = item.get("snapshotHash")
        mode = item.get("analysisMode")
        if not dart_revision or not snapshot_hash or mode in ("unresolved", "unsupported"):
            item["supported"] = False
            item["reason"] = item.get("reason") or ("snapshot_hash_unavailable" if dart_revision and not snapshot_hash else "dart_version_unsupported")
            coverage.append(item)
            continue
        analysis = mode == "analysis"
        pointer_modes = [item["compressedPointers"]] if item.get("compressedPointers") is not None else [False, True]
        keys = []
        for compressed in pointer_modes:
            variant_analysis = analysis and compressed
            raw_key = f"{dart_revision}|{compressed}|{variant_analysis}|{matrix['blutterCommit']}"
            key = hashlib.sha256(raw_key.encode()).hexdigest()[:20]
            keys.append(key)
            runner_id = f"dart-{slug(item.get('dartVersion') or dart_revision[:12])}-{key}"
            unique.setdefault(key, {
                "compatibilityKey": key,
                "runnerId": runner_id,
                "libraryName": f"blutter_{key}",
                "dartVersion": item.get("dartVersion"),
                "dartRevision": dart_revision,
                "snapshotAliases": [snapshot_hash],
                "abi": matrix["targetAbi"],
                "compressedPointers": compressed,
                "analysis": variant_analysis,
                "blutterCommit": matrix["blutterCommit"],
                "engineRevisions": [],
                "flutterVersions": [],
                "status": "source_resolvable",
            })
            runner = unique[key]
            if item.get("engineRevision") not in runner["engineRevisions"]:
                runner["engineRevisions"].append(item.get("engineRevision"))
            runner["flutterVersions"].append(item.get("flutterVersion"))
            if snapshot_hash not in runner["snapshotAliases"]:
                runner["snapshotAliases"].append(snapshot_hash)
        item["compatibilityKeys"] = keys
        item["supported"] = False
        item["reason"] = "runner_not_built"
        coverage.append(item)
    payload = {
        "schemaVersion": 1,
        "matrixVersion": matrix["matrixVersion"],
        "blutterCommit": matrix["blutterCommit"],
        "targetAbi": matrix["targetAbi"],
        "runners": sorted(unique.values(), key=lambda item: item["runnerId"]),
        "coverage": coverage,
    }
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
