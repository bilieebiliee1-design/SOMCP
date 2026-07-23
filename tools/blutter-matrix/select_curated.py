import argparse
import json
import pathlib


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", default="build/blutter-matrix/build-plan-full.json")
    parser.add_argument("--config", default="tools/blutter-matrix/curated-versions.json")
    parser.add_argument("--output", default="build/blutter-matrix/build-plan-curated.json")
    args = parser.parse_args()
    plan = json.loads(pathlib.Path(args.plan).read_text(encoding="utf-8"))
    config = json.loads(pathlib.Path(args.config).read_text(encoding="utf-8"))
    versions = set(config["dartVersions"])
    runners = [
        runner for runner in plan["runners"]
        if runner.get("dartVersion") in versions
        and runner.get("compressedPointers") is config["compressedPointers"]
        and runner.get("analysis") is config["analysis"]
    ]
    found = {runner["dartVersion"] for runner in runners}
    missing = sorted(versions - found)
    if missing:
        raise SystemExit(f"curated Dart versions missing from plan: {', '.join(missing)}")
    keys = {runner["compatibilityKey"] for runner in runners}
    coverage = []
    for candidate in plan["coverage"]:
        item = dict(candidate)
        matched = [key for key in item.get("compatibilityKeys", []) if key in keys]
        item["compatibilityKeys"] = matched
        item["supported"] = bool(matched)
        item["reason"] = None if matched else "runner_not_curated"
        coverage.append(item)
    payload = dict(plan)
    payload["runners"] = sorted(runners, key=lambda item: item["dartVersion"])
    payload["coverage"] = coverage
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
