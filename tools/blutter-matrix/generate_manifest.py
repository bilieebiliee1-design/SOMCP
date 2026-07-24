import argparse
import datetime
import json
import pathlib
import shutil


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", default="build/blutter-matrix/build-plan.json")
    parser.add_argument("--root", default="build/blutter-matrix")
    parser.add_argument("--manifest", default="app/src/main/assets/blutter/runners.json")
    parser.add_argument("--jni-root", default="app/src/main/jniLibs")
    args = parser.parse_args()
    plan = json.loads(pathlib.Path(args.plan).read_text(encoding="utf-8"))
    root = pathlib.Path(args.root)
    native_directory = pathlib.Path(args.jni_root) / "arm64-v8a"
    native_directory.mkdir(parents=True, exist_ok=True)
    for stale in native_directory.glob("libblutter_*.so"):
        stale.unlink()
    runners = []
    for candidate in plan["runners"]:
        status_file = root / "runners" / candidate["runnerId"] / "build.json"
        smoke_file = root / "runners" / candidate["runnerId"] / "smoke.json"
        if not status_file.is_file():
            continue
        status = json.loads(status_file.read_text(encoding="utf-8"))
        smoke = json.loads(smoke_file.read_text(encoding="utf-8")) if smoke_file.is_file() else {"smokeStatus": "not_run"}
        if status.get("buildStatus") != "passed" or status.get("staticStatus") != "passed" or smoke.get("smokeStatus") == "failed":
            continue
        runner = dict(candidate)
        runner.update({"sha256": status["sha256"], "buildStatus": "passed", "staticStatus": "passed", "smokeStatus": smoke.get("smokeStatus", "not_run"), "protocolVersion": 1, "upstreamCommit": plan["blutterCommit"], "exports": ["blutter_run_fd"]})
        runner["engineRevision"] = runner.get("engineRevisions", [None])[0]
        binary = root / "runners" / candidate["runnerId"] / f"lib{candidate['libraryName']}.so"
        destination = native_directory / binary.name
        shutil.copy2(binary, destination)
        runners.append(runner)
    coverage = []
    supported_keys = {item["compatibilityKey"] for item in runners}
    for item in plan["coverage"]:
        row = dict(item)
        matched = [key for key in row.get("compatibilityKeys", []) if key in supported_keys]
        row["supported"] = bool(matched)
        row["reason"] = None if matched else row.get("reason", "runner_not_static_verified")
        coverage.append(row)
    manifest = {"schemaVersion": 2, "matrixVersion": plan["matrixVersion"], "protocolVersion": 1, "upstreamCommit": plan["blutterCommit"], "generatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"), "targetAbi": plan["targetAbi"], "runners": runners, "coverage": coverage}
    pathlib.Path(args.manifest).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
