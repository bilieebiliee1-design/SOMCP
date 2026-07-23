import argparse
import datetime
import hashlib
import json
import pathlib
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="build/blutter-matrix")
    parser.add_argument("--runner-id", required=True)
    parser.add_argument("--device", required=True)
    parser.add_argument("--fixture-sha256", required=True)
    parser.add_argument("--result", required=True)
    args = parser.parse_args()
    runner_dir = pathlib.Path(args.root) / "runners" / args.runner_id
    build = json.loads((runner_dir / "build.json").read_text(encoding="utf-8"))
    if build.get("buildStatus") != "passed":
        raise SystemExit("runner build has not passed")
    fixture = args.fixture_sha256.lower()
    if len(fixture) != 64 or any(ch not in "0123456789abcdef" for ch in fixture):
        raise SystemExit("invalid fixture SHA-256")
    result_file = pathlib.Path(args.result)
    result = json.loads(result_file.read_text(encoding="utf-8"))
    required = ["schemaVersion", "summary", "libraries", "classes", "functions", "objects"]
    if result.get("schemaVersion") != 1 or any(key not in result for key in required):
        raise SystemExit("invalid runner smoke result")
    adb = subprocess.run(["adb", "-s", args.device, "shell", "getprop", "ro.product.cpu.abi"], capture_output=True, text=True, check=True)
    if adb.stdout.strip() != "arm64-v8a":
        raise SystemExit("smoke device is not arm64-v8a")
    payload = {
        "smokeStatus": "passed",
        "runnerId": args.runner_id,
        "deviceSerial": args.device,
        "deviceAbi": "arm64-v8a",
        "fixtureSha256": fixture,
        "resultSha256": hashlib.sha256(result_file.read_bytes()).hexdigest(),
        "completedAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    (runner_dir / "smoke.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
