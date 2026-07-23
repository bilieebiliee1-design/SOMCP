import argparse
import concurrent.futures
import hashlib
import json
import pathlib
import subprocess
import sys


def completed(root, runner):
    status_path = root / "runners" / runner["runnerId"] / "build.json"
    binary = root / "runners" / runner["runnerId"] / f"lib{runner['libraryName']}.so"
    if not status_path.is_file() or not binary.is_file():
        return False
    try:
        status = json.loads(status_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return (
        status.get("runnerId") == runner["runnerId"]
        and status.get("libraryName") == runner["libraryName"]
        and status.get("buildStatus") == "passed"
        and status.get("staticStatus") == "passed"
        and hashlib.sha256(binary.read_bytes()).hexdigest() == status.get("sha256")
    )


def build(script, plan, root, ndk, icu, capstone, runner_id):
    command = [sys.executable, str(script), "--plan", str(plan), "--root", str(root), "--runner-id", runner_id, "--android-ndk", ndk, "--icu-root", icu, "--capstone-root", capstone]
    return runner_id, subprocess.run(command).returncode


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", default="build/blutter-matrix/build-plan.json")
    parser.add_argument("--root", default="build/blutter-matrix")
    parser.add_argument("--android-ndk", required=True)
    parser.add_argument("--icu-root", required=True)
    parser.add_argument("--capstone-root", required=True)
    parser.add_argument("--workers", type=int, default=1)
    args = parser.parse_args()
    plan_path = pathlib.Path(args.plan).resolve()
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    script = pathlib.Path(__file__).resolve().parent / "build_runner.py"
    root = pathlib.Path(args.root).resolve()
    pending = [item for item in plan["runners"] if not completed(root, item)]
    skipped = len(plan["runners"]) - len(pending)
    workers = 1 if pending else max(1, args.workers)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(build, script, plan_path, root, args.android_ndk, args.icu_root, args.capstone_root, item["runnerId"]) for item in pending]
        results = [future.result() for future in concurrent.futures.as_completed(futures)]
    failed = [runner_id for runner_id, code in results if code != 0]
    print(json.dumps({"total": len(plan["runners"]), "built": len(results) - len(failed), "skipped": skipped, "failed": failed}, indent=2))
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
