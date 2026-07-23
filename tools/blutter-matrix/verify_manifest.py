import argparse
import hashlib
import json
import pathlib
import re
import sys


LIBRARY = re.compile(r"^blutter_[A-Za-z0-9_]+$")
DIGEST = re.compile(r"^[a-f0-9]{64}$")
REVISION = re.compile(r"^[a-f0-9]{40}$")


def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default="app/src/main/assets/blutter/runners.json")
    parser.add_argument("--jni-root", default="app/src/main/jniLibs")
    parser.add_argument("--allow-empty", action="store_true")
    args = parser.parse_args()
    manifest = json.loads(pathlib.Path(args.manifest).read_text(encoding="utf-8"))
    if manifest.get("schemaVersion") != 2:
        fail("runner manifest schemaVersion must be 2")
    runners = manifest.get("runners")
    if not isinstance(runners, list) or (not runners and not args.allow_empty):
        fail("runner manifest must contain verified runners")
    seen_ids = set()
    seen_libraries = set()
    for runner in runners:
        runner_id = runner.get("runnerId")
        library = runner.get("libraryName")
        digest = runner.get("sha256")
        if not runner_id or runner_id in seen_ids:
            fail("runnerId is missing or duplicated")
        if not isinstance(library, str) or not LIBRARY.fullmatch(library) or library in seen_libraries:
            fail(f"invalid or duplicated libraryName for {runner_id}")
        if runner.get("abi") != "arm64-v8a":
            fail(f"unsupported ABI for {runner_id}")
        if runner.get("buildStatus") != "passed" or runner.get("staticStatus") != "passed":
            fail(f"runner build/static verification failed for {runner_id}")
        if runner.get("smokeStatus") not in ("not_run", "passed"):
            fail(f"runner smoke verification failed for {runner_id}")
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            fail(f"invalid SHA-256 for {runner_id}")
        if not REVISION.fullmatch(runner.get("dartRevision", "")):
            fail(f"invalid Dart revision for {runner_id}")
        if not runner.get("snapshotAliases"):
            fail(f"missing snapshot aliases for {runner_id}")
        if runner.get("protocolVersion", 1) != 1:
            fail(f"unsupported runner protocol for {runner_id}")
        if runner.get("upstreamCommit") and runner["upstreamCommit"] != "528acbe83ba35a3a53fb97b231cb5f968c7068d1":
            fail(f"unexpected Blutter commit for {runner_id}")
        if "blutter_run_fd" not in runner.get("exports", ["blutter_run_fd"]):
            fail(f"runner export missing for {runner_id}")
        binary = pathlib.Path(args.jni_root) / "arm64-v8a" / f"lib{library}.so"
        if not binary.is_file():
            fail(f"missing runner binary {binary}")
        actual = hashlib.sha256(binary.read_bytes()).hexdigest()
        if actual != digest:
            fail(f"SHA-256 mismatch for {runner_id}")
        seen_ids.add(runner_id)
        seen_libraries.add(library)
    print(f"verified {len(runners)} runner(s)")


if __name__ == "__main__":
    main()
