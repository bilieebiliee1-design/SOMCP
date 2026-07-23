import argparse
import ast
import concurrent.futures
import hashlib
import json
import pathlib
import re
import time
import urllib.error
import urllib.request


REVISION = re.compile(r"^[a-f0-9]{40}$")
SNAPSHOT_FILES = (
    "app_snapshot.cc",
    "app_snapshot.h",
    "dart.cc",
    "dart_api_impl.cc",
    "datastream.h",
    "image_snapshot.cc",
    "image_snapshot.h",
    "object.cc",
    "object.h",
    "raw_object.cc",
    "raw_object.h",
    "snapshot.cc",
    "snapshot.h",
    "symbols.cc",
    "symbols.h",
)


def fetch_bytes(url, attempts=4):
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "SOMCP-Blutter-Matrix/1"})
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read()
        except (urllib.error.URLError, TimeoutError):
            if attempt + 1 == attempts:
                raise
            time.sleep(2 ** attempt)


def fetch_text(url, attempts=4):
    return fetch_bytes(url, attempts).decode("utf-8").strip()


def snapshot_files(script):
    tree = ast.parse(script)
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "VM_SNAPSHOT_FILES" for target in node.targets):
            value = ast.literal_eval(node.value)
            if isinstance(value, (list, tuple)) and value and all(isinstance(item, str) for item in value):
                return tuple(value)
    raise ValueError("VM_SNAPSHOT_FILES not found")


def resolve_framework(revision, cache):
    cached = cache / "framework" / f"{revision}.json"
    if cached.is_file():
        value = json.loads(cached.read_text(encoding="utf-8"))
        if value.get("engineRevision"):
            return value
    url = f"https://raw.githubusercontent.com/flutter/flutter/{revision}/bin/internal/engine.version"
    try:
        engine = fetch_text(url)
        if not REVISION.fullmatch(engine):
            raise ValueError("invalid engine revision")
        result = {"engineRevision": engine, "status": "source_resolvable", "reason": None}
    except Exception as error:
        result = {"engineRevision": None, "status": "indexed", "reason": f"engine_revision_unavailable:{type(error).__name__}"}
    cached.parent.mkdir(parents=True, exist_ok=True)
    cached.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
    return result


def resolve_engine(engine_revision, framework_revision, cache):
    cached = cache / "engine" / f"{engine_revision}-{framework_revision}.json"
    if cached.is_file():
        value = json.loads(cached.read_text(encoding="utf-8"))
        if value.get("dartRevision"):
            return value
    urls = [
        f"https://raw.githubusercontent.com/flutter/engine/{engine_revision}/DEPS",
        f"https://raw.githubusercontent.com/flutter/flutter/{framework_revision}/DEPS",
    ]
    result = None
    last_error = None
    for url in urls:
        try:
            deps = fetch_text(url)
            match = re.search(r"['\"]dart_revision['\"]\s*:\s*['\"]([a-f0-9]{40})['\"]", deps)
            if match is None:
                raise ValueError("dart revision not found")
            result = {"dartRevision": match.group(1), "dartRevisionSource": url, "reason": None}
            break
        except Exception as error:
            last_error = error
    if result is None:
        result = {"dartRevision": None, "dartRevisionSource": None, "reason": f"dart_revision_unavailable:{type(last_error).__name__}"}
    cached.parent.mkdir(parents=True, exist_ok=True)
    cached.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
    return result


def resolve_snapshot(dart_revision, cache):
    cached = cache / "dart" / f"{dart_revision}.json"
    if cached.is_file():
        value = json.loads(cached.read_text(encoding="utf-8"))
        if value.get("snapshotHash"):
            return value
    digest = hashlib.md5()
    try:
        repository = f"https://raw.githubusercontent.com/dart-lang/sdk/{dart_revision}"
        files = snapshot_files(fetch_text(f"{repository}/tools/make_version.py"))
        base = f"{repository}/runtime/vm"
        for name in files:
            digest.update(fetch_bytes(f"{base}/{name}"))
        result = {"snapshotHash": digest.hexdigest(), "snapshotHashSource": "dart_make_version", "snapshotHashReason": None}
    except Exception as error:
        result = {"snapshotHash": None, "snapshotHashSource": None, "snapshotHashReason": f"snapshot_hash_unavailable:{type(error).__name__}"}
    cached.parent.mkdir(parents=True, exist_ok=True)
    cached.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="build/blutter-matrix/index.json")
    parser.add_argument("--output", default="build/blutter-matrix/resolved.json")
    parser.add_argument("--cache", default="build/blutter-matrix/cache")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    matrix = json.loads(pathlib.Path(args.input).read_text(encoding="utf-8"))
    releases = matrix["releases"][-args.limit:] if args.limit else matrix["releases"]
    cache = pathlib.Path(args.cache)
    framework_revisions = sorted({item["frameworkRevision"] for item in releases if REVISION.fullmatch(item.get("frameworkRevision") or "")})
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        framework_results = dict(zip(framework_revisions, executor.map(lambda value: resolve_framework(value, cache), framework_revisions)))
    revision_pairs = sorted({(item["engineRevision"], framework) for framework, item in framework_results.items() if item.get("engineRevision")})
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        engine_results = dict(zip(revision_pairs, executor.map(lambda value: resolve_engine(value[0], value[1], cache), revision_pairs)))
    dart_revisions = sorted({item.get("dartRevision") for item in engine_results.values() if REVISION.fullmatch(item.get("dartRevision") or "")})
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        snapshot_results = dict(zip(dart_revisions, executor.map(lambda value: resolve_snapshot(value, cache), dart_revisions)))
    resolved = []
    for release in releases:
        item = dict(release)
        framework = framework_results.get(item.get("frameworkRevision"), {})
        engine = framework.get("engineRevision")
        item.update(framework)
        item.update(engine_results.get((engine, item.get("frameworkRevision")), {}))
        item.update(snapshot_results.get(item.get("dartRevision"), {}))
        if item.get("dartRevision") is None and item.get("reason") is None:
            item["reason"] = "dart_revision_unavailable"
        resolved.append(item)
    matrix["releases"] = resolved
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(matrix, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
