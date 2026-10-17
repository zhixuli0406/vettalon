#!/usr/bin/env python3
"""Run exactly two self-authored Go hosts once each; never run application code."""
import argparse
import json
import os
from pathlib import Path
import shutil
import time
import adapter


DB_SHA256 = "24896a2df144d2497bad35b949f6f7409d6755d36ce854ad8ad7d9232538f622"

def validate_db(db):
    files = list(db.iterdir())
    return (len(files) == 1 and files[0].name == "GO-2021-0113.json"
            and files[0].is_file() and not files[0].is_symlink()
            and adapter.digest(files[0].read_bytes()) == DB_SHA256)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", type=Path, required=True)
    parser.add_argument("--db", type=Path, required=True, help="Operator-supplied fixed official GO-2021-0113 subset directory")
    parser.add_argument("--output", type=Path, required=True, help="New output directory; existing paths are refused")
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.db = args.db.resolve()
    protected = [args.db, Path(__file__).resolve().parent / "fixtures"]
    if args.output.exists() or any(args.output == source or source in args.output.parents for source in protected):
        print("output exists or overlaps input; no files written")
        return 2
    try:
        if not validate_db(args.db):
            print("DB must contain exactly the pinned official advisory; checksum mismatch or invalid subset")
            return 2
        args.output.mkdir(parents=True, exist_ok=False)
    except OSError as error:
        print("invalid DB/output: " + str(error))
        return 2
    go = shutil.which("go")
    if not go:
        adapter.write_json(args.output / "summary.json", adapter.unknown("missing-go"))
        return 2
    # Downloads are limited to public official modules and checksum verification.
    env = {"PATH": str(Path(go).parent) + os.pathsep + os.defpath,
           "HOME": str(Path.home()), "GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off", "CGO_ENABLED": "0", "GOTELEMETRY": "off",
           "GOPROXY": "https://proxy.golang.org", "GOSUMDB": "sum.golang.org"}
    setup = adapter.invoke([go, "mod", "download", "-json", "golang.org/x/text@v0.3.5"], Path(__file__).parent, env, 120)
    adapter.write_json(args.output / "dependency-download.json", setup)
    if not adapter.successful_run(setup):
        adapter.write_json(args.output / "summary.json", adapter.unknown("dependency-fetch-error"))
        return 2
    try:
        directory = json.loads(setup["stdout"])["Dir"]
        if not isinstance(directory, str) or not directory:
            raise ValueError("missing dependency directory")
        dependency = Path(directory)
    except (ValueError, KeyError, TypeError):
        adapter.write_json(args.output / "summary.json", adapter.unknown("dependency-fetch-invalid"))
        return 2
    buildinfo = adapter.invoke([go, "version", "-m", str(args.tool.resolve())], Path.cwd(), env, 20)
    adapter.write_json(args.output / "tool-buildinfo.json", buildinfo)
    if not adapter.successful_run(buildinfo):
        adapter.write_json(args.output / "summary.json", adapter.unknown("tool-buildinfo-error"))
        return 2
    db = args.db
    results = []
    started = time.monotonic()
    for name in ["called", "not-called"]:
        if time.monotonic() - started > 1800:
            results.append({"host": name, **adapter.unknown("total-budget-exceeded")})
            break
        project = Path(__file__).parent / "fixtures" / name
        # go mod download only materializes checksums; no generation/build/run hooks.
        download = adapter.invoke([go, "mod", "download", "golang.org/x/text"], project, env, 120)
        adapter.write_json(args.output / (name + "-setup.json"), download)
        if not adapter.successful_run(download):
            results.append({"host": name, **adapter.unknown("dependency-fetch-error")})
            continue
        result = adapter.scan(project, args.output / name, args.tool, dependency=dependency, db=db, cache=args.output / "cache")
        results.append({"host": name, "status": result["status"], "reason": result["reason"], "trace_count": len(result["traces"]), "result": name + "/result.json"})
        print(name + ": " + result["status"])
    adapter.write_json(args.output / "summary.json", {"candidate": adapter.TARGET, "hosts": results, "seconds": time.monotonic() - started,
                       "limitations": ["single official advisory subset, not a full vulnerability database", "static reachability only", "not-observed does not suppress", "no exploitation or host execution", "first failure retained; no automatic retry"],
                       "false_exclusions": 0, "suppressed_alerts": 0, "known_positive_hosts": 1,
                       "false_exclusion_scope": "adapter suppresses no findings; two self-authored fixtures are not a recall benchmark"})
    return 2 if any(r["status"] == "unknown" for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
