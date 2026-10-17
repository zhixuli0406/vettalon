"""Read explicitly declared legacy observations without executing their producers."""
import argparse
import csv
import hashlib
import io
import json
import math
import os
import re
import stat
import sys

SCHEMA = "vettalon-legacy-observations-v1"
MANIFEST_SCHEMA = "vettalon-legacy-inputs-v1"
MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
MAX_MANIFEST = 256 * 1024
MAX_FILES = 32
MAX_CASES = 4096
MAX_SLOTS = 16384
MAX_OUTPUT = 16 * 1024 * 1024
ADAPTERS = {"recall-report-schema2-legacy", "owasp-boolean-rows-legacy", "ranking-target-rankers-legacy"}
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
SHA = re.compile(r"[a-f0-9]{64}\Z")
TSV_FIELDS = ["id", "repo", "vuln_ref", "cve", "class", "vuln_file"]
OWASP_FIELDS = {"id", "cat", "real", "cwe", "expect_class"}


class ReaderError(ValueError):
    """Rejected input; never interpret this as a benchmark outcome."""


def require(condition, reason):
    if not condition:
        raise ReaderError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def floating(value):
        number = float(value)
        require(math.isfinite(number), "nonfinite JSON number")
        return number
    def constant(_value):
        raise ReaderError("nonfinite JSON constant")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                          parse_float=floating, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ReaderError("invalid strict JSON") from exc


def identifier(value):
    require(isinstance(value, str) and ID.fullmatch(value) is not None, "invalid identifier")
    return value


def text(value):
    require(isinstance(value, str) and bool(value), "expected nonempty text")
    return value


def integer(value, minimum=0):
    require(type(value) is int and value >= minimum, "invalid integer")
    return value


def number(value):
    require(type(value) in (int, float), "invalid nonnegative number")
    try:
        require(math.isfinite(value) and value >= 0, "invalid nonnegative number")
    except OverflowError as exc:
        raise ReaderError("numeric range exceeded") from exc
    return value


def relative_parts(value):
    require(isinstance(value, str) and bool(value) and "\\" not in value and "\x00" not in value,
            "invalid relative path")
    parts = value.split("/")
    require(all(p and p not in (".", "..") for p in parts), "invalid relative path")
    return parts


def references(manifest):
    require(isinstance(manifest, dict) and manifest.get("schema") == MANIFEST_SCHEMA, "unsupported manifest schema")
    datasets = manifest.get("datasets")
    require(isinstance(datasets, list) and 0 < len(datasets) <= MAX_FILES, "invalid cohorts")
    refs, ids, slots = {}, set(), 0
    for d in datasets:
        require(isinstance(d, dict), "invalid cohort")
        ident = identifier(d.get("id"))
        require(ident not in ids, "duplicate cohort")
        ids.add(ident)
        require(isinstance(d.get("adapter"), str) and d["adapter"] in ADAPTERS, "unsupported adapter")
        text(d.get("scope"))
        arms = d.get("arms")
        require(isinstance(arms, list) and 0 < len(arms) <= 16, "invalid arms")
        require(len(set(identifier(a) for a in arms)) == len(arms), "duplicate arm")
        count = integer(d.get("expected_cases"), 1)
        require(count <= MAX_CASES, "case cap")
        slots += count * len(arms)
        require(slots <= MAX_SLOTS, "slot cap")
        inputs = d.get("inputs")
        require(isinstance(inputs, list) and len(inputs) <= MAX_FILES, "invalid inputs")
        local = set()
        for ref in [d.get("registry"), *inputs]:
            require(isinstance(ref, dict), "invalid file reference")
            path = ref.get("path")
            relative_parts(path)
            require(path not in local, "duplicate cohort file")
            local.add(path)
            require(isinstance(ref.get("sha256"), str) and SHA.fullmatch(ref["sha256"]) is not None, "invalid SHA256")
            require(integer(ref.get("bytes")) <= MAX_FILE, "file cap")
            if path in refs:
                require((refs[path]["sha256"], refs[path]["bytes"]) == (ref["sha256"], ref["bytes"]), "conflicting file reference")
            refs[path] = ref
    require(len(refs) <= MAX_FILES and sum(r["bytes"] for r in refs.values()) <= MAX_TOTAL, "combined input cap")
    return refs


def registry(raw, adapter):
    if adapter == "owasp-boolean-rows-legacy":
        rows = strict_json(raw)
        require(isinstance(rows, list), "OWASP registry must be rows")
        for row in rows:
            require(isinstance(row, dict) and set(row) == OWASP_FIELDS, "invalid OWASP registry row")
            require(type(row["real"]) is bool, "dataset label must be bool")
            for key in OWASP_FIELDS - {"real"}:
                text(row[key])
    else:
        try:
            reader = csv.reader(io.StringIO(raw.decode("utf-8")), delimiter="\t")
            require(next(reader, None) == TSV_FIELDS, "unsupported registry header")
            rows = []
            for values in reader:
                require(len(values) == len(TSV_FIELDS), "registry field count")
                require(all(values), "empty registry field")
                rows.append(dict(zip(TSV_FIELDS, values)))
        except (UnicodeError, csv.Error) as exc:
            raise ReaderError("invalid registry TSV") from exc
    require(0 < len(rows) <= MAX_CASES, "registry case cap")
    result = {}
    for row in rows:
        ident = identifier(row.get("id"))
        require(ident not in result, "duplicate registry case")
        result[ident] = row
    return result


def base_row(d, case, arm, reg, ref=None, pointer=None):
    lineage = {"schema": SCHEMA, "cohort_id": d["id"], "adapter": d["adapter"],
               "registry_sha256": d["registry"]["sha256"],
               "input_sha256": ref["sha256"] if ref else None,
               "input_path": ref["path"] if ref else None, "raw_pointer": pointer,
               "case_id": case, "arm_id": arm}
    return {"case_id": case, "arm_id": arm, "observation_kind": None,
            "observation_status": "missing", "reported": None, "lineage": lineage,
            "declared_case": dict(reg),
            "fingerprint": hashlib.sha256(canonical(lineage)).hexdigest(),
            "source_identity": {"declared_target_ref": reg.get("vuln_ref"),
                                "observed_revision": None, "verified_source_sha256": None},
            "adjudication": None, "verified_completion": None,
            "cost": {"reported_usd": None, "provenance": "unavailable", "raw_pointer": None, "billing_verified": False},
            "resources": {"cpu_seconds": None, "rss_bytes": None, "human_seconds": None, "tokens": None}}


def recall(d, cases, blobs):
    require(d["arms"] == ["recorded-scan"], "recall requires recorded-scan arm")
    observed = {}
    for ref in d["inputs"]:
        case = identifier(ref.get("case_id"))
        require(case in cases and case not in observed, "foreign or duplicate recall case")
        report = strict_json(blobs[ref["path"]])
        require(isinstance(report, dict) and type(report.get("schema_version")) is int and report["schema_version"] == 2,
                "unsupported recall report")
        require(report.get("run_status") in ("complete", "incomplete", "failed"), "invalid reported run status")
        require(report.get("incomplete_reason") is None or isinstance(report["incomplete_reason"], str), "invalid incomplete reason")
        require(isinstance(report.get("findings"), list), "missing findings")
        require(isinstance(report.get("coverage"), list) and isinstance(report.get("summary"), dict), "missing legacy summaries")
        require(isinstance(report.get("engines_run"), list) and isinstance(report.get("engines_missing"), list), "missing engine records")
        findings, seen = [], set()
        for i, finding in enumerate(report["findings"]):
            require(isinstance(finding, dict), "invalid finding")
            ident = identifier(finding.get("id"))
            require(ident not in seen, "duplicate finding ID")
            seen.add(ident)
            for key in ("rule_id", "status", "file"):
                text(finding.get(key))
            if finding.get("line") is not None:
                integer(finding["line"], 1)
            require(isinstance(finding.get("evidence"), list), "invalid evidence")
            item = {key: finding.get(key) for key in ("id", "rule_id", "status", "file", "line", "file_hash", "root_fingerprint")}
            item.update(raw_pointer=f"/findings/{i}", evidence_pointer=f"/findings/{i}/evidence",
                        reported_hash_verified=False)
            findings.append(item)
        # Preserve structured engine failures/partial coverage; do not infer clean from an empty list.
        reported = {key: report.get(key) for key in ("repo", "run_status", "incomplete_reason", "summary", "coverage", "engines_run", "engines_missing", "verifier", "ensemble", "profile", "started_at", "prior_run")}
        reported["findings"] = findings
        observed[case] = (ref, reported)
    rows = []
    for case, reg in cases.items():
        ref, reported = observed.get(case, (None, None))
        row = base_row(d, case, "recorded-scan", reg, ref, "" if ref else None)
        row.update(observation_kind="legacy-finding-and-coverage-record", modern_coverage_proven=False)
        if ref:
            row.update(observation_status="reported", reported=reported)
        rows.append(row)
    return {"rows": rows, "limitations": ["Legacy coverage lacks modern source/range/attempt binding.",
            "Reported complete and finding statuses are not independently verified completion or human adjudication."]}


def owasp(d, cases, blobs):
    require(d["arms"] == ["finder-readout", "crossfamily-readout"], "unsupported OWASP readout arms")
    require(len(d["inputs"]) <= 1, "OWASP cohort requires at most one result file")
    observed = {}
    ref = d["inputs"][0] if d["inputs"] else None
    if ref:
        result = strict_json(blobs[ref["path"]])
        require(isinstance(result, list) and len(result) <= MAX_CASES, "OWASP requires per-case rows")
        for i, item in enumerate(result):
            require(isinstance(item, dict) and set(item) == OWASP_FIELDS | {"finder_pos", "crossfamily_pos"}, "invalid OWASP result row")
            case = identifier(item.get("id"))
            require(case in cases and case not in observed, "foreign or duplicate OWASP case")
            require(type(item["real"]) is bool and all(item[k] == cases[case][k] for k in OWASP_FIELDS), "OWASP metadata mismatch")
            require(type(item["finder_pos"]) is bool and type(item["crossfamily_pos"]) is bool, "readouts must be bool")
            require(not item["crossfamily_pos"] or item["finder_pos"], "impossible paired readout")
            observed[case] = (i, item)
    rows, counts = [], {arm: 0 for arm in d["arms"]}
    for case, reg in cases.items():
        item = observed.get(case)
        for arm, key in zip(d["arms"], ("finder_pos", "crossfamily_pos")):
            row = base_row(d, case, arm, reg, ref if item else None, f"/{item[0]}/{key}" if item else None)
            row.update(observation_kind="historical-boolean-label-proxy",
                       declared_dataset_label={k: reg[k] for k in ("real", "cat", "cwe", "expect_class")})
            if item:
                row.update(observation_status="reported_boolean", reported={"positive": item[1][key]})
                counts[arm] += int(item[1][key])
            rows.append(row)
    return {"rows": rows, "declared_labels": {"positive": sum(r["real"] for r in cases.values()),
            "safe": sum(not r["real"] for r in cases.values())}, "reported_boolean_counts": counts,
            "comparison_design": "paired-readouts-not-independent-runs",
            "limitations": ["Producer default false may also mean missing raw report; false is not a verified TN or miss.",
                            "Arrays lack per-case execution status, raw report binding and measured usage."]}


def pointer_token(value):
    return value.replace("~", "~0").replace("/", "~1")


def ranking(d, cases, blobs):
    require(len(d["inputs"]) <= 1, "ranking cohort requires at most one result file")
    targets, producer, reported_summary, ref = {}, None, None, None
    if d["inputs"]:
        ref = d["inputs"][0]
        report = strict_json(blobs[ref["path"]])
        require(isinstance(report, dict) and isinstance(report.get("targets"), list), "ranking requires per-target rows")
        require(isinstance(report.get("walker"), dict) and isinstance(report.get("summary"), dict), "invalid ranking metadata")
        text(report.get("label"))
        require(len(report["targets"]) <= MAX_CASES, "target cap")
        producer, reported_summary = report["walker"], report["summary"]
        require(all(a in d["arms"] for a in reported_summary), "undeclared summary arm")
        for i, target in enumerate(report["targets"]):
            require(isinstance(target, dict), "invalid target")
            case = identifier(target.get("id"))
            require(case in cases and case not in targets, "foreign or duplicate ranking case")
            require(target.get("cve") == cases[case]["cve"] and target.get("vuln_file") == cases[case]["vuln_file"], "ranking target metadata mismatch")
            for key in ("code_files", "modules", "units"):
                integer(target.get(key))
            require(isinstance(target.get("git"), dict) and isinstance(target.get("rankers"), dict), "invalid target metadata")
            require(all(a in d["arms"] for a in target["rankers"]), "undeclared ranker arm")
            for ranker in target["rankers"].values():
                require(isinstance(ranker, dict) and {"status", "rank", "latency_ms", "cost_usd", "detail"} <= ranker.keys(), "invalid ranker record")
                text(ranker["status"])
                if ranker["rank"] is not None:
                    integer(ranker["rank"], 1)
                    number(ranker["rank"])
                for key in ("latency_ms", "cost_usd"):
                    if ranker[key] is not None:
                        number(ranker[key])
                require(isinstance(ranker["detail"], dict), "invalid ranker detail")
                for key in ("input_tokens", "output_tokens", "tokens"):
                    if key in ranker["detail"] and ranker["detail"][key] is not None:
                        integer(ranker["detail"][key])
            targets[case] = (i, target)
    rows, diagnostics, costs = [], {}, {}
    for case, reg in cases.items():
        target = targets.get(case)
        for arm in d["arms"]:
            record = target[1]["rankers"].get(arm) if target else None
            pointer = f"/targets/{target[0]}/rankers/{pointer_token(arm)}" if record is not None else None
            row = base_row(d, case, arm, reg, ref if record is not None else None, pointer)
            row.update(observation_kind="rank-only", cost_provenance="unknown")
            if record is not None:
                status = record["status"]
                state = ("observed" if record["rank"] is not None else "not_observed") if status == "ok" else ("skipped" if status.startswith("skipped") else "failed")
                row.update(observation_status=state, reported=record,
                           reported_target_metadata={k: target[1][k] for k in ("code_files", "modules", "units", "git")},
                           cost_provenance=("CLI-reported-not-billing" if arm == "metadata-llm" else "recorded-token-price-estimate-not-billing" if arm == "jev" else "reported-not-billing"))
                row["cost"].update(reported_usd=record["cost_usd"], provenance=row["cost_provenance"],
                                   raw_pointer=pointer + "/cost_usd")
            rows.append(row)
    for arm in d["arms"]:
        arm_rows = [r for r in rows if r["arm_id"] == arm]
        ranks = [r["reported"]["rank"] for r in arm_rows if r["observation_status"] == "observed"]
        diag = {"n": len(cases), "observed_ranks": len(ranks), "unobserved_slots": len(cases) - len(ranks),
                "hit@5": sum(r <= 5 for r in ranks), "hit@10": sum(r <= 10 for r in ranks),
                "hit@40": sum(r <= 40 for r in ranks), "mrr": round(sum(1 / r for r in ranks) / len(cases), 3)}
        diagnostics[arm] = diag
        known = [r["reported"]["cost_usd"] for r in arm_rows if r["reported"] is not None and r["reported"]["cost_usd"] is not None]
        subtotal = sum(known) if known else None
        require(subtotal is None or math.isfinite(subtotal), "cost total overflow")
        costs[arm] = {"known_slots": len(known), "unknown_slots": len(cases) - len(known),
                      "known_subtotal_usd": subtotal, "total_usd": subtotal if len(known) == len(cases) else None,
                      "authoritative_billing": False}
    matches = reported_summary is not None and set(reported_summary) == set(d["arms"]) and all(
        isinstance(summary, dict)
        and all(type(summary.get(k)) is int for k in ("n", "hit@5", "hit@10", "hit@40"))
        and type(summary.get("mrr")) in (int, float) and 0 <= summary["mrr"] <= 1
        and math.isfinite(summary["mrr"])
        and all(summary.get(k) == diagnostics[a][k] for k in ("n", "hit@5", "hit@10", "hit@40", "mrr"))
        for a, summary in reported_summary.items())
    return {"rows": rows, "reported_summary": reported_summary, "rank_diagnostics": diagnostics,
            "summary_matches_diagnostics": matches, "reported_producer_identity": producer,
            "implementation_identity_quality": "historical-declaration-not-attestation", "cost": costs,
            "limitations": ["Rank diagnostics use fixed registry slots; unobserved ranks are not detection misses.",
                            "Walker identity describes the producer, not observed target revision.",
                            "Cost is historical reported/estimated USD, not verified billing or whole-process cost."]}


def normalize_bundle(manifest, blobs):
    """Normalize supplied bytes only. Reject the entire bundle on malformed input."""
    # Copy through strict JSON to reject non-JSON Python values and detach caller objects.
    try:
        require(len(canonical(manifest)) <= MAX_MANIFEST, "manifest cap")
        manifest = strict_json(canonical(manifest))
    except (TypeError, ValueError, RecursionError) as exc:
        raise ReaderError("invalid manifest") from exc
    refs = references(manifest)
    require(isinstance(blobs, dict), "invalid byte bundle")
    for path, ref in refs.items():
        raw = blobs.get(path)
        require(type(raw) is bytes and len(raw) == ref["bytes"], "missing input or byte-count mismatch")
        require(hashlib.sha256(raw).hexdigest() == ref["sha256"], "input SHA256 mismatch")
    cohorts = []
    adapters = {"recall-report-schema2-legacy": recall, "owasp-boolean-rows-legacy": owasp, "ranking-target-rankers-legacy": ranking}
    for d in manifest["datasets"]:
        cases = registry(blobs[d["registry"]["path"]], d["adapter"])
        require(len(cases) == d["expected_cases"], "registry denominator mismatch")
        result = adapters[d["adapter"]](d, cases, blobs)
        result.update(id=d["id"], adapter=d["adapter"], scope=d["scope"], case_denominator=len(cases),
                      observation_slots=len(result["rows"]), missing_slots=sum(r["observation_status"] == "missing" for r in result["rows"]),
                      adjudicated_metrics=None, normalization_status="complete")
        cohorts.append(result)
    output = {"schema": SCHEMA, "normalization_status": "complete", "automatic_adjudicated_metric_feed": False,
              "cohorts": cohorts, "scope": "Reader completion only; no new benchmark, adjudication, runtime measurement or source execution."}
    require(len(canonical(output)) <= MAX_OUTPUT, "output cap")
    return output


def absolute_parts(path):
    require(isinstance(path, str) and path.startswith("/") and not path.startswith("//"), "absolute lexical path required")
    return relative_parts(path[1:])


def directory_fd(parts):
    require(hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY"), "secure POSIX file IO unavailable")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open("/", flags)
    try:
        for part in parts:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_absolute(path, cap):
    parts = absolute_parts(path)
    parent = directory_fd(parts[:-1])
    fd = None
    try:
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0), dir_fd=parent)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= cap, "input is nonregular or oversized")
        chunks, size = [], 0
        while size <= cap:
            chunk = os.read(fd, min(65536, cap + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        after = os.fstat(fd)
        require(size <= cap, "input cap exceeded")
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "input changed during read")
        return b"".join(chunks)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def write_exclusive(path, raw):
    require(type(raw) is bytes and len(raw) <= MAX_OUTPUT, "output cap")
    parts = absolute_parts(path)
    parent = directory_fd(parts[:-1])
    fd = None
    try:
        fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            require(written > 0, "incomplete output write")
            view = view[written:]
        os.fsync(fd)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--input-root", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        root = absolute_parts(args.input_root)
        # Validate the root even for an empty manifest; never canonicalize through symlinks.
        root_fd = directory_fd(root)
        os.close(root_fd)
        manifest = strict_json(read_absolute(args.manifest, MAX_MANIFEST))
        refs = references(manifest)
        blobs = {path: read_absolute("/" + "/".join(root + relative_parts(path)), ref["bytes"]) for path, ref in refs.items()}
        output = canonical(normalize_bundle(manifest, blobs)) + b"\n"
        write_exclusive(args.output, output)
        return 0
    except (ReaderError, OSError, RecursionError, OverflowError):
        print("legacy-reader: rejected input or output; no benchmark result produced", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
