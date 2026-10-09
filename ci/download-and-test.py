#!/usr/bin/env python3
"""Verify a downloaded CI artifact, then run its precompiled native harnesses.

No Rust toolchain, Cargo invocation, GitHub credentials, or package installation
is used here. Download the selected GitHub Actions artifact separately and pass
its ZIP or extracted root to --artifact. Every invocation needs a new output.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import zipfile


class VerificationError(ValueError):
    pass


FIXTURE_ROOT = "rust/src/pkg/upstream/fixtures/"
PRIVATE_PEM = re.compile(rb"(?m)^-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\r?$")


def der_sequence_tags(data: bytes) -> list[int] | None:
    """Read only definite-length DER TLVs, enough to distinguish certs/keys."""
    def tlv(offset):
        if offset + 2 > len(data):
            raise ValueError("short DER")
        tag, length = data[offset], data[offset + 1]
        cursor = offset + 2
        if length & 0x80:
            count = length & 0x7f
            if not 1 <= count <= 4 or cursor + count > len(data):
                raise ValueError("invalid DER length")
            length = int.from_bytes(data[cursor:cursor + count], "big")
            cursor += count
        if cursor + length > len(data):
            raise ValueError("truncated DER")
        return tag, cursor, cursor + length
    try:
        tag, start, end = tlv(0)
        if tag != 0x30 or end != len(data):
            return None
        tags = []
        while start < end:
            tag, _, start = tlv(start)
            tags.append(tag)
        return tags if start == end else None
    except ValueError:
        return None


def public_certificate(data: bytes) -> bool:
    if data.startswith(b"-----BEGIN CERTIFICATE-----"):
        match = re.fullmatch(rb"-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----\s*", data)
        if not match:
            return False
        try:
            data = base64.b64decode(re.sub(rb"\s", b"", match[1]), validate=True)
        except ValueError:
            return False
    return der_sequence_tags(data) == [0x30, 0x30, 0x03]


def reject_raw_private_keys(files: dict[str, Path], entries: dict[str, dict]) -> None:
    binary_roles = {"production_cli", "test_cli", "test_harness"}
    native_headers = (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce")
    for name, path in files.items():
        lower = name.lower()
        if re.search(r"(^|[-_/.])key(?:[-_.][^/]*)?\.(der|pem)$", lower) or lower.endswith(".key"):
            raise VerificationError(f"raw private-key file is forbidden in artifacts: {name}")
        # Native test executables intentionally embed freshly generated keys.
        # Only their container is exempt from PEM scanning; raw DER/PEM files
        # cannot bypass this check by claiming an executable role in manifest.
        with path.open("rb") as stream:
            header = stream.read(4)
        executable = entries.get(name, {}).get("role") in binary_roles and header in native_headers
        if executable:
            continue
        data = path.read_bytes()
        tags = der_sequence_tags(data) if data.startswith(b"\x30") else None
        if PRIVATE_PEM.search(data) or tags and tags[0] == 0x02:
            raise VerificationError(f"raw private-key contents are forbidden in artifacts: {name}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_relative(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise VerificationError(f"invalid artifact path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in value.split("/")):
        raise VerificationError(f"unsafe artifact path: {value!r}")
    if any(":" in part for part in path.parts):
        raise VerificationError(f"unsafe artifact path: {value!r}")
    return path.as_posix()


def directory_files(root: Path) -> dict[str, Path]:
    files = {}
    folded = set()
    if root.is_symlink() or not root.is_dir():
        raise VerificationError("artifact root must be a real directory")
    for parent, directories, names in os.walk(root, followlinks=False):
        for name in directories + names:
            item = Path(parent) / name
            relative = safe_relative(item.relative_to(root).as_posix())
            if relative.casefold() in folded:
                raise VerificationError(f"case-insensitive duplicate path: {relative}")
            folded.add(relative.casefold())
            mode = item.lstat().st_mode
            if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                raise VerificationError(f"non-regular artifact entry: {relative}")
            if stat.S_ISREG(mode):
                files[relative] = item
    return files


def safe_extract(archive: Path, destination: Path, max_bytes: int = 2 * 1024**3) -> None:
    """Validate every ZIP entry before writing any member."""
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        if len(members) > 10000:
            raise VerificationError("artifact ZIP has too many entries")
        seen = set()
        prefixes = {}
        paths = set()
        total = 0
        for member in members:
            raw = member.filename[:-1] if member.is_dir() else member.filename
            name = safe_relative(raw)
            if name.casefold() in seen:
                raise VerificationError(f"duplicate ZIP entry: {name}")
            seen.add(name.casefold())
            for prefix in [PurePosixPath(name), *PurePosixPath(name).parents]:
                if str(prefix) == ".":
                    continue
                folded = str(prefix).casefold()
                if folded in prefixes and prefixes[folded] != str(prefix):
                    raise VerificationError(f"case-insensitive ZIP path collision: {name}")
                prefixes[folded] = str(prefix)
            paths.add((name, member.is_dir()))
            mode = member.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise VerificationError(f"non-regular ZIP entry: {name}")
            if member.flag_bits & 1:
                raise VerificationError(f"encrypted ZIP entry: {name}")
            total += member.file_size
            if total > max_bytes:
                raise VerificationError("artifact ZIP exceeds extraction size limit")
        regular = {name.casefold() for name, is_dir in paths if not is_dir}
        for name, _ in paths:
            for parent in PurePosixPath(name).parents:
                if str(parent) != "." and str(parent).casefold() in regular:
                    raise VerificationError(f"ZIP file/directory path conflict: {name}")
        destination.mkdir()
        for member in members:
            name = member.filename.rstrip("/")
            path = destination / name
            if member.is_dir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(member) as source, path.open("xb") as target:
                    shutil.copyfileobj(source, target)


def source_tree_sha256(inputs: dict) -> str:
    digest = hashlib.sha256()
    for path, value in sorted(inputs.items()):
        digest.update(f"{path}\0{value['bytes']}\0{value['sha256']}\n".encode())
    return digest.hexdigest()


def verify_artifact(root: Path, commit: str, target: str, profile: str, source_root: Path | None = None) -> dict:
    actual = directory_files(root)
    if "manifest.json" not in actual:
        raise VerificationError("artifact root lacks manifest.json")
    try:
        manifest = json.loads(actual["manifest.json"].read_text())
    except (ValueError, UnicodeError) as error:
        raise VerificationError(f"invalid artifact manifest: {error}") from error
    if not isinstance(manifest, dict):
        raise VerificationError("artifact manifest must be an object")
    if type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 1:
        raise VerificationError("unsupported manifest schema")
    for name, expected in (("commit", commit), ("target", target), ("profile", profile)):
        if manifest.get(name) != expected:
            raise VerificationError(f"{name} mismatch: expected {expected!r}, got {manifest.get(name)!r}")
    if manifest.get("status") != "complete":
        raise VerificationError("artifact build is not complete")
    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries:
        raise VerificationError("manifest files must be a nonempty list")
    declared = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise VerificationError("invalid manifest file entry")
        name = safe_relative(entry.get("path"))
        if name in declared or name == "manifest.json":
            raise VerificationError(f"duplicate or self-referencing manifest file: {name}")
        declared[name] = entry
        if name not in actual:
            raise VerificationError(f"missing artifact file: {name}")
        expected_size = entry.get("bytes")
        expected_sha = entry.get("sha256")
        if not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size < 0:
            raise VerificationError(f"invalid artifact size: {name}")
        if not isinstance(expected_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
            raise VerificationError(f"invalid artifact SHA-256: {name}")
        if actual[name].stat().st_size != expected_size or sha256(actual[name]) != expected_sha:
            raise VerificationError(f"artifact digest mismatch: {name}")
    if set(actual) != set(declared) | {"manifest.json"}:
        raise VerificationError(f"unlisted artifact files: {sorted(set(actual) - set(declared) - {'manifest.json'})}")
    reject_raw_private_keys(actual, declared)
    sources = manifest.get("source_inputs")
    if not isinstance(sources, dict) or not sources:
        raise VerificationError("manifest lacks source_inputs")
    source_paths = set()
    for name, expected in sources.items():
        name = safe_relative(name)
        if not isinstance(expected, dict):
            raise VerificationError(f"invalid source input: {name}")
        packaged = "runtime-source/" + name
        source_paths.add(packaged)
        entry = declared.get(packaged)
        if entry is None or any(entry.get(key) != expected.get(key) for key in ("bytes", "sha256")):
            raise VerificationError(f"source input binding mismatch: {name}")
    generated = manifest.get("generated_test_inputs", {})
    if not isinstance(generated, dict) or set(generated) & set(sources):
        raise VerificationError("generated_test_inputs must be separate from tracked source_inputs")
    for name, expected in generated.items():
        name = safe_relative(name)
        if not name.startswith(FIXTURE_ROOT) or not isinstance(expected, dict):
            raise VerificationError(f"invalid generated fixture path: {name}")
        if type(expected.get("bytes")) is not int or expected["bytes"] < 1 or not isinstance(expected.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", expected["sha256"]):
            raise VerificationError(f"invalid generated fixture digest: {name}")
        packaged = "runtime-source/" + name
        kind = expected.get("kind")
        if kind == "private_key":
            if expected.get("packaged") is not False or packaged in actual:
                raise VerificationError(f"generated private key must not be packaged: {name}")
        elif kind == "public_certificate":
            entry = declared.get(packaged)
            if expected.get("packaged") is not True or entry is None or any(entry.get(key) != expected[key] for key in ("bytes", "sha256")):
                raise VerificationError(f"generated certificate binding mismatch: {name}")
            if not public_certificate(actual[packaged].read_bytes()):
                raise VerificationError(f"generated public fixture is not a certificate: {name}")
            source_paths.add(packaged)
        else:
            raise VerificationError(f"invalid generated fixture kind: {name}")
    if generated and manifest.get("generated_test_tree_sha256") != source_tree_sha256(generated):
        raise VerificationError("generated test tree digest mismatch")
    if any(value.get("kind") == "private_key" for value in generated.values()) and manifest.get("compile_only_private_key_files_removed") is not True:
        raise VerificationError("CI compile-only private-key cleanup was not confirmed")
    if source_paths != {name for name in declared if name.startswith("runtime-source/")}:
        raise VerificationError("runtime-source contents differ from tracked/generated inputs")
    if manifest.get("source_tree_sha256") != source_tree_sha256(sources):
        raise VerificationError("source tree digest mismatch")
    cli = [entry for entry in entries if entry.get("role") == "production_cli"]
    tests = [entry for entry in entries if entry.get("role") == "test_harness"]
    if len(cli) != 1 or not tests:
        raise VerificationError("artifact must contain one production CLI and test harnesses")
    for entry in tests:
        if entry.get("test") is not True:
            raise VerificationError(f"non-test harness role: {entry['path']}")
        for key in ("tests_all", "tests_ignored"):
            if not isinstance(entry.get(key), list) or any(not isinstance(name, str) for name in entry[key]):
                raise VerificationError(f"missing CI harness inventory: {entry['path']}")
            if len(entry[key]) != len(set(entry[key])):
                raise VerificationError(f"duplicate CI harness test: {entry['path']}")
        if not set(entry["tests_ignored"]).issubset(entry["tests_all"]):
            raise VerificationError(f"invalid CI ignored inventory: {entry['path']}")
    if source_root is not None:
        source_root = source_root.resolve()
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source_root, text=True).strip()
        if head != commit:
            raise VerificationError("local source checkout HEAD differs from expected commit")
        tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=source_root).decode().split("\0")[:-1]
        if set(tracked) != set(sources):
            raise VerificationError("local tracked files differ from artifact source_inputs")
        for name, expected in sources.items():
            path = source_root / safe_relative(name)
            if path.is_symlink() or not path.is_file() or any(parent.is_symlink() for parent in path.parents if parent != source_root and source_root in parent.parents):
                raise VerificationError(f"unsafe local source input: {name}")
            if path.stat().st_size != expected["bytes"] or sha256(path) != expected["sha256"]:
                raise VerificationError(f"local source input differs from artifact: {name}")
    return manifest


def host_target() -> str | None:
    machine = platform.machine().lower()
    cpu = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64", "amd64": "x86_64"}.get(machine)
    if sys.platform == "darwin" and cpu:
        return f"{cpu}-apple-darwin"
    if sys.platform.startswith("linux") and cpu:
        return f"{cpu}-unknown-linux-musl"
    return None


def execute(command: list[str], cwd: Path, environment: dict, logs: Path, label: str, timeout: int) -> dict:
    stdout = logs / f"{label}.stdout.log"
    stderr = logs / f"{label}.stderr.log"
    started = time.time()
    result = {"command": command, "cwd": str(cwd), "stdout": str(stdout), "stderr": str(stderr), "started_at_unix": started}
    with stdout.open("xb") as out, stderr.open("xb") as err:
        child = subprocess.Popen(command, cwd=cwd, env=environment, stdout=out, stderr=err, start_new_session=True)
        try:
            result["returncode"] = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
            result.update(returncode=child.returncode, timed_out=True)
        except KeyboardInterrupt:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
            raise
    result["elapsed_seconds"] = round(time.time() - started, 3)
    result["stdout_sha256"] = sha256(stdout)
    result["stderr_sha256"] = sha256(stderr)
    return result


def listed_tests(path: Path) -> list[str]:
    return sorted(line.rsplit(": ", 1)[0] for line in path.read_text(errors="replace").splitlines() if line.endswith(": test") or line.endswith(": benchmark"))


def run_validation(artifact: Path, manifest: dict, output: Path, threads: int, timeout: int, opt_ins: list[str]) -> dict:
    if host_target() != manifest["target"]:
        raise VerificationError(f"cannot execute {manifest['target']} on {host_target()}; use --verify-only")
    logs = output / "logs"
    logs.mkdir()
    cli = next(entry for entry in manifest["files"] if entry.get("role") == "production_cli")
    binary = artifact / cli["path"]
    harnesses = sorted((entry for entry in manifest["files"] if entry.get("role") == "test_harness"), key=lambda entry: entry["path"])
    for entry in [cli] + harnesses:
        (artifact / entry["path"]).chmod(0o755)
    environment = dict(os.environ)
    for key in ("MOSDNS_EXPORT_RUST_DUMP", "MOSDNS_TRUST_SCENARIO", "MOSDNS_TRUST_PROTOCOL"):
        environment.pop(key, None)
    environment.update(MOSDNS_TEST_BINARY=str(binary), MOSDNS_RS_TEST_BIN=str(binary), RUST_TEST_THREADS=str(threads))
    cwd = artifact / "runtime-source" / "rust"
    progress = {"status": "running", "commands": []}
    progress_path = output / "runtime-progress.json"
    def command(arguments, label):
        result = execute(arguments, cwd, environment, logs, label, timeout)
        progress["commands"].append(result)
        progress_path.write_text(json.dumps(progress, indent=2) + "\n")
        return result
    checks = []
    checks.append(command([str(binary), "version"], "cli-version"))
    version = Path(checks[-1]["stdout"]).read_text(errors="replace").strip()
    checks[-1]["matches_ci_version"] = version == manifest.get("production_version")
    config = output / "cli-check.yaml"
    config.write_text("plugins:\n  - tag: main\n    type: sequence\n    args:\n      - exec: 'reject 3'\n")
    checks.append(command([str(binary), "check", "--cpu", "1", "-c", str(config)], "cli-check"))
    inventory = []
    executions = []
    ignored_keys = set()
    for index, harness in enumerate(harnesses):
        path = artifact / harness["path"]
        label = f"harness-{index:03d}"
        listing = command([str(path), "--list", "--format", "terse"], label + "-list")
        ignored = command([str(path), "--ignored", "--list", "--format", "terse"], label + "-ignored-list")
        checks.extend([listing, ignored])
        names = listed_tests(Path(listing["stdout"]))
        ignored_names = listed_tests(Path(ignored["stdout"]))
        if len(names) != len(set(names)) or not set(ignored_names).issubset(names):
            raise VerificationError(f"invalid test inventory: {harness['path']}")
        if names != harness["tests_all"] or ignored_names != harness["tests_ignored"]:
            raise VerificationError(f"local harness inventory differs from CI: {harness['path']}")
        ignored_keys.update(f"{harness['path']}::{name}" for name in ignored_names)
        inventory.append({"path": harness["path"], "target_name": harness.get("target_name"), "tests": names, "ignored": ignored_names, "ordinary_count": len(names) - len(ignored_names)})
    unknown = set(opt_ins) - ignored_keys
    if unknown:
        raise VerificationError(f"requested ignored tests were not listed: {sorted(unknown)}")
    for index, harness in enumerate(harnesses):
        arguments = [str(artifact / harness["path"]), "--test-threads", str(threads)]
        execution = command(arguments, f"harness-{index:03d}-run")
        execution.update(path=harness["path"], mode="ordinary")
        summary = re.findall(r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", Path(execution["stdout"]).read_text(errors="replace"))
        if len(summary) == 1:
            state, passed, failed, ignored, measured, filtered = summary[0]
            execution["summary"] = dict(state=state, passed=int(passed), failed=int(failed), ignored=int(ignored), measured=int(measured), filtered_out=int(filtered))
            expected = inventory[index]
            execution["inventory_matches"] = int(passed) + int(failed) == expected["ordinary_count"] and int(ignored) == len(expected["ignored"]) and int(filtered) == 0
        else:
            execution["inventory_matches"] = False
        executions.append(execution)
    for index, key in enumerate(opt_ins):
        path, name = next((harness["path"], name) for harness in inventory for name in harness["ignored"] if key == f"{harness['path']}::{name}")
        execution = command([str(artifact / path), "--ignored", "--exact", name, "--test-threads", "1"], f"ignored-{index:03d}")
        execution.update(path=path, test=name, mode="ignored-opt-in")
        summaries = re.findall(r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", Path(execution["stdout"]).read_text(errors="replace"))
        execution["inventory_matches"] = len(summaries) == 1 and summaries[0][0:5] == ("ok", "1", "0", "0", "0")
        executions.append(execution)
    ordinary_ok = all(item["returncode"] == 0 and item.get("inventory_matches", True) for item in executions)
    checks_ok = all(item["returncode"] == 0 and item.get("matches_ci_version", True) for item in checks)
    result = {"status": "complete" if ordinary_ok and checks_ok else "failed", "checks": checks, "harness_inventory": inventory, "executions": executions, "ignored_not_run": sorted(ignored_keys - set(opt_ins)), "test_threads": threads}
    progress.update(status=result["status"])
    progress_path.write_text(json.dumps(progress, indent=2) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", required=True, type=Path, help="downloaded ZIP or extracted artifact root")
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-target", required=True)
    parser.add_argument("--expected-profile", required=True, choices=("full", "minimal"))
    parser.add_argument("--output", required=True, type=Path, help="new evidence directory, must not exist")
    parser.add_argument("--source-root", type=Path, help="also bind to this clean local Git checkout at the expected commit")
    parser.add_argument("--verify-only", action="store_true", help="verify without executing the downloaded binaries")
    parser.add_argument("--test-threads", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=300, help="per-command timeout in seconds")
    parser.add_argument("--run-ignored", action="append", default=[], metavar="HARNESS_PATH::EXACT_TEST")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.expected_commit):
        parser.error("--expected-commit must be the complete lowercase 40-character commit SHA")
    if args.test_threads < 1 or args.test_threads > 16 or args.timeout < 1:
        parser.error("--test-threads must be 1..16 and --timeout must be positive")
    if args.verify_only and args.run_ignored:
        parser.error("--run-ignored is incompatible with --verify-only")
    source = args.artifact.resolve()
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        parser.error("--output must not exist; old evidence is never overwritten")
    if source.is_dir() and (output == source or source in output.parents):
        parser.error("--output cannot be inside the source artifact")
    output.mkdir(parents=True)
    result = {"schema_version": 1, "status": "failed", "started_at_unix": time.time(), "artifact_input": str(source), "expected_commit": args.expected_commit, "expected_target": args.expected_target, "expected_profile": args.expected_profile, "verifier_sha256": sha256(Path(__file__)), "executed": False}
    destination = output / "artifact"
    try:
        if source.is_dir():
            directory_files(source)
            shutil.copytree(source, destination)
        elif source.is_file():
            result["archive_sha256"] = sha256(source)
            safe_extract(source, destination)
        else:
            raise VerificationError("artifact input does not exist")
        manifest = verify_artifact(destination, args.expected_commit, args.expected_target, args.expected_profile, args.source_root)
        result.update(manifest_sha256=sha256(destination / "manifest.json"), source_tree_sha256=manifest["source_tree_sha256"], generated_test_tree_sha256=manifest.get("generated_test_tree_sha256"), verified_file_count=len(manifest["files"]), verification="complete")
        if args.verify_only:
            result.update(status="verified", note="Binaries were not executed; runtime validation remains required.")
        else:
            if host_target() != manifest["target"]:
                raise VerificationError(f"cannot execute {manifest['target']} on {host_target()}; use --verify-only")
            result["executed"] = True
            result["runtime"] = run_validation(destination, manifest, output, args.test_threads, args.timeout, args.run_ignored)
            result["status"] = result["runtime"]["status"]
        verify_artifact(destination, args.expected_commit, args.expected_target, args.expected_profile, args.source_root)
        result["artifact_unchanged_after_validation"] = True
    except (VerificationError, OSError, zipfile.BadZipFile, KeyError, TypeError, subprocess.CalledProcessError) as error:
        result["error"] = str(error)
    except KeyboardInterrupt:
        result["error"] = "interrupted; active process group was stopped"
    if (output / "runtime-progress.json").exists():
        result["runtime_progress"] = str(output / "runtime-progress.json")
    result["completed_at_unix"] = time.time()
    (output / "RESULT.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(f"{result['status']}: {output / 'RESULT.json'}")
    return 0 if result["status"] in ("complete", "verified") else 1


if __name__ == "__main__":
    raise SystemExit(main())
