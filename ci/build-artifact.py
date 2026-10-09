#!/usr/bin/env python3
"""Build only on GitHub Actions; freeze CLI before Cargo test feature unification."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    "x86_64-unknown-linux-musl": ("Linux", {"x86_64", "AMD64"}),
    "aarch64-unknown-linux-musl": ("Linux", {"aarch64", "arm64"}),
    "aarch64-apple-darwin": ("Darwin", {"arm64", "aarch64"}),
}


class BuildError(RuntimeError):
    pass


def now():
    return datetime.now(timezone.utc).isoformat()


def record(path):
    if path.is_symlink() or not path.is_file():
        raise BuildError("expected regular file: " + str(path))
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def tree_digest(inputs):
    data = "".join(
        f"{name}\0{value['bytes']}\0{value['sha256']}\n"
        for name, value in sorted(inputs.items())
    ).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def git(*arguments):
    return subprocess.check_output(["git", *arguments], cwd=ROOT).decode("utf-8")


def inputs():
    paths = git("ls-files", "-z").split("\0")
    return {name: record(ROOT / name) for name in sorted(paths) if name}


def manifest_write(output, manifest):
    temporary = output / "manifest.json.tmp"
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    temporary.replace(output / "manifest.json")


def safe_text(value):
    return re.sub(r"(https?://)[^/\s@]+@", r"\1<redacted>@", value)


def execute(command, cwd, env, output, manifest, label):
    entry = {
        "command": command, "cwd": str(cwd), "started_at": now(),
        "stdout": f"logs/{label}.stdout", "stderr": f"logs/{label}.stderr",
    }
    manifest["commands"].append(entry)
    manifest_write(output, manifest)
    print("Running:", " ".join(command), flush=True)
    process = subprocess.run(command, cwd=cwd, env=env, capture_output=True,
                             text=True, encoding="utf-8", errors="replace")
    stdout = safe_text(process.stdout)
    stderr = safe_text(process.stderr)
    (output / entry["stdout"]).write_text(stdout)
    (output / entry["stderr"]).write_text(stderr)
    entry.update(exit_code=process.returncode, finished_at=now())
    manifest_write(output, manifest)
    if stderr:
        print(stderr, file=sys.stderr, flush=True)
    if process.returncode:
        if stdout:
            print(stdout, flush=True)
        raise BuildError(f"{label} failed with status {process.returncode}")
    return stdout, entry


def copy(source, destination):
    record(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o755)


def artifacts(stdout):
    for line in stdout.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if value.get("reason") == "compiler-artifact" and value.get("executable"):
            yield value


def names(stdout):
    return sorted(line.rsplit(": ", 1)[0] for line in stdout.splitlines()
                  if line.endswith(": test") or line.endswith(": benchmark"))


def describe_files(output, binaries, source_inputs, generated_inputs):
    result = []
    for path in sorted(output.rglob("*")):
        if path.is_symlink():
            raise BuildError("symlink in artifact: " + str(path))
        if not path.is_file() or path == output / "manifest.json":
            continue
        name = path.relative_to(output).as_posix()
        if name in binaries:
            metadata = binaries[name]
        elif name.startswith("runtime-source/"):
            source = name.removeprefix("runtime-source/")
            if source in source_inputs:
                expected = source_inputs[source]
                metadata = {"role": "source", "source_path": source}
            elif source in generated_inputs and generated_inputs[source]["packaged"]:
                expected = {key: generated_inputs[source][key] for key in ("bytes", "sha256")}
                metadata = {"role": "generated_public_certificate", "source_path": source}
            else:
                raise BuildError("unbound runtime source file: " + source)
            if record(path) != expected:
                raise BuildError("frozen input changed: " + source)
        elif name.startswith("tests/"):
            metadata = {"role": "test_listing"}
        else:
            metadata = {"role": "build_log"}
        result.append({"path": name, **record(path), **metadata})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    parser.add_argument("--profile", choices=("full", "minimal"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true":
        parser.error("Rust compilation is restricted to GitHub Actions; download artifacts locally")

    import platform
    system, machines = TARGETS[args.target]
    if platform.system() != system or platform.machine() not in machines:
        parser.error("target must run natively on the corresponding GitHub runner")
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        parser.error("output must be a new directory")
    output.mkdir(parents=True)
    (output / "logs").mkdir()
    (output / "tests").mkdir()
    manifest = {
        "schema_version": 1, "status": "preparing", "started_at": now(),
        "commit": git("rev-parse", "HEAD").strip(),
        "target": args.target, "profile": args.profile,
        "source_tree_algorithm": "sha256 of sorted UTF-8 path + NUL + decimal bytes + NUL + sha256 + newline",
        "github": {name: os.environ.get(name) for name in (
            "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
            "GITHUB_JOB", "RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion",
        )},
        "commands": [], "files": [], "ignored_tests_executed": False,
        "production_cli_frozen_before_test_build": True,
    }
    binaries = {}
    try:
        if manifest["commit"] != os.environ.get("GITHUB_SHA"):
            raise BuildError("checkout commit differs from workflow commit")
        if git("status", "--porcelain", "--untracked-files=no").strip():
            raise BuildError("tracked source is dirty before build")
        original = inputs()
        if not original or "Cargo.lock" not in original:
            raise BuildError("Cargo inputs not tracked")
        manifest["source_inputs"] = original
        manifest["source_tree_sha256"] = tree_digest(original)
        generation = json.loads((ROOT / ".artifacts/generated-test-fixtures.json").read_text())
        generated = generation["generated_test_inputs"]
        expected_generated = {
            "rust/src/pkg/upstream/fixtures/localhost-cert.der": "public_certificate",
            "rust/src/pkg/upstream/fixtures/localhost-key.der": "private_key",
            "rust/src/pkg/upstream/fixtures/system-trust/ca.pem": "public_certificate",
            "rust/src/pkg/upstream/fixtures/system-trust/server-cert.der": "public_certificate",
            "rust/src/pkg/upstream/fixtures/system-trust/server-key.der": "private_key",
            "rust/src/pkg/upstream/fixtures/system-trust/untrusted-ca.pem": "public_certificate",
        }
        if set(generated) != set(expected_generated) or set(generated).intersection(original):
            raise BuildError("generated TLS fixture paths differ or are tracked in Git")
        for name, kind in expected_generated.items():
            value = generated[name]
            expected = {key: value[key] for key in ("bytes", "sha256")}
            if value["kind"] != kind or value["packaged"] != (kind == "public_certificate"):
                raise BuildError("TLS fixture role/package policy differs: " + name)
            if record(ROOT / name) != expected:
                raise BuildError("generated TLS fixture changed: " + name)
        if tree_digest(generated) != generation["generated_test_tree_sha256"]:
            raise BuildError("generated TLS fixture metadata tree hash differs")
        if not generation["ca_signing_keys_removed"]:
            raise BuildError("fixture generator did not remove CA signing keys")
        manifest.update(generated_test_inputs=generated,
                        generated_test_tree_sha256=tree_digest(generated),
                        fixture_generation={key: generation[key] for key in (
                            "generated_at", "method", "openssl", "ca_signing_keys_removed",
                        )})
        for name in original:
            destination = output / "runtime-source" / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        for name, value in generated.items():
            if value["packaged"]:
                destination = output / "runtime-source" / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, destination)

        env = os.environ.copy()
        for key in list(env):
            if key.startswith("CARGO_PROFILE_RELEASE_") or key in {
                "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS",
                "CARGO_BUILD_TARGET", "CARGO_TARGET_DIR", "RUSTC_WRAPPER",
                "RUSTC_WORKSPACE_WRAPPER",
            }:
                del env[key]
        target_dir = Path(os.environ["RUNNER_TEMP"]) / f"rust-{args.target}-{args.profile}"
        env.update(CARGO_TARGET_DIR=str(target_dir), CARGO_INCREMENTAL="0",
                   CARGO_PROFILE_RELEASE_STRIP="symbols", CARGO_TERM_COLOR="never")
        if args.target.endswith("-linux-musl"):
            env["CC_" + args.target.replace("-", "_")] = "musl-gcc"
            env["AR_" + args.target.replace("-", "_")] = "ar"
            env["CARGO_TARGET_" + args.target.upper().replace("-", "_") + "_LINKER"] = "musl-gcc"
        manifest["build_environment"] = {
            key: value for key, value in sorted(env.items())
            if key.startswith(("CARGO_TARGET_", "CC_", "AR_")) or key in {
                "CARGO_INCREMENTAL", "CARGO_PROFILE_RELEASE_STRIP", "CARGO_TERM_COLOR",
            }
        }
        rustc, _ = execute(["rustc", "--version", "--verbose"], ROOT, env,
                           output, manifest, "rustc-version")
        cargo, _ = execute(["cargo", "--version"], ROOT, env,
                           output, manifest, "cargo-version")
        manifest.update(rustc=rustc.strip(), cargo=cargo.strip())
        common = ["--locked", "--workspace", "--release", "--target", args.target,
                  "--no-default-features", "--features", args.profile]
        built, _ = execute(["cargo", "build", *common, "--bin", "mosdns-rs",
                            "--message-format=json-render-diagnostics"],
                           ROOT, env, output, manifest, "cargo-build")
        production = [entry for entry in artifacts(built)
                      if entry["target"]["name"] == "mosdns-rs"
                      and not entry["profile"].get("test")]
        if len(production) != 1:
            raise BuildError("expected one production CLI Cargo artifact")
        production_path = output / "bin" / "mosdns-rs"
        copy(Path(production[0]["executable"]), production_path)
        binaries["bin/mosdns-rs"] = {
            "role": "production_cli", "package_id": production[0]["package_id"],
            "target_name": "mosdns-rs", "target_kind": production[0]["target"]["kind"],
            "cargo_executable": production[0]["executable"],
        }
        manifest["production_cli"] = "bin/mosdns-rs"
        version, _ = execute([str(production_path), "version"], ROOT, env,
                             output, manifest, "production-version")
        manifest["production_version"] = version.strip()
        test_json, _ = execute(["cargo", "test", *common, "--no-run",
                               "--message-format=json-render-diagnostics"],
                              ROOT, env, output, manifest, "cargo-test-no-run")
        for name, value in generated.items():
            expected = {key: value[key] for key in ("bytes", "sha256")}
            if record(ROOT / name) != expected:
                raise BuildError("generated TLS fixture changed during compilation: " + name)
        for name, value in generated.items():
            if value["kind"] == "private_key":
                (ROOT / name).unlink()
        manifest["compile_only_private_key_files_removed"] = True
        (output / "cargo-test.jsonl").write_text(test_json)
        test_cli_path = target_dir / args.target / "release" / "mosdns-rs"
        if test_cli_path.is_file():
            copy(test_cli_path, output / "bin" / "mosdns-rs-test-build")
            binaries["bin/mosdns-rs-test-build"] = {"role": "test_cli"}
        seen = set()
        harnesses = []
        for entry in artifacts(test_json):
            if not entry["profile"].get("test") or entry["executable"] in seen:
                continue
            seen.add(entry["executable"])
            source = Path(entry["executable"])
            name = f"harnesses/{entry['target']['name']}/{source.name}"
            destination = output / name
            copy(source, destination)
            binaries[name] = {
                "role": "test_harness", "package_id": entry["package_id"],
                "test": True,
                "target_name": entry["target"]["name"],
                "target_kind": entry["target"]["kind"],
                "test_target": "lib" if "lib" in entry["target"]["kind"] else entry["target"]["name"],
                "test_kind": entry["target"]["kind"],
                "cargo_executable": entry["executable"],
            }
            harnesses.append(name)
        if not harnesses:
            raise BuildError("cargo test produced no runnable test harnesses")
        env.update(MOSDNS_TEST_BINARY=str(production_path),
                   MOSDNS_RS_TEST_BIN=str(production_path))
        manifest["ordinary_test_runs"] = []
        for index, name in enumerate(sorted(harnesses)):
            path = output / name
            label = f"harness-{index:02d}"
            listed, _ = execute([str(path), "--list", "--format", "terse"],
                                output / "runtime-source", env, output, manifest,
                                label + "-list")
            ignored, _ = execute([str(path), "--list", "--ignored", "--format", "terse"],
                                 output / "runtime-source", env, output, manifest,
                                 label + "-ignored")
            listing_name = f"tests/{label}-list.txt"
            ignored_name = f"tests/{label}-ignored.txt"
            (output / listing_name).write_text(listed)
            (output / ignored_name).write_text(ignored)
            binaries[name].update(tests_all=names(listed), tests_ignored=names(ignored),
                                  listing=listing_name, ignored_listing=ignored_name)
            if not set(names(ignored)).issubset(names(listed)):
                raise BuildError("ignored test listing differs from full listing")
            tested, command = execute([str(path), "--test-threads=1"],
                                      output / "runtime-source", env, output,
                                      manifest, label + "-run")
            summary = re.search(
                r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", tested)
            if not summary:
                raise BuildError("test harness omitted an ordinary test summary: " + name)
            passed, failed, skipped = map(int, summary.groups())
            if failed or passed + skipped != len(names(listed)) or skipped != len(names(ignored)):
                raise BuildError("test counts do not match actual --list baseline: " + name)
            manifest["ordinary_test_runs"].append({
                "harness": name, "passed": passed, "failed": failed, "ignored": skipped,
                "stdout": command["stdout"], "stderr": command["stderr"], "exit_code": 0,
            })
        if args.target.endswith("-linux-musl"):
            for index, name in enumerate(sorted(binaries)):
                if binaries[name]["role"] not in {"production_cli", "test_cli", "test_harness"}:
                    continue
                headers, _ = execute(["readelf", "--program-headers", str(output / name)],
                                     ROOT, env, output, manifest, f"elf-{index:02d}")
                if re.search(r"\bINTERP\b", headers):
                    raise BuildError("Linux artifact requires a dynamic interpreter: " + name)
                binaries[name]["static_elf"] = True
        if inputs() != original:
            raise BuildError("source inputs changed during compilation/testing")
        manifest.update(status="complete", completed_at=now(),
                        files=describe_files(output, binaries, original, generated))
        manifest_write(output, manifest)
        print(f"Completed {args.target}/{args.profile}: {len(harnesses)} harnesses", flush=True)
        return 0
    except (BuildError, OSError, subprocess.SubprocessError) as error:
        manifest.update(status="failed", completed_at=now(), error=safe_text(str(error)))
        if "source_inputs" in manifest:
            manifest["files"] = describe_files(output, binaries, manifest["source_inputs"],
                                               manifest.get("generated_test_inputs", {}))
        manifest_write(output, manifest)
        print("Build failed:", error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
