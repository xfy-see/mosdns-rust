#!/usr/bin/env python3
"""Build frozen, stripped Rust full/minimal profiles offline without deployment."""

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import uuid
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGETS = ("native", "aarch64-unknown-linux-musl", "x86_64-unknown-linux-musl")
WRAPPERS = (
    "benchmarks/cc-musl.sh", "benchmarks/cc-x86-musl.sh",
    "benchmarks/ar-musl.sh",
)
EXCLUDED_DIRECTORIES = {".git", ".build", "target", "__pycache__", ".pytest_cache"}
ENVIRONMENT_WHITELIST = (
    "CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN", "RUSTUP_AUTO_INSTALL",
    "RUSTC", "CARGO_NET_OFFLINE", "CARGO_INCREMENTAL", "CARGO_BUILD_JOBS",
    "CARGO_TARGET_DIR", "CARGO_PROFILE_RELEASE_STRIP", "CARGO_ENCODED_RUSTFLAGS",
    "MOSDNS_ZIG", "ZIG_GLOBAL_CACHE_DIR", "ZIG_LOCAL_CACHE_DIR",
)


class BuildError(RuntimeError):
    pass


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_record(path):
    if path.is_symlink() or not path.is_file():
        raise BuildError("input is not a regular file: " + str(path))
    data = path.read_bytes()
    return dict(bytes=len(data), sha256=digest(data))


def walk_files(root):
    if root.is_symlink() or not root.is_dir():
        raise BuildError("input directory is not a regular directory: " + str(root))
    for directory, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = sorted(d for d in directories if d not in EXCLUDED_DIRECTORIES)
        for name in directories:
            if (pathlib.Path(directory) / name).is_symlink():
                raise BuildError("symlink directory in inputs: " + str(directory))
        for name in sorted(filenames):
            if name != ".DS_Store":
                yield pathlib.Path(directory) / name


def source_inputs(root):
    paths = [root / name for name in ("Cargo.toml", "Cargo.lock")]
    paths.extend(walk_files(root / "rust"))
    paths.extend(walk_files(root / "tests/fixtures"))
    paths.extend(root / name for name in WRAPPERS)
    paths.append(root / "benchmarks/build-rust-profiles.py")
    return {
        path.relative_to(root).as_posix(): file_record(path)
        for path in sorted(set(paths))
    }


def snapshot_inputs(snapshot):
    result = {}
    for directory, directories, filenames in os.walk(snapshot, followlinks=False):
        for name in directories:
            if (pathlib.Path(directory) / name).is_symlink():
                raise BuildError("symlink introduced into snapshot")
        for name in filenames:
            path = pathlib.Path(directory) / name
            result[path.relative_to(snapshot).as_posix()] = file_record(path)
    return result


def difference(actual, expected):
    return dict(
        added=sorted(set(actual) - set(expected)),
        removed=sorted(set(expected) - set(actual)),
        changed=sorted(k for k in set(actual) & set(expected) if actual[k] != expected[k]),
    )


def validate_inputs(snapshot, expected):
    for label, actual in (
        ("original", source_inputs(ROOT)), ("snapshot", snapshot_inputs(snapshot)),
    ):
        if actual != expected:
            raise BuildError(label + " inputs changed: " + json.dumps(difference(actual, expected)))


def freeze_inputs(snapshot, expected):
    snapshot.mkdir(mode=0o700)
    for name, record in expected.items():
        data = (ROOT / name).read_bytes()
        if dict(bytes=len(data), sha256=digest(data)) != record:
            raise BuildError("input changed while freezing: " + name)
        target = snapshot / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)
        target.chmod(0o555 if name in WRAPPERS else 0o444)
    validate_inputs(snapshot, expected)


def write_manifest(output, manifest):
    temporary = output / "manifest.json.tmp"
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    temporary.replace(output / "manifest.json")


def executable(value):
    found = shutil.which(str(value))
    if found is None:
        raise BuildError("executable not found: " + str(value))
    # Keep a rustup shim's invocation name (rustc/cargo), rather than invoking
    # its resolved rustup binary as if it were the requested tool.
    return pathlib.Path(found).absolute()


def tool_record(path):
    resolved = path.resolve()
    return dict(path=str(path), resolved_path=str(resolved), **file_record(resolved))


def safe_output(text):
    return re.sub(r"(https?://)[^/\s@]+@", r"\1<redacted>@", text)


def environment_record(env):
    keys = set(ENVIRONMENT_WHITELIST)
    keys.update(k for k in env if re.fullmatch(
        r"(?:CC|AR)_(?:aarch64|x86_64)_unknown_linux_musl|"
        r"CARGO_TARGET_(?:AARCH64|X86_64)_UNKNOWN_LINUX_MUSL_LINKER", k))
    return {k: env[k] for k in sorted(keys) if k in env}


def run(command, cwd, env, log, output, manifest):
    validate_inputs(cwd, manifest["inputs"])
    record = dict(command=command, cwd=str(cwd), started_at=now(),
                  environment=environment_record(env), log=log)
    manifest["commands"].append(record)
    write_manifest(output, manifest)
    try:
        result = subprocess.run(command, cwd=str(cwd), env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, encoding="utf-8",
                                errors="replace")
    except BaseException as error:
        record.update(finished_at=now(), error=safe_output(repr(error)))
        write_manifest(output, manifest)
        raise
    text = safe_output(result.stdout)
    if result.stderr:
        text += "\n[stderr]\n" + safe_output(result.stderr)
    (output / log).write_text(text)
    record.update(finished_at=now(), exit_code=result.returncode,
                  log_sha256=digest(text.encode()))
    write_manifest(output, manifest)
    validate_inputs(cwd, manifest["inputs"])
    if result.returncode:
        raise BuildError("command failed (%s): see %s" % (result.returncode, log))
    return result.stdout


def build_environment():
    env = os.environ.copy()
    # Source Cargo profiles define optimization/LTO/panic. Do not inherit
    # alternate profile flags, build destinations or compiler wrappers.
    for key in list(env):
        if key.startswith("CARGO_PROFILE_RELEASE_") or key in {
            "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS",
            "CARGO_BUILD_TARGET", "CARGO_TARGET_DIR", "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
        }:
            del env[key]
    env.update(CARGO_NET_OFFLINE="true", RUSTUP_AUTO_INSTALL="0",
               CARGO_INCREMENTAL="0", CARGO_PROFILE_RELEASE_STRIP="symbols",
               CARGO_ENCODED_RUSTFLAGS="", RUSTC_WRAPPER="", RUSTC_WORKSPACE_WRAPPER="")
    return env


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGETS, default="native")
    parser.add_argument("--profile", choices=("full", "minimal", "both"), default="both")
    parser.add_argument("--output", type=pathlib.Path, help="new exclusive output directory")
    parser.add_argument("--zig", help="existing Zig executable; required for Linux musl targets")
    parser.add_argument("--rust-lld", help="existing rust-lld executable; otherwise use rustc sysroot")
    return parser.parse_args(argv)


def main(argv=None):
    args = arguments(argv)
    requested = args.output or ROOT / ".build" / (
        "rust-profiles-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-" + uuid.uuid4().hex[:8])
    if requested.exists() or requested.is_symlink():
        print("output already exists: " + str(requested), file=sys.stderr)
        return 2
    output = requested.resolve()
    for source in (ROOT / "rust", ROOT / "tests/fixtures"):
        if output == source or source in output.parents:
            print("output must be outside frozen input directories", file=sys.stderr)
            return 2
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        output.mkdir(mode=0o700)
    except FileExistsError:
        print("output already exists: " + str(output), file=sys.stderr)
        return 2
    manifest = dict(schema_version=1, status="preparing", started_at=now(),
                    source_root=str(ROOT), output=str(output), requested_target=args.target,
                    requested_profile=args.profile, commands=[], tools={}, profiles={},
                    network_access="Cargo offline; automatic rustup installation disabled",
                    deployed=False, compressed=False)
    write_manifest(output, manifest)
    snapshot = output / "snapshot"
    try:
        expected = source_inputs(ROOT)
        manifest["inputs"] = expected
        manifest["input_tree_sha256"] = digest(json.dumps(
            expected, sort_keys=True, separators=(",", ":")).encode())
        freeze_inputs(snapshot, expected)
        env = build_environment()
        cargo = executable("cargo")
        rustc = executable(env.get("RUSTC", "rustc"))
        env["RUSTC"] = str(rustc)
        for name, path in (("cargo", cargo), ("rustc", rustc)):
            manifest["tools"][name] = tool_record(path)
        cargo_version = run([str(cargo), "--version"], snapshot, env, "cargo-version.log",
                            output, manifest).strip()
        rustc_version = run([str(rustc), "-vV"], snapshot, env, "rustc-version.log",
                            output, manifest).strip()
        manifest["tools"]["cargo"]["version"] = cargo_version
        manifest["tools"]["rustc"]["version"] = rustc_version
        host = re.search(r"^host:\s*(\S+)$", rustc_version, re.MULTILINE)
        if host is None:
            raise BuildError("rustc did not report its host target")
        target = host.group(1) if args.target == "native" else args.target
        manifest["target"] = target
        sysroot = run([str(rustc), "--print", "sysroot"], snapshot, env,
                      "rustc-sysroot.log", output, manifest).strip()
        manifest["tools"]["rustc"]["sysroot"] = sysroot
        # The bundled macOS LLVM tools require the installed toolchain library
        # directory even when rustc itself has a working embedded rpath.
        if sys.platform == "darwin":
            env["DYLD_LIBRARY_PATH"] = str(pathlib.Path(sysroot) / "lib")
            llvm = pathlib.Path(sysroot) / "lib/libLLVM.dylib"
            if llvm.is_file():
                manifest["tools"]["llvm_shared_library"] = tool_record(llvm)
        # A rustup shim is not the compiler payload. Record installed payloads
        # when the reported sysroot supplies them as well as invocation paths.
        for name in ("rustc", "cargo"):
            payload = pathlib.Path(sysroot) / "bin" / name
            if payload.is_file():
                manifest["tools"][name + "_sysroot_payload"] = tool_record(payload)
        if args.target != "native":
            zig = executable(args.zig or env.get("MOSDNS_ZIG", "zig"))
            manifest["tools"]["zig"] = tool_record(zig)
            manifest["tools"]["zig"]["version"] = run(
                [str(zig), "version"], snapshot, env, "zig-version.log", output, manifest).strip()
            lld = executable(args.rust_lld or str(
                pathlib.Path(sysroot) / "lib/rustlib" / host.group(1) / "bin/rust-lld"))
            manifest["tools"]["rust-lld"] = tool_record(lld)
            manifest["tools"]["rust-lld"]["version"] = run(
                [str(lld), "-flavor", "gnu", "--version"], snapshot, env,
                "rust-lld-version.log", output, manifest).strip()
            arch = "aarch64" if target.startswith("aarch64") else "x86_64"
            suffix = target.replace("-", "_")
            env["MOSDNS_ZIG"] = str(zig)
            env["CC_" + suffix] = str(snapshot / (
                "benchmarks/cc-musl.sh" if arch == "aarch64" else "benchmarks/cc-x86-musl.sh"))
            env["AR_" + suffix] = str(snapshot / "benchmarks/ar-musl.sh")
            env["CARGO_TARGET_" + suffix.upper() + "_LINKER"] = str(lld)
            env["CARGO_ENCODED_RUSTFLAGS"] = "-C\x1flinker-flavor=ld.lld"
            env["ZIG_GLOBAL_CACHE_DIR"] = str(output / "zig-global-cache")
            env["ZIG_LOCAL_CACHE_DIR"] = str(output / "zig-local-cache")
        profiles = ("full", "minimal") if args.profile == "both" else (args.profile,)
        manifest["status"] = "building"
        for profile in profiles:
            validate_inputs(snapshot, expected)
            profile_env = dict(env, CARGO_TARGET_DIR=str(output / ("target-" + profile)))
            feature_args = ["--no-default-features", "--features", profile]
            common = ["-p", "mosdns-rs", "--locked", "--offline", "--target", target]
            tree_command = [str(cargo), "tree"] + common + feature_args + [
                "--edges", "normal,build", "--format", "{p} {f}"]
            tree = run(tree_command, snapshot, profile_env, profile + "-dependencies.log",
                       output, manifest)
            validate_inputs(snapshot, expected)
            tree_file = output / (profile + "-dependencies.txt")
            tree_file.write_text(tree)
            entry = dict(features=[profile], default_features=False,
                         target_directory=profile_env["CARGO_TARGET_DIR"],
                         dependency_tree=dict(file=tree_file.name, **file_record(tree_file)),
                         environment=environment_record(profile_env))
            manifest["profiles"][profile] = entry
            command = [str(cargo), "build"] + common + feature_args + [
                "--release", "--bin", "mosdns-rs", "--message-format=json"]
            raw = run(command, snapshot, profile_env, profile + "-build.log", output, manifest)
            validate_inputs(snapshot, expected)
            json_file = output / (profile + "-cargo-artifacts.jsonl")
            json_file.write_text(raw)
            artifacts = [json.loads(line) for line in raw.splitlines() if line.strip()]
            candidates = {
                item["executable"] for item in artifacts
                if item.get("reason") == "compiler-artifact" and item.get("executable")
                and item.get("target", {}).get("name") == "mosdns-rs"
                and "bin" in item.get("target", {}).get("kind", [])
                and item.get("profile", {}).get("test") is False
            }
            if len(candidates) != 1:
                raise BuildError("Cargo did not report one production CLI for " + profile)
            source = pathlib.Path(next(iter(candidates)))
            if pathlib.Path(profile_env["CARGO_TARGET_DIR"]) not in source.resolve().parents:
                raise BuildError("Cargo executable is outside this profile's target directory")
            record = file_record(source)
            destination = output / ("mosdns-rs-" + profile + "-" + target
                                    + (".exe" if "windows" in target else ""))
            with destination.open("xb") as stream:
                stream.write(source.read_bytes())
            destination.chmod(0o755)
            if file_record(destination) != record:
                raise BuildError("copied executable differs from Cargo artifact")
            entry.update(binary=dict(file=destination.name, **record),
                         cargo_artifacts=dict(file=json_file.name, **file_record(json_file)),
                         completed_at=now(), status="complete")
            write_manifest(output, manifest)
        validate_inputs(snapshot, expected)
        if run([str(cargo), "--version"], snapshot, env, "cargo-version-after.log",
               output, manifest).strip() != cargo_version:
            raise BuildError("Cargo version changed during build")
        if run([str(rustc), "-vV"], snapshot, env, "rustc-version-after.log",
               output, manifest).strip() != rustc_version:
            raise BuildError("Rust compiler version changed during build")
        for name, tool in manifest["tools"].items():
            if tool_record(pathlib.Path(tool["path"])) != {
                key: tool[key] for key in ("path", "resolved_path", "bytes", "sha256")
            }:
                raise BuildError("tool executable changed during build: " + name)
        manifest.update(status="complete", completed_at=now(),
                        original_inputs_unchanged=True, snapshot_inputs_unchanged=True)
        write_manifest(output, manifest)
        print(str(output / "manifest.json"))
        return 0
    except (Exception, KeyboardInterrupt) as error:
        manifest.update(status="failed", failed_at=now(), error=safe_output(repr(error)))
        write_manifest(output, manifest)
        print("build failed; evidence retained at " + str(output / "manifest.json"),
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
