#!/usr/bin/env python3
"""Generate one-run mock TLS fixtures only on a GitHub Actions runner."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
BASE = "rust/src/pkg/upstream/fixtures/"
GENERATED = {
    BASE + "localhost-cert.der": "public_certificate",
    BASE + "localhost-key.der": "private_key",
    BASE + "system-trust/ca.pem": "public_certificate",
    BASE + "system-trust/server-cert.der": "public_certificate",
    BASE + "system-trust/server-key.der": "private_key",
    BASE + "system-trust/untrusted-ca.pem": "public_certificate",
}
REPORT = ROOT / ".artifacts/generated-test-fixtures.json"

# These identities are part of the existing negative TLS tests. In particular,
# system_trust's wrong-name probe uses localhost and must reject that name.
LOCAL_EXTENSIONS = """[leaf]
basicConstraints = critical,CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = DNS:dns.test.invalid,IP:127.0.0.1
"""
SERVER_EXTENSIONS = """[leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = DNS:dns.test.invalid,IP:192.0.2.1,IP:127.0.0.1
"""
CA_EXTENSIONS = """[ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
"""


class FixtureError(RuntimeError):
    pass


def tree_digest(inputs):
    text = "".join(f"{name}\0{value['bytes']}\0{value['sha256']}\n"
                   for name, value in sorted(inputs.items()))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def file_record(path, kind):
    if path.is_symlink() or not path.is_file():
        raise FixtureError("fixture must be a regular file: " + str(path))
    data = path.read_bytes()
    return {
        "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
        "kind": kind, "packaged": kind == "public_certificate",
    }


def openssl_executable():
    requested = os.environ.get("OPENSSL_EXECUTABLE")
    if requested:
        if not Path(requested).is_file():
            raise FixtureError("OPENSSL_EXECUTABLE is not a file")
        return requested
    executable = shutil.which("openssl")
    if executable:
        return executable
    if os.name == "nt":
        executable = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/usr/bin/openssl.exe"
        if executable.is_file():
            return str(executable)
    raise FixtureError("OpenSSL is required on the GitHub runner")


def openssl(executable, *arguments):
    result = subprocess.run([executable, *map(str, arguments)], capture_output=True,
                            text=True, encoding="utf-8", errors="replace")
    if result.returncode:
        # Never relay OpenSSL stdout/stderr: a command's behavior may change and
        # include private material. Keep error diagnostics to command and status.
        raise FixtureError(f"OpenSSL {arguments[0]} failed with status {result.returncode}")
    return result.stdout


def key(executable, path):
    openssl(executable, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", path)
    path.chmod(0o600)


def request(executable, key_path, csr_path, common_name):
    openssl(executable, "req", "-new", "-sha256", "-key", key_path,
            "-subj", "/CN=" + common_name, "-out", csr_path)


def certificate(executable, csr_path, destination, extensions, serial, *signing):
    openssl(executable, "x509", "-req", "-in", csr_path, "-sha256", "-days", "365",
            "-set_serial", serial, "-extfile", extensions, "-extensions",
            "ca" if extensions.name == "ca.cnf" else "leaf", *signing, "-out", destination)


def generate():
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise FixtureError("test fixture generation is restricted to GitHub Actions")
    if REPORT.exists() or REPORT.is_symlink():
        raise FixtureError("fixture metadata already exists; start a fresh runner job")
    tracked = set(subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0"))
    if tracked.intersection(GENERATED):
        raise FixtureError("generated fixtures must never be tracked in Git")
    if any((ROOT / name).exists() or (ROOT / name).is_symlink() for name in GENERATED):
        raise FixtureError("fixture paths already exist; refusing to reuse or replace any old key")
    executable = openssl_executable()
    version = openssl(executable, "version").strip()
    old_umask = os.umask(0o077)
    created = []
    try:
        with tempfile.TemporaryDirectory(prefix="mosdns-ci-tls-", dir=os.environ.get("RUNNER_TEMP")) as directory:
            temporary = Path(directory)
            temporary.chmod(0o700)
            for name, contents in (("local.cnf", LOCAL_EXTENSIONS),
                                   ("server.cnf", SERVER_EXTENSIONS), ("ca.cnf", CA_EXTENSIONS)):
                (temporary / name).write_text(contents)
            local_key = temporary / "local-key.pem"
            ca_key = temporary / "ca-key.pem"
            server_key = temporary / "server-key.pem"
            other_key = temporary / "other-key.pem"
            for path in (local_key, ca_key, server_key, other_key):
                key(executable, path)
            for label, private, common_name in (
                ("local", local_key, "dns.test.invalid"),
                ("ca", ca_key, "mosdns one-run mock CA"),
                ("server", server_key, "dns.test.invalid"),
                ("other", other_key, "mosdns unrelated one-run mock CA"),
            ):
                request(executable, private, temporary / (label + ".csr"), common_name)
            serial = "0x" + os.urandom(16).hex()
            certificate(executable, temporary / "ca.csr", temporary / "ca.pem",
                        temporary / "ca.cnf", serial, "-signkey", ca_key)
            certificate(executable, temporary / "other.csr", temporary / "other.pem",
                        temporary / "ca.cnf", "0x" + os.urandom(16).hex(), "-signkey", other_key)
            certificate(executable, temporary / "local.csr", temporary / "local.pem",
                        temporary / "local.cnf", "0x" + os.urandom(16).hex(), "-signkey", local_key)
            certificate(executable, temporary / "server.csr", temporary / "server.pem",
                        temporary / "server.cnf", "0x" + os.urandom(16).hex(),
                        "-CA", temporary / "ca.pem", "-CAkey", ca_key)
            openssl(executable, "verify", "-CAfile", temporary / "ca.pem", temporary / "server.pem")
            destinations = {
                "local.pem": BASE + "localhost-cert.der",
                "server.pem": BASE + "system-trust/server-cert.der",
                "local-key.pem": BASE + "localhost-key.der",
                "server-key.pem": BASE + "system-trust/server-key.der",
            }
            for source, name in destinations.items():
                target = ROOT / name
                target.parent.mkdir(parents=True, exist_ok=True)
                created.append(target)
                if GENERATED[name] == "private_key":
                    openssl(executable, "pkcs8", "-topk8", "-nocrypt", "-in", temporary / source,
                            "-outform", "DER", "-out", target)
                    target.chmod(0o600)
                else:
                    openssl(executable, "x509", "-in", temporary / source, "-outform", "DER", "-out", target)
                    target.chmod(0o644)
            for source, name in (("ca.pem", BASE + "system-trust/ca.pem"),
                                 ("other.pem", BASE + "system-trust/untrusted-ca.pem")):
                target = ROOT / name
                created.append(target)
                shutil.copyfile(temporary / source, target)
                target.chmod(0o644)
            generated = {name: file_record(ROOT / name, kind) for name, kind in sorted(GENERATED.items())}
        # CA signing keys, PEM leaf keys, CSRs, and temporary PEM certificates
        # have all been removed before writing a public metadata-only record.
        REPORT.parent.mkdir(parents=True, exist_ok=True)
        REPORT.write_text(json.dumps({
            "schema_version": 1, "generated_at": datetime.now(timezone.utc).isoformat(),
            "method": "fresh one-run OpenSSL RSA-2048; SHA-256 X509; PKCS8 DER leaf keys",
            "openssl": version, "ca_signing_keys_removed": True,
            "generated_test_inputs": generated,
            "generated_test_tree_sha256": tree_digest(generated),
        }, indent=2, sort_keys=True) + "\n")
        print("Generated 4 public mock certificates and 2 one-run compile-only keys; no key material logged")
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    finally:
        os.umask(old_umask)


def remove_private_keys():
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise FixtureError("test fixture cleanup is restricted to GitHub Actions")
    if not REPORT.is_file():
        return
    generated = json.loads(REPORT.read_text())["generated_test_inputs"]
    for name, kind in GENERATED.items():
        if kind != "private_key":
            continue
        path = ROOT / name
        if not path.exists() and not path.is_symlink():
            continue
        if file_record(path, kind) != generated.get(name):
            raise FixtureError("refusing to remove an unbound private fixture: " + name)
        path.unlink()
    print("Removed one-run compile-only private fixture files")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remove-private-keys", action="store_true",
                        help="after compilation, delete only bound one-run private fixture files")
    args = parser.parse_args()
    try:
        if args.remove_private_keys:
            remove_private_keys()
        else:
            generate()
    except (FixtureError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("Fixture generation failed:", error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
