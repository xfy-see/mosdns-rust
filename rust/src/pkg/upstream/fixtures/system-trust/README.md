The files referenced by Rust tests in this directory are generated temporarily
in GitHub Actions before compilation. Fixed certificate/private-key blobs are
not tracked in this independent repository. Their include paths remain unchanged
so the Rust implementation and test source do not need to embed old keys.

`ci/generate-test-fixtures.py` runs only with `GITHUB_ACTIONS=true` and no
arguments. CI generates a fresh CA, an unrelated untrusted CA, and a server certificate/key
for the local mock tests. Required identities include `dns.test.invalid`,
`localhost`, `192.0.2.1`, and `127.0.0.1`; the generator supplies the appropriate
SANs and validity window. Do not install the test CA in a system trust store or
use any of this material for a real service.

The six generated certificate/key paths are excluded from Git. The two DER
private-key files are deleted after compilation and never packaged separately in
`runtime-source/` or downloadable artifacts. Four public test certificates may be
packaged for runtime validation. CA private keys only exist in the generator's
temporary directory. Generated-file paths, byte sizes, SHA-256 values, and
generation metadata are recorded separately as `generated_test_inputs`, outside
the Git-tracked source manifest. Private-key contents are not logged or uploaded.

Test harnesses embed only this run's disposable localhost mock material. Local
validation runs the verified harness from the matching GitHub build and does not
regenerate keys or install a Rust toolchain. The integration test uses isolated
processes with temporary `SSL_CERT_FILE` / `SSL_CERT_DIR` paths.
