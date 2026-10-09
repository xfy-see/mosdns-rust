// Copyright (C) 2020-2022, IrineSistiana
// SPDX-License-Identifier: GPL-3.0-or-later

//! Native trust roots are shared by every DNS TLS client. Like Go's system
//! roots, this snapshot is loaded once per process; restarting reloads it.

use anyhow::{anyhow, bail, Result};
use std::sync::{Arc, OnceLock};

static SYSTEM_ROOTS: OnceLock<std::result::Result<Arc<rustls::RootCertStore>, String>> =
    OnceLock::new();

pub(super) fn system_roots() -> Result<Arc<rustls::RootCertStore>> {
    SYSTEM_ROOTS
        .get_or_init(|| {
            roots_from_result(load_system_certificates())
                .map(Arc::new)
                .map_err(|error| format!("{error:#}"))
        })
        .clone()
        .map_err(|error| anyhow!(error))
}

#[cfg(not(target_os = "linux"))]
fn load_system_certificates() -> rustls_native_certs::CertificateResult {
    rustls_native_certs::load_native_certs()
}

#[cfg(target_os = "linux")]
fn load_system_certificates() -> rustls_native_certs::CertificateResult {
    use std::path::PathBuf;
    // Go crypto/x509/root_linux.go: stop at the first readable file and scan
    // every default directory. Each nonempty environment variable replaces
    // only its own list, so SSL_CERT_FILE retains the default directories.
    let files: Vec<_> = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/pki/tls/cacert.pem",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/etc/ssl/cert.pem",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect();
    let dirs: Vec<_> = ["/etc/ssl/certs", "/etc/pki/tls/certs"]
        .into_iter()
        .map(PathBuf::from)
        .collect();
    linux_paths::Paths::select(
        &files,
        &dirs,
        std::env::var_os("SSL_CERT_FILE"),
        std::env::var_os("SSL_CERT_DIR"),
    )
    .load()
}

#[cfg(any(target_os = "linux", all(test, unix)))]
mod linux_paths {
    use rustls_native_certs::{CertificateResult, Error, ErrorKind};
    use std::{ffi::OsString, io::ErrorKind as IoErrorKind, path::PathBuf};

    pub(super) struct Paths {
        pub(super) files: Vec<PathBuf>,
        pub(super) dirs: Vec<PathBuf>,
    }

    impl Paths {
        pub(super) fn select(
            files: &[PathBuf],
            dirs: &[PathBuf],
            cert_file: Option<OsString>,
            cert_dirs: Option<OsString>,
        ) -> Self {
            Self {
                files: match cert_file.filter(|value| !value.is_empty()) {
                    Some(file) => vec![file.into()],
                    None => files.to_vec(),
                },
                dirs: match cert_dirs.filter(|value| !value.is_empty()) {
                    Some(dirs) => std::env::split_paths(&dirs).collect(),
                    None => dirs.to_vec(),
                },
            }
        }

        pub(super) fn load(&self) -> CertificateResult {
            let mut result = CertificateResult::default();
            for path in &self.files {
                match std::fs::read(path) {
                    Ok(contents) => {
                        for cert in rustls_pemfile::certs(&mut contents.as_slice()) {
                            match cert {
                                Ok(cert) => result.certs.push(cert),
                                Err(error) => result.errors.push(Error {
                                    context: "failed to read PEM certificate",
                                    kind: ErrorKind::Io {
                                        inner: error,
                                        path: path.clone(),
                                    },
                                }),
                            }
                        }
                        // A readable empty/malformed file also ends this scan,
                        // exactly as Go's AppendCertsFromPEM does.
                        break;
                    }
                    Err(error) if error.kind() == IoErrorKind::NotFound => {}
                    Err(error) => result.errors.push(Error {
                        context: "failed to read system CA file",
                        kind: ErrorKind::Io {
                            inner: error,
                            path: path.clone(),
                        },
                    }),
                }
            }
            for path in &self.dirs {
                let loaded = rustls_native_certs::load_certs_from_paths(None, Some(path));
                result.certs.extend(loaded.certs);
                result.errors.extend(loaded.errors.into_iter().filter(|error| {
                    !matches!(&error.kind, ErrorKind::Io { inner, .. } if inner.kind() == IoErrorKind::NotFound)
                }));
            }
            result
                .certs
                .sort_unstable_by(|a, b| a.as_ref().cmp(b.as_ref()));
            result.certs.dedup();
            result
        }
    }
}

fn roots_from_result(
    result: rustls_native_certs::CertificateResult,
) -> Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    let mut errors: Vec<_> = result.errors.iter().map(ToString::to_string).collect();
    for certificate in result.certs {
        if let Err(error) = roots.add(certificate) {
            errors.push(format!("unusable root certificate: {error}"));
        }
    }
    if roots.is_empty() {
        bail!(
            "system TLS trust: no usable CA certificates{}",
            if errors.is_empty() {
                String::new()
            } else {
                format!(": {}", errors.join("; "))
            }
        );
    }
    // Native stores can include old/malformed certificates. Retain usable
    // roots, report skipped entries, and never fall back to bundled roots.
    for error in errors {
        eprintln!("system TLS trust: skipped {error}");
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use linux_paths::Paths;
    #[cfg(unix)]
    use std::path::PathBuf;

    #[cfg(unix)]
    #[test]
    fn linux_environment_overrides_only_its_own_default_path_list() {
        let files = vec![PathBuf::from("default-file")];
        let dirs = vec![PathBuf::from("default-dir")];
        let file_only = Paths::select(&files, &dirs, Some("override-file".into()), None);
        assert_eq!(file_only.files, vec![PathBuf::from("override-file")]);
        assert_eq!(file_only.dirs, dirs);
        let dir_only = Paths::select(&files, &dirs, None, Some("one:two".into()));
        assert_eq!(dir_only.files, files);
        assert_eq!(
            dir_only.dirs,
            vec![PathBuf::from("one"), PathBuf::from("two")]
        );
        let empty = Paths::select(&files, &dirs, Some("".into()), Some("".into()));
        assert_eq!(empty.files, files);
        assert_eq!(empty.dirs, dirs);
    }

    #[cfg(unix)]
    #[test]
    fn linux_loader_stops_at_first_readable_file_and_scans_all_directories() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("empty.pem");
        let second = temp.path().join("valid.pem");
        let dir_one = temp.path().join("one");
        let dir_two = temp.path().join("two");
        std::fs::write(&first, b"").unwrap();
        std::fs::write(&second, include_bytes!("fixtures/system-trust/ca.pem")).unwrap();
        std::fs::create_dir(&dir_one).unwrap();
        std::fs::create_dir(&dir_two).unwrap();
        std::fs::write(
            dir_one.join("ca.pem"),
            include_bytes!("fixtures/system-trust/ca.pem"),
        )
        .unwrap();
        std::fs::write(
            dir_two.join("other-ca.pem"),
            include_bytes!("fixtures/system-trust/untrusted-ca.pem"),
        )
        .unwrap();
        let mut paths = Paths {
            files: vec![temp.path().join("missing.pem"), first, second],
            dirs: Vec::new(),
        };
        let loaded = paths.load();
        assert!(loaded.certs.is_empty());
        assert!(loaded.errors.is_empty());
        paths.dirs = vec![temp.path().join("missing-dir"), dir_one, dir_two];
        let loaded = paths.load();
        assert!(loaded.errors.is_empty());
        assert_eq!(roots_from_result(loaded).unwrap().len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn linux_loader_deduplicates_file_and_directory_certificates() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("ca.pem");
        std::fs::write(&file, include_bytes!("fixtures/system-trust/ca.pem")).unwrap();
        let loaded = Paths {
            files: vec![file],
            dirs: vec![temp.path().to_owned()],
        }
        .load();
        assert_eq!(loaded.certs.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn linux_single_environment_override_retains_other_default_roots() {
        let temp = tempfile::tempdir().unwrap();
        let default_file = temp.path().join("default.pem");
        let default_dir = temp.path().join("default-dir");
        let override_file = temp.path().join("override.pem");
        let override_dir = temp.path().join("override-dir");
        std::fs::create_dir(&default_dir).unwrap();
        std::fs::create_dir(&override_dir).unwrap();
        for file in [&default_file, &default_dir.join("ca.pem")] {
            std::fs::write(file, include_bytes!("fixtures/system-trust/ca.pem")).unwrap();
        }
        for file in [&override_file, &override_dir.join("ca.pem")] {
            std::fs::write(
                file,
                include_bytes!("fixtures/system-trust/untrusted-ca.pem"),
            )
            .unwrap();
        }
        let files = vec![default_file];
        let dirs = vec![default_dir];
        let file_only = Paths::select(&files, &dirs, Some(override_file.into_os_string()), None);
        assert_eq!(roots_from_result(file_only.load()).unwrap().len(), 2);
        let dir_only = Paths::select(&files, &dirs, None, Some(override_dir.into_os_string()));
        assert_eq!(roots_from_result(dir_only.load()).unwrap().len(), 2);
    }

    #[test]
    fn empty_or_invalid_native_roots_fail_without_bundled_fallback() {
        assert!(roots_from_result(rustls_native_certs::CertificateResult::default()).is_err());
        let mut result = rustls_native_certs::CertificateResult::default();
        result.certs.push(vec![1, 2, 3].into());
        assert!(roots_from_result(result).is_err());
    }

    #[test]
    fn invalid_roots_do_not_discard_valid_roots() {
        let mut result = rustls_native_certs::CertificateResult::default();
        result.certs =
            rustls_pemfile::certs(&mut &include_bytes!("fixtures/system-trust/ca.pem")[..])
                .collect::<std::result::Result<_, _>>()
                .unwrap();
        result.certs.push(vec![1, 2, 3].into());
        assert_eq!(roots_from_result(result).unwrap().len(), 1);
    }
}
