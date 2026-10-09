//! Profile boundaries shared with Go's protocol_minimal and tls_minimal tests.
use super::*;

#[test]
fn minimal_accepts_numeric_plaintext_and_pipeline_helpers() {
    for address in [
        "127.0.0.1",
        "udp://127.0.0.1:53",
        "udp://[::1]:53",
        "tcp://127.0.0.1:53",
        "tcp+pipeline://127.0.0.1:53",
        "tcp://[::1]:53",
    ] {
        assert!(
            Upstream::validate_options(address, &Options::default()).is_ok(),
            "{address}"
        );
        assert!(
            Upstream::new(address, Duration::from_secs(1)).is_ok(),
            "{address}"
        );
    }
}

#[test]
fn minimal_rejects_encrypted_and_unknown_transports_at_construction() {
    for scheme in ["tls", "tls+pipeline", "https", "h3", "quic", "doq", "ftp"] {
        assert!(
            Upstream::validate_options(&format!("{scheme}://127.0.0.1"), &Options::default())
                .is_err(),
            "{scheme}"
        );
        let error = Upstream::new(&format!("{scheme}://127.0.0.1"), Duration::from_secs(1))
            .err()
            .expect("unavailable transport accepted");
        assert!(error.to_string().contains("minimal"), "{scheme}: {error:#}");
    }
}

#[test]
fn minimal_rejects_full_profile_options_even_for_udp() {
    for (name, options) in [
        (
            "enable_http3",
            Options {
                enable_http3: true,
                ..Default::default()
            },
        ),
        (
            "socks5",
            Options {
                socks5: "127.0.0.1:1080".into(),
                ..Default::default()
            },
        ),
        (
            "bootstrap",
            Options {
                bootstrap: "127.0.0.1".into(),
                ..Default::default()
            },
        ),
        (
            "bootstrap_version",
            Options {
                bootstrap_version: 6,
                ..Default::default()
            },
        ),
        (
            "insecure_skip_verify",
            Options {
                insecure_skip_verify: true,
                ..Default::default()
            },
        ),
    ] {
        assert!(
            Upstream::validate_options("127.0.0.1:53", &options).is_err(),
            "{name}"
        );
        let error = Upstream::new_with_options("127.0.0.1:53", Duration::from_secs(1), options)
            .err()
            .unwrap_or_else(|| panic!("minimal accepted {name}"));
        assert!(error.to_string().contains("minimal"), "{name}: {error:#}");
    }
}

#[test]
fn minimal_pure_check_shares_url_and_dial_override_validation() {
    // No Tokio runtime is installed: this entry point must stay synchronous.
    for address in [
        "udp://127.0.0.1:0",
        "tcp://127.0.0.1/path",
        "tcp://127.0.0.1?x=1",
        "udp://user@127.0.0.1",
        "udp://127.0.0.1#fragment",
        "udp://dns.test.invalid",
    ] {
        assert!(
            Upstream::validate_options(address, &Options::default()).is_err(),
            "{address}"
        );
        assert!(
            Upstream::new(address, Duration::from_secs(1)).is_err(),
            "{address}"
        );
    }
    let options = Options {
        dial_addr: "[::1]:15331".into(),
        ..Default::default()
    };
    assert!(Upstream::validate_options("tcp+pipeline://dns.test.invalid", &options).is_ok());
    assert!(Upstream::new_with_options(
        "tcp+pipeline://dns.test.invalid",
        Duration::from_secs(1),
        options
    )
    .is_ok());
}

#[test]
fn minimal_requires_a_numeric_effective_dial_address() {
    for address in [
        "udp://dns.test.invalid",
        "tcp://dns.test.invalid",
        "tcp+pipeline://dns.test.invalid",
    ] {
        assert!(
            Upstream::new(address, Duration::from_secs(1)).is_err(),
            "{address}"
        );
        assert!(
            Upstream::new_with_options(
                address,
                Duration::from_secs(1),
                Options {
                    dial_addr: "127.0.0.1:15331".into(),
                    ..Default::default()
                }
            )
            .is_ok(),
            "numeric dial override of {address}"
        );
    }
    assert!(Upstream::new_with_options(
        "tcp://127.0.0.1",
        Duration::from_secs(1),
        Options {
            dial_addr: "dns.test.invalid:53".into(),
            ..Default::default()
        }
    )
    .is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn minimal_retains_mark_and_bind_device_without_opening_sockets() {
    assert!(Upstream::new_with_options(
        "udp://127.0.0.1",
        Duration::from_secs(1),
        Options {
            so_mark: 0x0100_0000,
            bind_to_device: "lo".into(),
            ..Default::default()
        }
    )
    .is_ok());
}
