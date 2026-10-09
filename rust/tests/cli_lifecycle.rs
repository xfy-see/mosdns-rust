// SPDX-License-Identifier: GPL-3.0-or-later
//! Exercise the actual CLI process, DNS listener and Unix shutdown signal.
#![cfg(feature = "full")]
#![cfg(unix)]
use hickory_proto::{
    op::{Message, Query},
    rr::{Name, RecordType},
};
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

async fn connect(path: &Path) -> UnixStream {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(stream) = UnixStream::connect(path).await {
                return stream;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("CLI did not start its task-owned Unix listener")
}

#[tokio::test]
async fn sigterm_drains_cli_and_persists_queried_cache() {
    let started = std::time::Instant::now();
    let stage = |name: &str| {
        eprintln!(
            "cli_lifecycle stage={name} elapsed_ms={} harness_pid={}",
            started.elapsed().as_millis(),
            std::process::id()
        );
    };
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.yaml");
    let socket = directory.path().join("dns.sock");
    let dump = directory.path().join("cache.gz");
    let config = format!("plugins:\n  - tag: cached\n    type: cache\n    args:\n      dump_file: '{}'\n      dump_interval: 3600\n  - tag: main\n    type: sequence\n    args:\n      - exec: '$cached'\n      - {{matches: has_resp, exec: accept}}\n      - exec: 'black_hole 192.0.2.7'\n  - tag: listener\n    type: tcp_server\n    args:\n      entry: main\n      listen: 'unix://{}'\n", dump.display(), socket.display());
    std::fs::write(&config_path, &config).unwrap();
    // Cross-target harnesses can point at the separately uploaded task binary.
    let binary = std::env::var_os("MOSDNS_TEST_BINARY")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_mosdns-rs").into());
    stage("before_spawn");
    eprintln!(
        "cli_lifecycle binary={binary:?} config={}",
        config_path.display()
    );
    let mut child = ChildGuard(
        Command::new(binary)
            .args(["start", "--cpu", "1", "-c"])
            .arg(&config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let child_pid = child.0.id();
    stage("spawned");
    eprintln!("cli_lifecycle child_pid={child_pid}");
    stage("before_unix_connect");
    let mut stream = connect(&socket).await;
    stage("unix_connected");
    let mut query = Message::new();
    query.set_id(2718).add_query(Query::query(
        Name::from_ascii("shutdown.example.").unwrap(),
        RecordType::A,
    ));
    let wire = query.to_vec().unwrap();
    stream.write_u16(wire.len() as u16).await.unwrap();
    stream.write_all(&wire).await.unwrap();
    let response = tokio::time::timeout(Duration::from_secs(3), async {
        let size = stream.read_u16().await.unwrap();
        let mut bytes = vec![0; usize::from(size)];
        stream.read_exact(&mut bytes).await.unwrap();
        Message::from_vec(&bytes).unwrap()
    })
    .await
    .unwrap();
    assert_eq!(response.id(), query.id());
    assert_eq!(response.answers().len(), 1);
    stage("dns_response_validated");
    // Keep the client socket open across shutdown to exercise listener cleanup.
    // SAFETY: this test owns the child PID, which is still waiting for signals.
    assert!(child_pid > 1, "refuse SIGTERM to child PID {child_pid}");
    stage("before_sigterm");
    eprintln!("cli_lifecycle sigterm_target_pid={child_pid}");
    assert_eq!(
        unsafe { libc::kill(child_pid as libc::pid_t, libc::SIGTERM) },
        0
    );
    let status = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("CLI failed to finish SIGTERM shutdown");
    stage("child_exited");
    eprintln!("cli_lifecycle child_exit={status}");
    assert!(status.success(), "CLI exited {status}");
    stage("before_cache_reload");
    let engine =
        mosdns_rs::coremain::Engine::new(mosdns_rs::coremain::Config::from_yaml(&config).unwrap())
            .unwrap();
    assert_eq!(
        engine.cache_stats("cached").unwrap().len,
        1,
        "SIGTERM lost the queried cache"
    );
    stage("cache_reloaded");
    stage("before_reloaded_engine_shutdown");
    engine.shutdown().await.unwrap();
    stage("reloaded_engine_shutdown_complete");
}
