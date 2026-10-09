// SPDX-License-Identifier: GPL-3.0-or-later
use anyhow::{bail, Context, Result};
#[cfg(feature = "full")]
use mosdns_rs::pkg::server::{serve_http, serve_quic, serve_tls};
use mosdns_rs::{
    coremain::{Config, Engine},
    pkg::server::{serve_tcp_with_timeout, serve_udp},
};
use std::{path::PathBuf, sync::Arc};
use tokio::task::JoinSet;
#[cfg(feature = "full")]
mod service;
#[cfg(feature = "full")]
mod windows_service;

async fn shutdown() -> Result<()> {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! { r = tokio::signal::ctrl_c() => r?, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    #[cfg(feature = "full")]
    if args.first().is_some_and(|arg| arg == "service") {
        return service::run(&args[1..]);
    }
    #[cfg(feature = "full")]
    if args
        .first()
        .is_some_and(|arg| matches!(arg.as_str(), "probe" | "config" | "tools"))
    {
        return runtime(None)?.block_on(mosdns_rs::tools::run(&args));
    }
    #[cfg(not(feature = "full"))]
    if args.first().is_some_and(|arg| {
        !matches!(
            arg.as_str(),
            "start" | "check" | "version" | "--version" | "help" | "--help" | "-h"
        )
    }) {
        bail!("command {} is unavailable in the minimal build", args[0]);
    }
    if args.iter().any(|a| a == "--help" || a == "-h") || args.is_empty() || args[0] == "help" {
        #[cfg(feature = "full")]
        println!("mosdns-rs {}\nUsage: mosdns-rs start|check -c CONFIG [-d DIRECTORY] [--cpu N] [--as-service]\n       mosdns-rs version\n       mosdns-rs probe|config --help\n       mosdns-rs service --help", env!("CARGO_PKG_VERSION"));
        #[cfg(not(feature = "full"))]
        println!("mosdns-rs minimal {}\nUsage: mosdns-rs start|check -c CONFIG [-d DIRECTORY] [--cpu N]\n       mosdns-rs version", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args[0] == "version" || args[0] == "--version" {
        #[cfg(not(feature = "full"))]
        if args.len() != 1 {
            bail!("version takes no arguments");
        }
        println!("mosdns-rs {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args[0] != "start" && args[0] != "check" {
        bail!("unknown command {}", args[0]);
    }
    let options = start_options(&args[1..])?;
    #[cfg(all(windows, feature = "full"))]
    if options.as_service {
        if args[0] != "start" {
            bail!("--as-service requires the start command");
        }
        return windows_service::dispatch(options);
    }
    runtime(options.cpu)?.block_on(start(&args[0], options))
}

fn runtime(cpu: Option<usize>) -> Result<tokio::runtime::Runtime> {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    if let Some(cpu) = cpu {
        builder.worker_threads(cpu);
    }
    builder.build().context("create DNS runtime")
}

#[derive(Debug, PartialEq, Eq)]
struct StartOptions {
    path: PathBuf,
    directory: Option<PathBuf>,
    cpu: Option<usize>,
    as_service: bool,
    service_name: Option<String>,
}

fn start_options(args: &[String]) -> Result<StartOptions> {
    let mut path = PathBuf::from("config.yaml");
    let mut directory = None;
    let mut cpu = None;
    let mut as_service = false;
    #[cfg(feature = "full")]
    let mut service_name = None;
    #[cfg(not(feature = "full"))]
    let service_name = None;
    let mut i = 0;
    while i < args.len() {
        let (flag, inline) = args[i]
            .split_once('=')
            .map_or((args[i].as_str(), None), |(key, value)| (key, Some(value)));
        #[cfg(not(feature = "full"))]
        if matches!(flag, "--as-service" | "--service-name") {
            bail!("{flag} requires the full build");
        }
        if flag == "--as-service" {
            as_service = inline.map_or(Ok(true), |value| {
                value.parse().context("invalid --as-service boolean")
            })?;
            i += 1;
            continue;
        }
        let value = if let Some(value) = inline {
            value
        } else {
            i += 1;
            args.get(i).context("missing start option value")?.as_str()
        };
        match flag {
            "-c" | "--config" => {
                path = PathBuf::from(value);
            }
            "-d" | "--dir" => {
                directory = Some(PathBuf::from(value));
            }
            "--cpu" => {
                let value: i64 = value.parse().context("invalid --cpu")?;
                cpu = if value > 0 {
                    Some(usize::try_from(value)?)
                } else {
                    None
                };
            }
            #[cfg(feature = "full")]
            "--service-name" => {
                windows_service::validate_name(value)?;
                service_name = Some(value.to_owned());
            }
            x => bail!("unknown option {x}"),
        }
        i += 1;
    }
    if service_name.is_some() && !as_service {
        bail!("--service-name requires --as-service");
    }
    Ok(StartOptions {
        path,
        directory,
        cpu,
        as_service,
        service_name,
    })
}

async fn start(command: &str, options: StartOptions) -> Result<()> {
    start_with_stop(command, options, shutdown(), || Ok(()), || Ok(())).await
}

async fn start_with_stop(
    command: &str,
    options: StartOptions,
    stop: impl std::future::Future<Output = Result<()>>,
    ready: impl FnOnce() -> Result<()>,
    stopping: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if let Some(dir) = options.directory {
        std::env::set_current_dir(dir)?;
    }
    let config = Config::load(&options.path)?;
    #[cfg(feature = "full")]
    let api_listen = config.api.http.clone();
    #[cfg(not(feature = "full"))]
    if command == "check" {
        Engine::check_config(&config)?;
        println!("configuration decoding and plugin availability checks passed; startup validates plugin options and sockets");
        return Ok(());
    }
    let engine = Arc::new(Engine::new(config)?);
    if command == "check" {
        println!("configuration valid: {} listeners", engine.servers().len());
        return engine.shutdown().await;
    }
    if engine.servers().is_empty() {
        return finish_shutdown(
            Err(anyhow::anyhow!("configuration contains no DNS listeners")),
            &engine,
        )
        .await;
    }
    let mut tasks = JoinSet::new();
    for s in engine.servers() {
        let (listen, entry, kind, idle) = (
            s.listen.clone(),
            s.entry.clone(),
            s.kind.clone(),
            s.idle_timeout,
        );
        #[cfg(feature = "full")]
        let (cert, key, entries, src_ip_header) = (
            s.cert.clone(),
            s.key.clone(),
            s.entries
                .iter()
                .map(|x| (x.path.clone(), x.exec.clone()))
                .collect(),
            s.src_ip_header.clone(),
        );
        let engine = engine.clone();
        eprintln!("{kind} listen={listen} entry={entry}");
        tasks.spawn(async move {
            match kind.as_str() {
                "udp_server" => serve_udp(&listen, engine, entry).await,
                #[cfg(feature = "full")]
                "tcp_server" if !cert.is_empty() => {
                    serve_tls(
                        &listen,
                        engine,
                        entry,
                        &cert,
                        &key,
                        std::time::Duration::from_secs(if idle == 0 { 10 } else { idle }),
                    )
                    .await
                }
                "tcp_server" => {
                    serve_tcp_with_timeout(
                        &listen,
                        engine,
                        entry,
                        std::time::Duration::from_secs(if idle == 0 { 10 } else { idle }),
                    )
                    .await
                }
                #[cfg(feature = "full")]
                "http_server" => {
                    serve_http(
                        &listen,
                        engine,
                        entries,
                        src_ip_header,
                        &cert,
                        &key,
                        std::time::Duration::from_secs(if idle == 0 { 30 } else { idle }),
                    )
                    .await
                }
                #[cfg(feature = "full")]
                "quic_server" => {
                    serve_quic(
                        &listen,
                        engine,
                        entry,
                        &cert,
                        &key,
                        std::time::Duration::from_secs(if idle == 0 { 30 } else { idle }),
                    )
                    .await
                }
                _ => bail!("unsupported server {kind}"),
            }
        });
    }
    #[cfg(feature = "full")]
    if !api_listen.is_empty() {
        tasks.spawn(mosdns_rs::api::serve(api_listen, engine.clone()));
    }
    if let Err(error) = ready() {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        return finish_shutdown(Err(error), &engine).await;
    }
    supervise_with_stop_hook(tasks, engine, stop, stopping).await
}

#[cfg(all(test, feature = "full"))]
async fn supervise(
    tasks: JoinSet<Result<()>>,
    engine: Arc<Engine>,
    stop: impl std::future::Future<Output = Result<()>>,
) -> Result<()> {
    supervise_with_stop_hook(tasks, engine, stop, || Ok(())).await
}

async fn supervise_with_stop_hook(
    mut tasks: JoinSet<Result<()>>,
    engine: Arc<Engine>,
    stop: impl std::future::Future<Output = Result<()>>,
    stopping: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let mut signal = engine.shutdown_signal();
    // Keep the trigger result until cleanup finishes: a bind/signal error must
    // not skip cache persistence and custom plugin close hooks.
    let mut trigger = tokio::select! {
        result = stop => result,
        result = tasks.join_next() => {
            match result {
                Some(Ok(result)) => result.context("server failed"),
                Some(Err(error)) => Err(error).context("server task failed"),
                None => Err(anyhow::anyhow!("no server task")),
            }
        },
        _ = signal.wait_for(|closing| *closing) => Ok(()),
    };
    if let Err(error) = stopping() {
        trigger = match trigger {
            Ok(()) => Err(error),
            Err(original) => {
                Err(original.context(format!("service stop status also failed: {error:#}")))
            }
        };
    }
    engine.request_shutdown(None);
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    finish_shutdown(trigger, &engine).await
}

async fn finish_shutdown(trigger: Result<()>, engine: &Engine) -> Result<()> {
    let cleanup = engine.shutdown().await;
    match (trigger, cleanup) {
        (Ok(()), result) | (result, Ok(())) => result,
        (Err(original), Err(cleanup)) => {
            Err(original.context(format!("shutdown also failed: {cleanup:#}")))
        }
    }
}

#[cfg(all(test, feature = "full"))]
mod tests {
    use super::*;
    use mosdns_rs::coremain::{registry::PluginCloser, Plugin, Registry};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).into()).collect()
    }
    #[test]
    fn cpu_flag_configures_runtime_workers_and_preserves_go_nonpositive_default() {
        for flags in [args(&["--cpu", "2"]), args(&["--cpu=2"])] {
            let options = start_options(&flags).unwrap();
            assert_eq!(options.cpu, Some(2));
            assert_eq!(runtime(options.cpu).unwrap().metrics().num_workers(), 2);
        }
        assert_eq!(start_options(&args(&["--cpu=0"])).unwrap().cpu, None);
        assert_eq!(start_options(&args(&["--cpu=-1"])).unwrap().cpu, None);
        assert!(start_options(&args(&["--cpu=invalid"])).is_err());
    }
    #[test]
    fn unix_as_service_and_inline_paths_preserve_start_arguments() {
        let options = start_options(&args(&[
            "--as-service",
            "--config=path with space.yaml",
            "-d",
            "/tmp/work",
        ]))
        .unwrap();
        assert!(options.as_service);
        assert_eq!(options.path, PathBuf::from("path with space.yaml"));
        assert_eq!(options.directory, Some(PathBuf::from("/tmp/work")));
        assert!(
            !start_options(&args(&["--as-service=false"]))
                .unwrap()
                .as_service
        );
        assert!(start_options(&args(&["--as-service=invalid"])).is_err());
        assert!(start_options(&args(&["-c"])).is_err());
        assert!(start_options(&args(&["--unknown", "value"])).is_err());
    }

    #[test]
    fn custom_windows_service_name_requires_dispatcher_mode_and_is_validated() {
        let options = start_options(&args(&["--as-service", "--service-name=custom-dns"])).unwrap();
        assert_eq!(options.service_name.as_deref(), Some("custom-dns"));
        assert!(start_options(&args(&["--service-name=custom-dns"])).is_err());
        assert!(start_options(&args(&["--as-service", "--service-name=../other"])).is_err());
        assert!(start_options(&args(&["--as-service", "--service-name="])).is_err());
    }

    #[tokio::test]
    async fn windows_stop_and_preshutdown_use_existing_listener_and_plugin_cleanup() {
        for event in [
            windows_service::Control::Stop,
            windows_service::Control::Preshutdown,
        ] {
            let (engine, calls) = supervised_engine(false, false);
            let (tasks, dropped) = pending_listener();
            let controller = windows_service::Controller::new(|_| Ok(()));
            controller.begin().unwrap();
            controller.ready().unwrap();
            controller.control(event).unwrap();
            let stopping = controller.clone();
            supervise_with_stop_hook(tasks, engine, controller.wait_for_stop(), move || {
                stopping.stopping()
            })
            .await
            .unwrap();
            controller.finish(false).unwrap();
            assert!(dropped.load(Ordering::SeqCst));
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn windows_status_reporting_failure_still_runs_shutdown_cleanup() {
        let (engine, calls) = supervised_engine(false, false);
        let (tasks, dropped) = pending_listener();
        let error = supervise_with_stop_hook(tasks, engine, async { Ok(()) }, || {
            bail!("SetServiceStatus failed")
        })
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("SetServiceStatus failed"));
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failed_listener_still_persists_cache_before_returning_original_error() {
        let directory = tempfile::tempdir().unwrap();
        let dump = directory.path().join("failure-cache.gz");
        let path = directory.path().join("config.yaml");
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = format!(
            "plugins:\n  - tag: cached\n    type: cache\n    args:\n      dump_file: {}\n      dump_interval: 3600\n  - tag: main\n    type: sequence\n    args:\n      - exec: 'black_hole 192.0.2.1'\n  - tag: listener\n    type: tcp_server\n    args:\n      entry: main\n      listen: '{}'\n",
            dump.display(), occupied.local_addr().unwrap()
        );
        std::fs::write(&path, config).unwrap();
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            start(
                "start",
                StartOptions {
                    path,
                    directory: None,
                    cpu: None,
                    as_service: false,
                    service_name: None,
                },
            ),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(format!("{error:#}").contains("bind TCP DNS listener"));
        assert!(
            dump.exists(),
            "listener failure bypassed cache shutdown dump"
        );
        assert_eq!(&std::fs::read(dump).unwrap()[..2], &[0x1f, 0x8b]);
    }

    struct Closer {
        calls: Arc<AtomicUsize>,
        fail: bool,
    }
    impl PluginCloser for Closer {
        fn close(&self) -> Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                bail!("close hook failed");
            }
            Ok(())
        }
    }
    struct Dropped(Arc<AtomicBool>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    fn supervised_engine(fail_close: bool, fail_service: bool) -> (Arc<Engine>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let closer = Arc::new(Closer {
            calls: calls.clone(),
            fail: fail_close,
        });
        let mut registry = Registry::new();
        registry
            .register_plugin_type("resource", move |build, _| {
                build.register_closer(closer.clone())?;
                if fail_service {
                    build.attach_service(async { bail!("plugin service failed") })?;
                }
                Ok(Plugin::Data(Arc::new(())))
            })
            .unwrap();
        let config = Config::from_yaml("plugins:\n  - {tag: resource, type: resource}\n").unwrap();
        (
            Arc::new(Engine::new_with_registry(config, registry).unwrap()),
            calls,
        )
    }
    fn pending_listener() -> (JoinSet<Result<()>>, Arc<AtomicBool>) {
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = Dropped(dropped.clone());
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let _guard = guard;
            std::future::pending::<Result<()>>().await
        });
        (tasks, dropped)
    }

    #[tokio::test]
    async fn plugin_fatal_signal_stops_listeners_and_runs_cleanup() {
        let (engine, calls) = supervised_engine(false, true);
        let (tasks, dropped) = pending_listener();
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            supervise(tasks, engine.clone(), std::future::pending()),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(format!("{error:#}").contains("plugin service failed"));
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(engine.shutdown().await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn signal_error_preserves_both_original_and_close_hook_failure() {
        let (engine, calls) = supervised_engine(true, false);
        let (tasks, dropped) = pending_listener();
        let error = supervise(tasks, engine, async { bail!("signal handler failed") })
            .await
            .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("signal handler failed") && message.contains("close hook failed"));
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn panicking_listener_still_closes_other_tasks_and_plugins() {
        let (engine, calls) = supervised_engine(false, false);
        let (mut tasks, dropped) = pending_listener();
        tasks.spawn(async {
            panic!("listener panic");
            #[allow(unreachable_code)]
            Ok(())
        });
        let error = supervise(tasks, engine, std::future::pending())
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("listener panic"));
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
