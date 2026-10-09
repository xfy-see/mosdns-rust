// SPDX-License-Identifier: GPL-3.0-or-later
//! SCM uses structured service definitions, never a shell or sc.exe.

use anyhow::{bail, Result};

pub(super) const DEFAULT_NAME: &str = "mosdns-rs";
pub(super) const MARKER: &str = "Managed by mosdns-rs service";

pub(super) fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || name.starts_with('-')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
    {
        bail!("service name must contain only letters, digits, dash, underscore and dot");
    }
    Ok(())
}

fn display_name(name: &str) -> String {
    format!("mosdns Rust DNS forwarder ({name}) [{MARKER}]")
}

#[cfg(any(windows, test))]
fn is_managed(name: &str, installed_display_name: &std::ffi::OsStr) -> bool {
    installed_display_name == std::ffi::OsStr::new(&display_name(name))
}

/// Microsoft C runtime argument quoting, also used by windows-service's SCM
/// image-path builder. This string is a preview; install passes separate args.
fn quote(value: &str) -> String {
    if !value.is_empty()
        && !value
            .chars()
            .any(|ch| matches!(ch, '"' | ' ' | '\t' | '\n' | '\u{b}'))
    {
        return value.to_owned();
    }
    let mut result = String::from("\"");
    let mut slashes = 0;
    for ch in value.chars() {
        match ch {
            '\\' => slashes += 1,
            '"' => {
                result.extend(std::iter::repeat_n('\\', slashes * 2 + 1));
                result.push('"');
                slashes = 0;
            }
            ch => {
                result.extend(std::iter::repeat_n('\\', slashes));
                result.push(ch);
                slashes = 0;
            }
        }
    }
    result.extend(std::iter::repeat_n('\\', slashes * 2));
    result.push('"');
    result
}

pub(super) fn launch_arguments(name: &str, arguments: &[String]) -> Vec<String> {
    let mut arguments = arguments.to_vec();
    arguments.extend(["--service-name".into(), name.into()]);
    arguments
}

pub(super) fn render(name: &str, binary: &str, arguments: &[String]) -> Result<String> {
    validate_name(name)?;
    let arguments = launch_arguments(name, arguments);
    let command_line = std::iter::once(binary)
        .chain(arguments.iter().map(String::as_str))
        .map(quote)
        .collect::<Vec<_>>()
        .join(" ");
    let mut result = serde_json::to_string_pretty(&serde_json::json!({
        "name": name,
        "display_name": display_name(name),
        "description": MARKER,
        "binary": binary,
        "arguments": arguments,
        "command_line": command_line,
        "start_type": "automatic",
    }))?;
    result.push('\n');
    Ok(result)
}

#[cfg(any(windows, test))]
mod lifecycle {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tokio::sync::watch;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum State {
        StartPending,
        Running,
        StopPending,
        Stopped,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct Status {
        pub(crate) state: State,
        pub(crate) checkpoint: u32,
        pub(crate) failed: bool,
    }

    #[derive(Clone, Copy, Debug)]
    pub(crate) enum Control {
        Stop,
        Preshutdown,
        Interrogate,
    }

    pub(crate) struct Controller {
        state: Mutex<Status>,
        stop: watch::Sender<bool>,
        report: Box<dyn Fn(Status) -> Result<()> + Send + Sync>,
        reporting_error: Mutex<Option<String>>,
        pending_since: Mutex<Instant>,
    }

    impl Controller {
        pub(crate) fn new(
            report: impl Fn(Status) -> Result<()> + Send + Sync + 'static,
        ) -> Arc<Self> {
            let (stop, _) = watch::channel(false);
            Arc::new(Self {
                state: Mutex::new(Status {
                    state: State::StartPending,
                    checkpoint: 1,
                    failed: false,
                }),
                stop,
                report: Box::new(report),
                reporting_error: Mutex::new(None),
                pending_since: Mutex::new(Instant::now()),
            })
        }

        pub(crate) fn begin(&self) -> Result<()> {
            let status = self.state.lock().unwrap();
            // Reporting SERVICE_STOPPED closes the SCM RPC context. Never
            // repeat that status, including a late Interrogate callback.
            if status.state == State::Stopped {
                return Ok(());
            }
            self.publish(*status)
        }

        fn publish(&self, status: Status) -> Result<()> {
            let result = (self.report)(status);
            if let Err(error) = &result {
                self.reporting_error
                    .lock()
                    .unwrap()
                    .get_or_insert_with(|| format!("{error:#}"));
            }
            result
        }

        pub(crate) fn reporting_error(&self) -> Option<String> {
            self.reporting_error.lock().unwrap().clone()
        }

        pub(crate) fn ready(&self) -> Result<()> {
            let mut status = self.state.lock().unwrap();
            if status.state == State::StartPending {
                status.state = State::Running;
                status.checkpoint = 0;
                self.publish(*status)?;
            }
            // A stop requested during initialization must never be overwritten
            // by a later Running report.
            Ok(())
        }

        pub(crate) fn stopping(&self) -> Result<()> {
            let mut status = self.state.lock().unwrap();
            if !matches!(status.state, State::StopPending | State::Stopped) {
                status.state = State::StopPending;
                status.checkpoint = 1;
                *self.pending_since.lock().unwrap() = Instant::now();
                self.publish(*status)?;
            }
            Ok(())
        }

        pub(crate) fn control(&self, control: Control) -> Result<()> {
            match control {
                Control::Interrogate => self.begin(),
                Control::Stop | Control::Preshutdown => {
                    let result = self.stopping();
                    // Even a SetServiceStatus failure must not lose the stop.
                    self.stop.send_replace(true);
                    result
                }
            }
        }

        pub(crate) fn tick(&self) -> Result<()> {
            let mut status = self.state.lock().unwrap();
            if matches!(status.state, State::StartPending | State::StopPending) {
                // A periodic heartbeat must not hide a hung init/close hook
                // forever. Past this budget, stop advancing SCM checkpoints.
                if self.pending_since.lock().unwrap().elapsed() >= Duration::from_secs(180) {
                    let error = "Windows service pending operation exceeded 180 seconds";
                    self.reporting_error
                        .lock()
                        .unwrap()
                        .get_or_insert_with(|| error.into());
                    bail!(error);
                }
                status.checkpoint = status.checkpoint.saturating_add(1);
                self.publish(*status)?;
            }
            Ok(())
        }

        pub(crate) fn finish(&self, failed: bool) -> Result<()> {
            let mut status = self.state.lock().unwrap();
            if status.state != State::Stopped {
                status.state = State::Stopped;
                status.checkpoint = 0;
                status.failed = failed || self.reporting_error().is_some();
                self.publish(*status)?;
            }
            Ok(())
        }

        pub(crate) async fn wait_for_stop(&self) -> Result<()> {
            let mut stop = self.stop.subscribe();
            if *stop.borrow() {
                return Ok(());
            }
            stop.wait_for(|stopping| *stopping)
                .await
                .map_err(|_| anyhow::anyhow!("Windows service stop channel closed"))?;
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn pending_heartbeat_is_bounded_without_cancelling_shutdown() {
            for stopping in [false, true] {
                let controller = Controller::new(|_| Ok(()));
                if stopping {
                    controller.stopping().unwrap();
                }
                *controller.pending_since.lock().unwrap() =
                    Instant::now() - Duration::from_secs(181);
                assert!(controller.tick().is_err());
                assert_eq!(controller.state.lock().unwrap().checkpoint, 1);
                assert!(controller.reporting_error().is_some());
                // An expired StopPending budget cannot be reset by duplicate
                // stop controls; the existing shutdown future keeps running.
                if stopping {
                    controller.control(Control::Stop).unwrap();
                    assert!(controller.tick().is_err());
                }
                controller.finish(false).unwrap();
                assert!(controller.state.lock().unwrap().failed);
            }
        }
    }
}

#[cfg(any(windows, test))]
pub(crate) use lifecycle::{Control, Controller, State, Status};

#[cfg(windows)]
pub(super) use native::{dispatch, manage};

#[cfg(windows)]
mod native {
    use super::*;
    use ::windows_service::{
        define_windows_service,
        service::{
            Service, ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl,
            ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
        service_dispatcher,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    use anyhow::Context;
    use std::{
        ffi::{OsStr, OsString},
        path::Path,
        sync::{Arc, Mutex, OnceLock},
        time::{Duration, Instant},
    };

    const WAIT_TIMEOUT: Duration = Duration::from_secs(180);
    static OPTIONS: OnceLock<Mutex<Option<crate::StartOptions>>> = OnceLock::new();
    static OUTCOME: Mutex<Option<std::result::Result<(), String>>> = Mutex::new(None);
    define_windows_service!(ffi_service_main, service_main);

    pub(crate) fn dispatch(options: crate::StartOptions) -> Result<()> {
        let name = options
            .service_name
            .as_deref()
            .unwrap_or(DEFAULT_NAME)
            .to_owned();
        validate_name(&name)?;
        OPTIONS
            .set(Mutex::new(Some(options)))
            .map_err(|_| anyhow::anyhow!("Windows service dispatcher already started"))?;
        service_dispatcher::start(name, ffi_service_main).context("connect Windows service dispatcher (use service start rather than launching --as-service manually)")?;
        match OUTCOME.lock().unwrap().take() {
            Some(Ok(())) => Ok(()),
            Some(Err(error)) => bail!("Windows service failed: {error}"),
            None => bail!("Windows service dispatcher returned without a service result"),
        }
    }

    fn native_status(status: Status) -> ServiceStatus {
        let pending = matches!(status.state, State::StartPending | State::StopPending);
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: match status.state {
                State::StartPending => ServiceState::StartPending,
                State::Running => ServiceState::Running,
                State::StopPending => ServiceState::StopPending,
                State::Stopped => ServiceState::Stopped,
            },
            controls_accepted: if status.state == State::Running {
                ServiceControlAccept::STOP
                    | ServiceControlAccept::PRESHUTDOWN
                    | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: if status.failed {
                ServiceExitCode::ServiceSpecific(1)
            } else {
                ServiceExitCode::Win32(0)
            },
            checkpoint: status.checkpoint,
            wait_hint: if pending {
                Duration::from_secs(30)
            } else {
                Duration::ZERO
            },
            process_id: None,
        }
    }

    fn service_main(_arguments: Vec<OsString>) {
        let handle: Arc<OnceLock<ServiceStatusHandle>> = Arc::new(OnceLock::new());
        let reporter = handle.clone();
        let controller = Controller::new(move |status| {
            if let Some(handle) = reporter.get() {
                handle
                    .set_service_status(native_status(status))
                    .context("report Windows service status")?;
            }
            Ok(())
        });
        // Never unwind across the generated ServiceMain FFI boundary.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let options = OPTIONS.get().context("missing Windows service startup options")?.lock().unwrap().take().context("Windows service main called twice")?;
            let name = options.service_name.as_deref().unwrap_or(DEFAULT_NAME);
            let controls = controller.clone();
            let status_handle = service_control_handler::register(name, move |control| {
                let control = match control {
                    ServiceControl::Stop | ServiceControl::Shutdown => Control::Stop,
                    ServiceControl::Preshutdown => Control::Preshutdown,
                    ServiceControl::Interrogate => Control::Interrogate,
                    _ => return ServiceControlHandlerResult::NotImplemented,
                };
                if let Err(error) = controls.control(control) { eprintln!("Windows service control: {error:#}"); }
                ServiceControlHandlerResult::NoError
            }).context("register Windows service control handler")?;
            handle.set(status_handle).map_err(|_| anyhow::anyhow!("Windows service status handler already registered"))?;
            controller.begin()?;
            crate::runtime(options.cpu)?.block_on(async {
                let ready = controller.clone();
                let stopping = controller.clone();
                let run = crate::start_with_stop("start", options, controller.wait_for_stop(), move || ready.ready(), move || stopping.stopping());
                tokio::pin!(run);
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                let mut reporting_error = None;
                loop {
                    tokio::select! {
                        result = &mut run => {
                            return match (result, reporting_error) {
                                (Ok(()), Some(error)) => Err(error),
                                (Err(error), Some(reporting)) => Err(error.context(format!("service status also failed: {reporting:#}"))),
                                (result, None) => result,
                            };
                        }
                        _ = interval.tick() => {
                            if let Err(error) = controller.tick() {
                                reporting_error.get_or_insert(error);
                                let _ = controller.control(Control::Stop);
                            }
                        }
                    }
                }
            })
        })).unwrap_or_else(|_| Err(anyhow::anyhow!("panic in Windows service runtime")));
        let result = match (result, controller.reporting_error()) {
            (Ok(()), Some(error)) => Err(anyhow::anyhow!(error)),
            (Err(error), Some(reporting)) => {
                Err(error.context(format!("service status also failed: {reporting}")))
            }
            (result, None) => result,
        };
        let finished = controller.finish(result.is_err());
        let result = match (result, finished) {
            (Ok(()), result) | (result, Ok(())) => result,
            (Err(error), Err(status)) => {
                Err(error.context(format!("final service status also failed: {status:#}")))
            }
        };
        if let Err(error) = &result {
            eprintln!("Windows service: {error:#}");
        }
        *OUTCOME.lock().unwrap() = Some(result.map_err(|error| format!("{error:#}")));
    }

    fn wait_for(service: &Service, expected: ServiceState) -> Result<()> {
        let started = Instant::now();
        loop {
            let status = service
                .query_status()
                .context("query Windows service status")?;
            if status.current_state == expected {
                return Ok(());
            }
            if expected == ServiceState::Running && status.current_state == ServiceState::Stopped {
                bail!(
                    "Windows service stopped during startup: {:?}",
                    status.exit_code
                );
            }
            if started.elapsed() >= WAIT_TIMEOUT {
                bail!(
                    "timeout waiting for Windows service {expected:?}; current state {:?}",
                    status.current_state
                );
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn start(service: &Service) -> Result<()> {
        match service.query_status()?.current_state {
            ServiceState::Running => return Ok(()),
            ServiceState::StartPending => return wait_for(service, ServiceState::Running),
            ServiceState::StopPending => wait_for(service, ServiceState::Stopped)?,
            ServiceState::Stopped => {}
            state => bail!("cannot start Windows service in {state:?}"),
        }
        service
            .start::<&OsStr>(&[])
            .context("start Windows service")?;
        wait_for(service, ServiceState::Running)
    }

    fn stop(service: &Service) -> Result<()> {
        match service.query_status()?.current_state {
            ServiceState::Stopped => return Ok(()),
            ServiceState::StopPending => {}
            ServiceState::StartPending => {
                if let Err(error) = wait_for(service, ServiceState::Running) {
                    // A failed startup is already stopped and can be uninstalled.
                    if service.query_status()?.current_state == ServiceState::Stopped {
                        return Ok(());
                    }
                    return Err(error);
                }
                service.stop().context("stop Windows service")?;
            }
            _ => {
                service.stop().context("stop Windows service")?;
            }
        }
        wait_for(service, ServiceState::Stopped)
    }

    pub(crate) fn manage(
        action: &str,
        name: &str,
        binary: &Path,
        arguments: &[String],
    ) -> Result<()> {
        validate_name(name)?;
        let access = ServiceManagerAccess::CONNECT
            | if action == "install" {
                ServiceManagerAccess::CREATE_SERVICE
            } else {
                ServiceManagerAccess::empty()
            };
        let manager = ServiceManager::local_computer(None::<&str>, access)
            .context("open Windows Service Control Manager")?;
        if action == "install" {
            let info = ServiceInfo {
                name: name.into(),
                display_name: display_name(name).into(),
                service_type: ServiceType::OWN_PROCESS,
                start_type: ServiceStartType::AutoStart,
                error_control: ServiceErrorControl::Normal,
                executable_path: binary.into(),
                launch_arguments: launch_arguments(name, arguments)
                    .into_iter()
                    .map(OsString::from)
                    .collect(),
                dependencies: vec![],
                account_name: None,
                account_password: None,
            };
            // CreateService fails if the name exists; never replace or adopt it.
            let service = manager
                .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::DELETE)
                .context("create Windows service; existing services are never overwritten")?;
            if let Err(error) = service
                .set_description(MARKER)
                .and_then(|_| service.set_preshutdown_timeout(WAIT_TIMEOUT))
            {
                let rollback = service.delete();
                return Err(error).with_context(|| {
                    format!("initialize new Windows service; rollback deletion: {rollback:?}")
                });
            }
            println!("installed {name}");
            return Ok(());
        }
        let mut access = ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS;
        match action {
            "start" => access |= ServiceAccess::START,
            "stop" => access |= ServiceAccess::STOP,
            "restart" => access |= ServiceAccess::START | ServiceAccess::STOP,
            "uninstall" => access |= ServiceAccess::STOP | ServiceAccess::DELETE,
            "status" => {}
            _ => bail!("unknown Windows service action {action}"),
        }
        let service = manager
            .open_service(name, access)
            .context("open Windows service")?;
        let config = service
            .query_config()
            .context("query Windows service management marker")?;
        if !is_managed(name, &config.display_name)
            || config.service_type != ServiceType::OWN_PROCESS
        {
            bail!("refuse to operate on a Windows service not created by mosdns-rs");
        }
        match action {
            "status" => println!(
                "{}",
                match service.query_status()?.current_state {
                    ServiceState::Running => "running",
                    ServiceState::Stopped => "stopped",
                    ServiceState::StartPending => "starting",
                    ServiceState::StopPending => "stopping",
                    _ => "paused",
                }
            ),
            "start" => start(&service)?,
            "stop" => stop(&service)?,
            "restart" => {
                stop(&service)?;
                start(&service)?;
            }
            "uninstall" => {
                stop(&service)?;
                service.delete().context("delete stopped Windows service")?;
                println!("{name} stopped and marked for deletion");
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn native_status_accepts_controls_only_when_running_and_reports_failed_exit() {
            for state in [
                State::StartPending,
                State::Running,
                State::StopPending,
                State::Stopped,
            ] {
                let pending = matches!(state, State::StartPending | State::StopPending);
                let status = native_status(Status {
                    state,
                    checkpoint: u32::from(pending),
                    failed: state == State::Stopped,
                });
                assert_eq!(status.wait_hint.is_zero(), !pending);
                if state == State::Running {
                    assert!(status
                        .controls_accepted
                        .contains(ServiceControlAccept::STOP | ServiceControlAccept::PRESHUTDOWN));
                } else {
                    assert!(status.controls_accepted.is_empty());
                }
                if state == State::Stopped {
                    assert_eq!(status.exit_code, ServiceExitCode::ServiceSpecific(1));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn windows_quoting_preserves_empty_spaces_quotes_and_trailing_backslashes() {
        assert_eq!(quote("plain"), "plain");
        assert_eq!(quote(""), "\"\"");
        assert_eq!(
            quote(r"C:\Program Files\mosdns\"),
            r#""C:\Program Files\mosdns\\""#
        );
        assert_eq!(quote(r#"--config=a"b.yaml"#), r#""--config=a\"b.yaml""#);
        assert_eq!(quote("中文 配置.yaml"), "\"中文 配置.yaml\"");
        assert_eq!(quote(r#"space \\"quoted"#), r#""space \\\\\"quoted""#);
    }

    #[test]
    fn marker_check_requires_exact_managed_service_identity() {
        assert!(is_managed(
            "dns",
            std::ffi::OsStr::new(&display_name("dns"))
        ));
        assert!(!is_managed(
            "dns",
            std::ffi::OsStr::new("unrelated service")
        ));
        assert!(!is_managed(
            "dns",
            std::ffi::OsStr::new(&display_name("other"))
        ));
        assert!(!is_managed("dns", std::ffi::OsStr::new(MARKER)));
    }

    fn controller() -> (Arc<Controller>, Arc<Mutex<Vec<Status>>>) {
        let statuses = Arc::new(Mutex::new(Vec::new()));
        let record = statuses.clone();
        (
            Controller::new(move |status| {
                record.lock().unwrap().push(status);
                Ok(())
            }),
            statuses,
        )
    }

    #[tokio::test]
    async fn stop_and_preshutdown_share_shutdown_and_status_transitions() {
        for control in [Control::Stop, Control::Preshutdown] {
            let (controller, statuses) = controller();
            controller.begin().unwrap();
            controller.tick().unwrap();
            controller.ready().unwrap();
            controller.control(control).unwrap();
            controller.control(control).unwrap();
            controller.tick().unwrap();
            controller.wait_for_stop().await.unwrap();
            controller.finish(false).unwrap();
            let statuses = statuses.lock().unwrap();
            assert_eq!(
                statuses
                    .iter()
                    .map(|status| status.state)
                    .collect::<Vec<_>>(),
                vec![
                    State::StartPending,
                    State::StartPending,
                    State::Running,
                    State::StopPending,
                    State::StopPending,
                    State::Stopped
                ]
            );
            assert_eq!(statuses[1].checkpoint, 2);
            assert_eq!(statuses[4].checkpoint, 2);
            assert_eq!(statuses.last().unwrap().checkpoint, 0);
            assert!(!statuses.last().unwrap().failed);
        }
    }

    #[tokio::test]
    async fn early_stop_is_not_overwritten_and_reporting_errors_do_not_lose_stop() {
        let (controller, statuses) = controller();
        controller.control(Control::Stop).unwrap();
        controller.ready().unwrap();
        controller.wait_for_stop().await.unwrap();
        controller.finish(true).unwrap();
        assert!(statuses
            .lock()
            .unwrap()
            .iter()
            .all(|status| status.state != State::Running));
        assert!(statuses.lock().unwrap().last().unwrap().failed);
        let broken = Controller::new(|_| bail!("simulated SetServiceStatus failure"));
        assert!(broken.control(Control::Preshutdown).is_err());
        assert!(broken
            .reporting_error()
            .unwrap()
            .contains("SetServiceStatus"));
        tokio::time::timeout(std::time::Duration::from_secs(1), broken.wait_for_stop())
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn interrogate_reports_current_state_and_stopped_is_terminal() {
        let (controller, statuses) = controller();
        controller.begin().unwrap();
        controller.control(Control::Interrogate).unwrap();
        controller.finish(true).unwrap();
        controller.control(Control::Interrogate).unwrap();
        controller.ready().unwrap();
        controller.control(Control::Stop).unwrap();
        controller.tick().unwrap();
        controller.finish(false).unwrap();
        let statuses = statuses.lock().unwrap();
        assert_eq!(statuses.len(), 3);
        assert_eq!(statuses[0], statuses[1]);
        assert!(statuses[2].failed);
        assert_eq!(statuses[2].state, State::Stopped);
    }
}
