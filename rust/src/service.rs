// SPDX-License-Identifier: GPL-3.0-or-later
//! Native service-manager commands. Tests only render definitions and plans.
use anyhow::{bail, Context, Result};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
};

const MARKER: &str = crate::windows_service::MARKER;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Platform {
    Systemd,
    Launchd,
    Procd,
    Windows,
}

impl Platform {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "systemd" => Ok(Self::Systemd),
            "launchd" | "macos" => Ok(Self::Launchd),
            "procd" | "openwrt" => Ok(Self::Procd),
            "windows" => Ok(Self::Windows),
            _ => bail!("unsupported service platform {value}"),
        }
    }
    fn native() -> Result<Self> {
        if cfg!(windows) {
            return Ok(Self::Windows);
        }
        if cfg!(target_os = "macos") {
            return Ok(Self::Launchd);
        }
        if cfg!(target_os = "linux") {
            return Ok(
                if Path::new("/sbin/procd").exists() || Path::new("/usr/sbin/procd").exists() {
                    Self::Procd
                } else {
                    Self::Systemd
                },
            );
        }
        bail!(
            "service lifecycle is supported on Windows/SCM, Linux/systemd, OpenWrt/procd and macOS/launchd only"
        )
    }
    fn path(self, name: &str) -> PathBuf {
        match self {
            Self::Systemd => PathBuf::from(format!("/etc/systemd/system/{name}.service")),
            Self::Launchd => PathBuf::from(format!("/Library/LaunchDaemons/{name}.plist")),
            Self::Procd => PathBuf::from(format!("/etc/init.d/{name}")),
            Self::Windows => unreachable!("Windows SCM services have no definition-file path"),
        }
    }
}

#[derive(Clone, Debug)]
struct Definition {
    name: String,
    binary: String,
    directory: String,
    config: String,
    cpu: Option<usize>,
}

impl Definition {
    fn arguments(&self) -> Vec<String> {
        let mut arguments = vec![
            self.binary.clone(),
            "start".into(),
            "--as-service".into(),
            "-d".into(),
            self.directory.clone(),
            "-c".into(),
            self.config.clone(),
        ];
        if let Some(cpu) = self.cpu {
            arguments.extend(["--cpu".into(), cpu.to_string()]);
        }
        arguments
    }
    fn validate(&self) -> Result<()> {
        if self.name.is_empty()
            || self.name.len() > 128
            || !self
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
            || self.name.starts_with('-')
        {
            bail!("service name must contain only letters, digits, dash, underscore and dot");
        }
        for field in [&self.binary, &self.directory, &self.config] {
            if field.is_empty() || field.chars().any(char::is_control) {
                bail!("service paths must be nonempty and contain no control characters");
            }
        }
        Ok(())
    }
    fn render(&self, platform: Platform) -> Result<String> {
        self.validate()?;
        let arguments = self.arguments();
        match platform {
            Platform::Systemd => Ok(format!("# {MARKER}\n[Unit]\nDescription=mosdns Rust DNS forwarder\nAfter=network.target\n\n[Service]\nType=simple\nExecStart={}\nWorkingDirectory={}\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n", arguments.iter().map(|arg| systemd_quote(arg, true)).collect::<Vec<_>>().join(" "), systemd_quote(&self.directory, false))),
            Platform::Launchd => Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<!-- {MARKER} -->\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{}</string>\n<key>ProgramArguments</key><array>{}</array>\n<key>WorkingDirectory</key><string>{}</string>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n</dict></plist>\n", xml(&self.name), arguments.iter().map(|arg| format!("<string>{}</string>",xml(arg))).collect::<String>(), xml(&self.directory))),
            Platform::Procd => Ok(format!("#!/bin/sh /etc/rc.common\n# {MARKER}\nUSE_PROCD=1\nSTART=21\nSTOP=89\n\nstart_service() {{\n    procd_open_instance\n    procd_set_param command {}\n    procd_set_param respawn 3600 5 5\n    procd_set_param stdout 1\n    procd_set_param stderr 1\n    procd_close_instance\n}}\n", arguments.iter().map(|arg| shell_quote(arg)).collect::<Vec<_>>().join(" "))),
            Platform::Windows => crate::windows_service::render(&self.name, &self.binary, &arguments[1..]),
        }
    }
}

fn systemd_quote(value: &str, environment_expansion: bool) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%");
    format!(
        "\"{}\"",
        if environment_expansion {
            escaped.replace('$', "$$")
        } else {
            escaped
        }
    )
}
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[derive(Debug, PartialEq, Eq)]
struct Operation {
    program: String,
    arguments: Vec<String>,
}
impl Operation {
    fn new(program: &str, arguments: &[&str]) -> Self {
        Self {
            program: program.into(),
            arguments: arguments.iter().map(|arg| (*arg).into()).collect(),
        }
    }
    fn run(&self) -> Result<()> {
        let output = Command::new(&self.program)
            .args(&self.arguments)
            .output()
            .with_context(|| format!("run {}", self.program))?;
        io::stdout().write_all(&output.stdout)?;
        io::stderr().write_all(&output.stderr)?;
        if !output.status.success() {
            bail!(
                "{} {:?} exited {}",
                self.program,
                self.arguments,
                output.status
            );
        }
        Ok(())
    }
}

fn launchd_loaded(name: &str) -> Result<bool> {
    let output = Command::new("launchctl")
        .args(["print", &format!("system/{name}")])
        .output()
        .context("query launchd service")?;
    if output.status.success() {
        return Ok(true);
    }
    let error = String::from_utf8_lossy(&output.stderr);
    if error.contains("Could not find service") || error.contains("Service not found") {
        return Ok(false);
    }
    bail!("launchctl print failed: {}", error.trim())
}

fn service_status(platform: Platform, name: &str) -> Result<()> {
    let operation = match platform {
        Platform::Systemd => {
            Operation::new("systemctl", &["is-active", &format!("{name}.service")])
        }
        Platform::Launchd => Operation::new("launchctl", &["print", &format!("system/{name}")]),
        Platform::Procd => Operation::new(&platform.path(name).to_string_lossy(), &["status"]),
        Platform::Windows => bail!("Windows status uses the native SCM API"),
    };
    let output = Command::new(&operation.program)
        .args(&operation.arguments)
        .output()
        .context("query service status")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let status = if output.status.success() {
        match platform {
            Platform::Systemd => {
                if matches!(stdout.trim(), "active" | "activating" | "reloading") {
                    "running"
                } else {
                    "stopped"
                }
            }
            Platform::Launchd => {
                if stdout.contains("state = running") {
                    "running"
                } else {
                    "stopped"
                }
            }
            Platform::Procd => {
                if stdout.trim_start().starts_with("running") {
                    "running"
                } else {
                    "stopped"
                }
            }
            Platform::Windows => unreachable!(),
        }
    } else if platform == Platform::Launchd
        && (stderr.contains("Could not find service") || stderr.contains("Service not found"))
        || platform != Platform::Launchd && output.status.code() == Some(3)
    {
        "stopped"
    } else {
        bail!("{} status failed: {}{}", operation.program, stdout, stderr);
    };
    println!("{status}");
    Ok(())
}

fn plan(platform: Platform, name: &str, action: &str) -> Result<Vec<Operation>> {
    if platform == Platform::Windows {
        bail!("Windows lifecycle uses the native SCM API");
    }
    let unit = format!("{name}.service");
    let label = format!("system/{name}");
    let path = platform.path(name).to_string_lossy().into_owned();
    match (platform, action) {
        (Platform::Systemd, "install") => Ok(vec![
            Operation::new("systemctl", &["daemon-reload"]),
            Operation::new("systemctl", &["enable", &unit]),
        ]),
        (Platform::Systemd, "uninstall") => Ok(vec![Operation::new(
            "systemctl",
            &["disable", "--now", &unit],
        )]),
        (Platform::Systemd, "status") => Ok(vec![Operation::new("systemctl", &["status", &unit])]),
        (Platform::Systemd, "start" | "stop" | "restart") => {
            Ok(vec![Operation::new("systemctl", &[action, &unit])])
        }
        (Platform::Launchd, "install") => Ok(vec![]),
        (Platform::Launchd, "start") => Ok(vec![Operation::new(
            "launchctl",
            &["bootstrap", "system", &path],
        )]),
        (Platform::Launchd, "stop") => Ok(vec![Operation::new("launchctl", &["bootout", &label])]),
        (Platform::Launchd, "restart") => Ok(vec![Operation::new(
            "launchctl",
            &["kickstart", "-k", &label],
        )]),
        (Platform::Launchd, "status") => Ok(vec![Operation::new("launchctl", &["print", &label])]),
        (Platform::Launchd, "uninstall") => {
            Ok(vec![Operation::new("launchctl", &["bootout", &label])])
        }
        (Platform::Procd, "install") => Ok(vec![Operation::new(&path, &["enable"])]),
        (Platform::Procd, "uninstall") => Ok(vec![
            Operation::new(&path, &["stop"]),
            Operation::new(&path, &["disable"]),
        ]),
        (Platform::Procd, "start" | "stop" | "restart" | "status") => {
            Ok(vec![Operation::new(&path, &[action])])
        }
        _ => bail!("unknown service action {action}"),
    }
}

fn write_new(path: &Path, contents: &str, executable: bool) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| {
            format!(
                "create service definition {}; existing files are not overwritten",
                path.display()
            )
        })?;
    file.write_all(contents.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(if executable {
            0o755
        } else {
            0o644
        }))?;
    }
    #[cfg(not(unix))]
    let _ = executable;
    file.sync_all()?;
    Ok(())
}

pub fn run(args: &[String]) -> Result<()> {
    if args.is_empty()
        || args
            .iter()
            .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        println!("Usage: mosdns-rs service generate|install|uninstall|start|stop|restart|status\nOptions: --platform systemd|launchd|procd|windows --name NAME -d DIRECTORY -c CONFIG --cpu N\nGenerate only: --binary PATH -o OUTPUT (defaults to stdout; Windows emits a JSON preview)\nDefault service name: mosdns-rs; existing definitions are never overwritten.");
        return Ok(());
    }
    let action = &args[0];
    if ![
        "generate",
        "install",
        "uninstall",
        "start",
        "stop",
        "restart",
        "status",
    ]
    .contains(&action.as_str())
    {
        bail!("unknown service action {action}");
    }
    let binary = std::env::current_exe()?;
    let mut definition = Definition {
        name: crate::windows_service::DEFAULT_NAME.into(),
        binary: binary
            .to_str()
            .context("service binary path is not UTF-8")?
            .into(),
        directory: binary
            .parent()
            .context("service binary has no parent")?
            .to_str()
            .context("service working directory is not UTF-8")?
            .into(),
        config: "config.yaml".into(),
        cpu: None,
    };
    let mut selected_platform = None;
    let mut binary_override = None;
    let mut directory_override = None;
    let mut output = None;
    let mut index = 1;
    while index < args.len() {
        let (flag, inline) = args[index]
            .split_once('=')
            .map_or((args[index].as_str(), None), |(key, value)| {
                (key, Some(value))
            });
        let value = if let Some(value) = inline {
            value
        } else {
            index += 1;
            args.get(index)
                .context("missing service option value")?
                .as_str()
        };
        match flag {
            "--platform" => selected_platform = Some(Platform::parse(value)?),
            "--name" => definition.name = value.into(),
            "--binary" if action == "generate" => binary_override = Some(value.to_owned()),
            "-d" | "--dir" => directory_override = Some(value.to_owned()),
            "-c" | "--config" => definition.config = value.into(),
            "--cpu" => {
                let cpu: i64 = value.parse().context("invalid --cpu")?;
                definition.cpu = if cpu > 0 {
                    Some(usize::try_from(cpu)?)
                } else {
                    None
                };
            }
            "-o" | "--output" if action == "generate" => output = Some(PathBuf::from(value)),
            _ => bail!("unknown service option {flag}"),
        }
        index += 1;
    }
    let platform = selected_platform.map_or_else(Platform::native, Ok)?;
    if let Some(binary) = binary_override {
        definition.binary = absolute_for_platform(&binary, platform)?;
    }
    if let Some(directory) = directory_override {
        definition.directory = absolute_for_platform(&directory, platform)?;
    }
    definition.validate()?;
    if action == "generate" {
        let contents = definition.render(platform)?;
        if let Some(path) = output {
            write_new(&path, &contents, platform == Platform::Procd)?;
        } else {
            io::stdout().write_all(contents.as_bytes())?;
        }
        return Ok(());
    }
    if platform != Platform::native()? {
        bail!("service operations must use this host's native service manager; use generate for another platform");
    }
    if platform == Platform::Windows {
        #[cfg(windows)]
        return crate::windows_service::manage(
            action,
            &definition.name,
            Path::new(&definition.binary),
            &definition.arguments()[1..],
        );
        #[cfg(not(windows))]
        bail!("Windows service operations require a Windows host");
    }
    let path = platform.path(&definition.name);
    if action == "install" {
        write_new(
            &path,
            &definition.render(platform)?,
            platform == Platform::Procd,
        )?;
        println!("service definition written to {}", path.display());
    } else {
        if fs::symlink_metadata(&path)?.file_type().is_symlink() {
            bail!("refuse to operate on a symlinked service definition");
        }
        if !fs::read_to_string(&path)
            .with_context(|| format!("read installed definition {}", path.display()))?
            .contains(MARKER)
        {
            bail!("refuse to modify a service definition not created by mosdns-rs");
        }
    }
    if action == "status" {
        return service_status(platform, &definition.name);
    }
    if platform == Platform::Launchd
        && matches!(action.as_str(), "start" | "stop" | "restart" | "uninstall")
    {
        let loaded = launchd_loaded(&definition.name)?;
        match action.as_str() {
            "start" | "restart" if !loaded => {
                Operation::new(
                    "launchctl",
                    &["bootstrap", "system", &path.to_string_lossy()],
                )
                .run()?;
                return Ok(());
            }
            "start" if loaded => {
                Operation::new(
                    "launchctl",
                    &["kickstart", &format!("system/{}", definition.name)],
                )
                .run()?;
                return Ok(());
            }
            "stop" if !loaded => return Ok(()),
            "uninstall" if !loaded => {
                fs::remove_file(&path)?;
                return Ok(());
            }
            _ => (),
        }
    }
    for operation in plan(platform, &definition.name, action)? {
        operation.run()?;
    }
    if action == "uninstall" {
        fs::remove_file(&path)?;
        if platform == Platform::Systemd {
            Operation::new("systemctl", &["daemon-reload"]).run()?;
        }
    }
    Ok(())
}

fn absolute(value: &str) -> Result<String> {
    let path = Path::new(value);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    Ok(absolute
        .to_str()
        .context("service path is not UTF-8")?
        .into())
}

fn absolute_for_platform(value: &str, platform: Platform) -> Result<String> {
    if platform == Platform::Windows {
        let bytes = value.as_bytes();
        if value.starts_with("\\\\")
            || (bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && matches!(bytes[2], b'\\' | b'/'))
        {
            return Ok(value.to_owned());
        }
    }
    absolute(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn definition() -> Definition {
        Definition {
            name: "mosdns-rs-test".into(),
            binary: "/tmp/path with space/mosdns-rs".into(),
            directory: "/tmp/query $d %i".into(),
            config: "a<&'\".yaml".into(),
            cpu: Some(2),
        }
    }
    #[test]
    fn manager_templates_preserve_arguments_and_escape_each_format() {
        let definition = definition();
        let systemd = definition.render(Platform::Systemd).unwrap();
        assert!(systemd.contains("\"/tmp/path with space/mosdns-rs\" \"start\" \"--as-service\""));
        assert!(systemd.contains("query $$d %%i"));
        assert!(systemd.contains("\"--cpu\" \"2\""));
        let launchd = definition.render(Platform::Launchd).unwrap();
        assert!(launchd.contains("a&lt;&amp;&apos;&quot;.yaml"));
        assert!(launchd.contains("<key>ProgramArguments</key>"));
        let procd = definition.render(Platform::Procd).unwrap();
        assert!(procd.contains("'/tmp/path with space/mosdns-rs' 'start'"));
        assert!(procd.contains("'\"'\"'"));
    }
    #[test]
    fn definition_write_never_overwrites_or_follows_existing_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("service");
        fs::write(&path, "original").unwrap();
        assert!(write_new(&path, "replacement", false).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "original");
        #[cfg(unix)]
        {
            let link = directory.path().join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(write_new(&link, "replacement", false).is_err());
        }
    }
    #[test]
    fn invalid_names_and_paths_fail_before_manager_commands() {
        for name in ["../other", "-flag", "name\nInjected", "", "name/child"] {
            let mut definition = definition();
            definition.name = name.into();
            assert!(definition.validate().is_err());
        }
        let mut definition = definition();
        definition.config = "line\nbreak".into();
        assert!(definition.render(Platform::Systemd).is_err());
        assert_eq!(Platform::parse("windows").unwrap(), Platform::Windows);
        assert!(plan(Platform::Windows, "dns", "start").is_err());
    }
    #[test]
    fn lifecycle_plans_are_explicit_and_install_does_not_start_daemons() {
        assert_eq!(
            plan(Platform::Systemd, "dns", "install").unwrap(),
            vec![
                Operation::new("systemctl", &["daemon-reload"]),
                Operation::new("systemctl", &["enable", "dns.service"])
            ]
        );
        assert!(plan(Platform::Launchd, "dns", "install")
            .unwrap()
            .is_empty());
        assert_eq!(
            plan(Platform::Procd, "dns", "start").unwrap(),
            vec![Operation::new("/etc/init.d/dns", &["start"])]
        );
        assert!(plan(Platform::Systemd, "dns", "invalid").is_err());
    }

    #[test]
    fn windows_definition_can_be_previewed_without_invoking_a_service_manager() {
        let platform =
            Platform::parse("windows").expect("Windows service definitions are supported");
        let definition = definition();
        let rendered = definition.render(platform).unwrap();
        let rendered: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(rendered["name"], definition.name);
        assert_eq!(rendered["arguments"][0], "start");
        assert_eq!(rendered["arguments"][1], "--as-service");
        assert!(rendered["display_name"].as_str().unwrap().contains(MARKER));
        assert_eq!(rendered["arguments"][3], definition.directory);
        assert_eq!(rendered["arguments"][5], definition.config);
        assert_eq!(rendered["arguments"][8], "--service-name");
        assert_eq!(rendered["arguments"][9], definition.name);
    }

    #[test]
    fn cross_platform_windows_preview_preserves_drive_and_unc_paths() {
        for path in [
            r"C:\Program Files\mosdns-rs.exe",
            r"\\server\share\dns config",
        ] {
            assert_eq!(
                absolute_for_platform(path, Platform::Windows).unwrap(),
                path
            );
        }
        assert!(absolute_for_platform("relative", Platform::Windows)
            .unwrap()
            .ends_with("relative"));
    }
}
