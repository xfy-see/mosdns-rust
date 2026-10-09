// SPDX-License-Identifier: GPL-3.0-or-later
//! Process collector with the Prometheus client_golang process metric names.
//! Collection failures omit the affected sample, like its default ReportErrors=false.
//! Linux network counters describe the process's network namespace (procfs netstat),
//! as they do in the Go collector; they are not per-upstream byte counters.
#[cfg(all(feature = "full", unix))]
use std::fmt::Write;
#[cfg(feature = "full")]
mod registry;
#[cfg(feature = "full")]
pub use registry::{Counter, Gauge, Histogram, MetricRegistry, Registerer};
#[cfg(not(feature = "full"))]
mod minimal;
#[cfg(not(feature = "full"))]
pub use minimal::{Counter, Gauge, Histogram, MetricRegistry, Registerer};

#[derive(Default)]
#[cfg(all(feature = "full", unix))]
struct Samples(String);
#[cfg(all(feature = "full", unix))]
impl Samples {
    fn add(&mut self, name: &str, kind: &str, help: &str, value: impl std::fmt::Display) {
        let _ = writeln!(
            self.0,
            "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}"
        );
    }
}

/// Collect only metrics supported by this host, without changing process state.
pub fn process_metrics() -> String {
    #[cfg(all(feature = "full", unix))]
    {
        let mut samples = Samples::default();
        collect_unix(&mut samples);
        #[cfg(target_os = "linux")]
        collect_linux(&mut samples);
        #[cfg(target_os = "macos")]
        collect_macos(&mut samples);
        samples.0
    }
    #[cfg(not(all(feature = "full", unix)))]
    String::new()
}

#[cfg(all(feature = "full", unix))]
fn collect_unix(samples: &mut Samples) {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage initializes this writable struct on success.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } == 0 {
        let usage = unsafe { usage.assume_init() };
        let cpu = usage.ru_utime.tv_sec as f64
            + usage.ru_stime.tv_sec as f64
            + (usage.ru_utime.tv_usec as f64 + usage.ru_stime.tv_usec as f64) / 1_000_000.0;
        samples.add(
            "process_cpu_seconds_total",
            "counter",
            "Total user and system CPU time spent in seconds.",
            cpu,
        );
    }
    for (resource, name, help) in [
        (
            libc::RLIMIT_NOFILE,
            "process_max_fds",
            "Maximum number of open file descriptors.",
        ),
        (
            libc::RLIMIT_AS,
            "process_virtual_memory_max_bytes",
            "Maximum amount of virtual memory available in bytes.",
        ),
    ] {
        let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        // SAFETY: getrlimit initializes this writable struct on success.
        if unsafe { libc::getrlimit(resource, limit.as_mut_ptr()) } == 0 {
            samples.add(name, "gauge", help, unsafe { limit.assume_init() }.rlim_cur);
        }
    }
    let directory = if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    if let Ok(mut entries) = std::fs::read_dir(directory) {
        let Ok(count) = entries.try_fold(0usize, |count, entry| entry.map(|_| count + 1)) else {
            return;
        };
        // read_dir itself owns one descriptor during this enumeration.
        samples.add(
            "process_open_fds",
            "gauge",
            "Number of open file descriptors.",
            count.saturating_sub(1),
        );
    }
}

#[cfg(all(feature = "full", any(target_os = "linux", test)))]
fn linux_stat(text: &str, page_size: u64, ticks: f64, boot_time: u64) -> Option<(u64, u64, f64)> {
    // comm can include spaces and ')' characters; split at its last closing delimiter.
    let fields: Vec<_> = text
        .get(text.rfind(')')? + 1..)?
        .split_whitespace()
        .collect();
    let virtual_size = fields.get(20)?.parse().ok()?;
    let resident_pages: i64 = fields.get(21)?.parse().ok()?;
    let resident_size = u64::try_from(resident_pages).ok()?.checked_mul(page_size)?;
    let start_ticks: u64 = fields.get(19)?.parse().ok()?;
    if !ticks.is_finite() || ticks <= 0.0 {
        return None;
    }
    Some((
        virtual_size,
        resident_size,
        boot_time as f64 + start_ticks as f64 / ticks,
    ))
}

#[cfg(all(feature = "full", any(target_os = "linux", test)))]
fn network_octets(text: &str) -> Option<(u64, u64)> {
    let mut lines = text.lines();
    while let (Some(names), Some(values)) = (lines.next(), lines.next()) {
        let names: Vec<_> = names.split_whitespace().collect();
        let values: Vec<_> = values.split_whitespace().collect();
        if names.first() != Some(&"IpExt:") {
            continue;
        }
        if values.first() != Some(&"IpExt:") || names.len() != values.len() {
            return None;
        }
        let read = |name| -> Option<u64> {
            match names.iter().position(|field| *field == name) {
                Some(index) => values[index].parse().ok(),
                None => Some(0),
            }
        };
        return Some((read("InOctets")?, read("OutOctets")?));
    }
    None
}

#[cfg(all(feature = "full", target_os = "linux"))]
fn collect_linux(samples: &mut Samples) {
    let memory = || {
        let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
        // SAFETY: sysconf has no pointer arguments and reads system constants.
        let pages = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        linux_stat(&stat, u64::try_from(pages).ok()?, ticks as f64, 0)
    };
    if let Some((virtual_size, resident_size, start_time)) = memory() {
        samples.add(
            "process_virtual_memory_bytes",
            "gauge",
            "Virtual memory size in bytes.",
            virtual_size,
        );
        samples.add(
            "process_resident_memory_bytes",
            "gauge",
            "Resident memory size in bytes.",
            resident_size,
        );
        if let Some(boot_time) = std::fs::read_to_string("/proc/stat").ok().and_then(|boot| {
            boot.lines()
                .find_map(|line| line.strip_prefix("btime "))
                .and_then(|value| value.trim().parse::<u64>().ok())
        }) {
            samples.add(
                "process_start_time_seconds",
                "gauge",
                "Start time of the process since unix epoch in seconds.",
                start_time + boot_time as f64,
            );
        }
    }
    if let Some((received, sent)) = std::fs::read_to_string("/proc/self/net/netstat")
        .ok()
        .and_then(|text| network_octets(&text))
    {
        samples.add(
            "process_network_receive_bytes_total",
            "counter",
            "Number of bytes received over the process network namespace.",
            received,
        );
        samples.add(
            "process_network_transmit_bytes_total",
            "counter",
            "Number of bytes sent over the process network namespace.",
            sent,
        );
    }
}

#[cfg(all(feature = "full", target_os = "macos"))]
fn collect_macos(samples: &mut Samples) {
    let mut info = std::mem::MaybeUninit::<libc::mach_task_basic_info>::uninit();
    let mut count = libc::MACH_TASK_BASIC_INFO_COUNT;
    // SAFETY: task_info receives a correctly sized/aligned writable info buffer.
    // libc retains this stable Darwin ABI but deprecates its convenience wrapper.
    #[allow(deprecated)]
    let result = unsafe {
        libc::task_info(
            libc::mach_task_self(),
            libc::MACH_TASK_BASIC_INFO,
            info.as_mut_ptr().cast(),
            &mut count,
        )
    };
    if result == libc::KERN_SUCCESS && count == libc::MACH_TASK_BASIC_INFO_COUNT {
        let info = unsafe { info.assume_init() };
        samples.add(
            "process_virtual_memory_bytes",
            "gauge",
            "Virtual memory size in bytes.",
            info.virtual_size,
        );
        samples.add(
            "process_resident_memory_bytes",
            "gauge",
            "Resident memory size in bytes.",
            info.resident_size,
        );
    }
}

#[cfg(all(feature = "full", test))]
mod tests {
    use super::*;

    #[test]
    fn proc_stat_handles_spaces_and_parentheses_and_uses_host_units() {
        let mut fields = vec!["0"; 22];
        fields[0] = "S";
        fields[19] = "1234";
        fields[20] = "987654";
        fields[21] = "37";
        let text = format!("12 (name with ) space) {}", fields.join(" "));
        assert_eq!(
            linux_stat(&text, 4096, 100.0, 1000),
            Some((987654, 151552, 1012.34))
        );
        assert_eq!(linux_stat(&text, 16384, 100.0, 1000).unwrap().1, 606208);
        fields[21] = "-1";
        assert!(linux_stat(&format!("12 (name) {}", fields.join(" ")), 4096, 100.0, 0).is_none());
        assert!(linux_stat("broken", 4096, 100.0, 0).is_none());
        assert!(linux_stat(&text, 4096, 0.0, 0).is_none());
    }

    #[test]
    fn proc_network_fields_are_matched_by_name_without_crossing_sections() {
        assert_eq!(
            network_octets(
                "TcpExt: Other\nTcpExt: 9\nIpExt: OutOctets Other InOctets\nIpExt: 42 9 123\n"
            ),
            Some((123, 42))
        );
        assert_eq!(network_octets("IpExt: Other\nIpExt: 4\n"), Some((0, 0)));
        assert_eq!(
            network_octets("IpExt: InOctets OutOctets\nIpExt: 3\n"),
            None
        );
        assert_eq!(network_octets("IpExt: InOctets\nTcpExt: 3\n"), None);
        assert_eq!(network_octets("IpExt: InOctets\nIpExt: nope\n"), None);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn live_process_metrics_are_typed_unique_and_cpu_does_not_decrease() {
        let sample = process_metrics();
        let cpu = |text: &str| -> f64 {
            text.lines()
                .find_map(|line| line.strip_prefix("process_cpu_seconds_total "))
                .unwrap()
                .parse()
                .unwrap()
        };
        assert!(cpu(&process_metrics()) >= cpu(&sample));
        let mut names = std::collections::HashSet::new();
        for line in sample.lines().filter(|line| !line.starts_with('#')) {
            let mut fields = line.split_whitespace();
            let name = fields.next().unwrap();
            assert!(names.insert(name));
            assert!(sample.contains(&format!("# HELP {name} ")));
            let value: f64 = fields.next().unwrap().parse().unwrap();
            assert!(value.is_finite() && value >= 0.0);
            assert!(fields.next().is_none());
        }
        assert!(names.contains("process_resident_memory_bytes"));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn process_metrics_follow_shared_go_names_types_and_no_labels() {
        let fixture: std::collections::HashMap<String, std::collections::HashMap<String, String>> =
            serde_json::from_str(include_str!("../../../tests/fixtures/process_metrics.json"))
                .unwrap();
        let mut wanted = fixture["unix"].clone();
        if cfg!(target_os = "linux") {
            wanted.extend(fixture["linux"].clone());
        }
        let text = process_metrics();
        for (name, kind) in wanted {
            assert!(text.contains(&format!("# TYPE {name} {}\n", kind.to_lowercase())));
            let samples: Vec<_> = text
                .lines()
                .filter(|line| line.starts_with(&format!("{name} ")))
                .collect();
            assert_eq!(samples.len(), 1, "{name}");
            let value: f64 = samples[0]
                .split_whitespace()
                .nth(1)
                .unwrap()
                .parse()
                .unwrap();
            assert!(value.is_finite() && value >= 0.0);
        }
    }
}
