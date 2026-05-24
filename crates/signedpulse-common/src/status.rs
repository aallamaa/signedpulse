//! Local, on-demand status reporting.
//!
//! A running daemon keeps a live [`ServerStatusSnapshot`] / [`ClientStatusSnapshot`]
//! in memory and writes it to a state file **only when asked** (on SIGUSR1).
//! The `status` subcommand finds the daemon via its PID file, sends the signal,
//! waits for the state file to be refreshed, and prints it. Nothing here touches
//! the network — status is strictly local.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// A verified pulse from a client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PulseInfo {
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub at_unix: i64,
}

/// The result of running the hook command.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HookInfo {
    pub client_id: String,
    pub source_ip: IpAddr,
    pub at_unix: i64,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    /// Decrypted parameter passed to the hook, if any (local state file only).
    #[serde(default)]
    pub param: Option<String>,
}

/// Point-in-time view of the server, written on demand.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerStatusSnapshot {
    pub started_at_unix: i64,
    pub pid: u32,
    /// HELLOs that passed all checks and got a CHALLENGE.
    pub hello_accepted: u64,
    /// RESPONSEs that fully verified.
    pub verified: u64,
    /// Packets dropped for any validation failure.
    pub rejected: u64,
    /// Subset of rejections that were replays.
    pub replays: u64,
    pub last_pulse: Option<PulseInfo>,
    pub last_hook: Option<HookInfo>,
    /// Last verified pulse per client_id.
    pub clients: BTreeMap<String, PulseInfo>,
}

/// Point-in-time view of the client, written on demand. A client may pulse
/// several servers; each gets its own [`ServerLegStatus`] keyed by `server_id`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientStatusSnapshot {
    pub started_at_unix: i64,
    pub pid: u32,
    /// Per-server pulse status, keyed by `server_id`.
    pub servers: BTreeMap<String, ServerLegStatus>,
}

/// Status of one server the client pulses.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerLegStatus {
    pub server_addr: String,
    /// The wire `server_id` signed for this server (may differ from the label).
    #[serde(default)]
    pub server_id: String,
    pub interval_seconds: u64,
    pub last_attempt_at_unix: Option<i64>,
    pub last_success_at_unix: Option<i64>,
    /// "ok" after a successful cycle, otherwise a short error description.
    pub last_result: String,
}

/// Default state-file path for a component ("server"/"client"). Uses
/// `$XDG_RUNTIME_DIR` when set (typical for user sessions and systemd `--user`),
/// otherwise `/run`. Both the daemon and `status` compute this identically.
pub fn default_state_path(component: &str) -> PathBuf {
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run"));
    dir.join("signedpulse")
        .join(format!("{component}.state.json"))
}

/// PID-file path derived from the state path (same name, `.pid` extension), so a
/// single `state_file` config knob controls both files.
pub fn pid_path(state_path: &Path) -> PathBuf {
    state_path.with_extension("pid")
}

/// Candidate default state-file locations to probe when no `state_file` is
/// configured. The daemon writes to exactly one of these (whichever
/// `default_state_path` resolves to in *its* environment), but the `status`
/// command may run in a different environment — e.g. an interactive root shell
/// has `XDG_RUNTIME_DIR=/run/user/0` while the systemd system service has none
/// and writes to `/run`. Probing all of them makes `status` robust to that
/// mismatch. Order: the caller's `$XDG_RUNTIME_DIR`, then `/run`, then the root
/// login runtime dir; de-duplicated.
pub fn state_path_candidates(component: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut add = |dir: PathBuf| {
        let p = dir
            .join("signedpulse")
            .join(format!("{component}.state.json"));
        if !out.contains(&p) {
            out.push(p);
        }
    };
    if let Some(x) = std::env::var_os("XDG_RUNTIME_DIR") {
        add(PathBuf::from(x));
    }
    add(PathBuf::from("/run"));
    add(PathBuf::from("/run/user/0"));
    out
}

/// Create `path` for writing with owner-only (`0600`) permissions set at
/// creation time and without following a symlink at the final component (unix).
/// `exclusive` uses `O_EXCL` (fails if it already exists) for temp files.
fn create_secure(path: &Path, exclusive: bool) -> io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true);
    if exclusive {
        opts.create_new(true);
    } else {
        opts.create(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)
}

/// Atomically write a snapshot as pretty JSON with owner-only permissions. The
/// temp file is created with `O_EXCL`+`0600`+`O_NOFOLLOW` so there is no
/// world-readable window and no symlink-redirection of the write.
pub fn write_snapshot<T: Serialize>(path: &Path, snapshot: &T) -> io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec_pretty(snapshot)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    // Unique per-process temp name; clear any stale leftover from a prior crash.
    let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let mut f = create_secure(&tmp, true)?;
    f.write_all(&json)?;
    f.sync_all().ok();
    drop(f);
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Read and parse a snapshot, returning `None` if the file is missing or invalid.
pub fn read_snapshot<T: DeserializeOwned>(path: &Path) -> Option<T> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Write the current process PID to `path`. Uses the same hardened create path
/// as the snapshot writer (`O_NOFOLLOW` + `O_TRUNC` + `0600`) so a pre-planted
/// symlink at the pid path cannot redirect the write.
pub fn write_pidfile(path: &Path) -> io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = create_secure(path, false)?;
    f.write_all(format!("{}\n", std::process::id()).as_bytes())?;
    Ok(())
}

/// Read a PID from a PID file, if present and parseable. Only strictly positive
/// PIDs are accepted, so a corrupt/hostile pid file can never make us signal a
/// process group (negative pid) or pid 0.
pub fn read_pid(path: &Path) -> Option<i32> {
    let pid: i32 = std::fs::read_to_string(path).ok()?.trim().parse().ok()?;
    if pid > 0 {
        Some(pid)
    } else {
        None
    }
}

/// Whether a process with `pid` currently exists (best effort, unix only).
#[cfg(unix)]
pub fn process_alive(pid: i32) -> bool {
    // `kill(pid, 0)` performs error checking without sending a signal.
    pid > 0 && unsafe { libc::kill(pid, 0) == 0 }
}

/// Best-effort check that `pid` is actually a SignedPulse process before we
/// signal it, to avoid hitting an unrelated process if the daemon's PID was
/// recycled. On Linux we read `/proc/<pid>/comm`; elsewhere we cannot cheaply
/// verify, so we assume true (the positive-PID + liveness checks still apply).
#[cfg(target_os = "linux")]
pub fn process_is_signedpulse(pid: i32) -> bool {
    // Prefer /proc/<pid>/exe (the real executable, not spoofable via prctl like
    // comm) and require the binary name to start with "signedpulse"; fall back
    // to comm only if exe is unreadable.
    if let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) {
        return exe
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with("signedpulse"))
            .unwrap_or(false);
    }
    match std::fs::read_to_string(format!("/proc/{pid}/comm")) {
        Ok(comm) => comm.trim_end().starts_with("signedpulse"),
        Err(_) => false,
    }
}

#[cfg(not(target_os = "linux"))]
pub fn process_is_signedpulse(_pid: i32) -> bool {
    true
}

#[cfg(not(unix))]
pub fn process_alive(_pid: i32) -> bool {
    false
}

/// Ask the daemon to dump its status by sending SIGUSR1 (unix only).
#[cfg(unix)]
pub fn send_dump_signal(pid: i32) -> io::Result<()> {
    if unsafe { libc::kill(pid, libc::SIGUSR1) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
pub fn send_dump_signal(_pid: i32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "status signalling is only supported on unix",
    ))
}

/// Current unix time in seconds.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Human "N ago" string for a past unix timestamp.
pub fn ago(at_unix: i64) -> String {
    let secs = (now_unix() - at_unix).max(0);
    format!("{} ago", duration_words(secs))
}

/// Compact duration like "2h13m", "4m17s", "8s".
pub fn duration_words(secs: i64) -> String {
    let secs = secs.max(0);
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}h{m}m")
    } else if m > 0 {
        format!("{m}m{s}s")
    } else {
        format!("{s}s")
    }
}

/// One-word rendering of a service-manager state.
pub fn service_word(state: crate::service::ServiceState) -> &'static str {
    match state {
        crate::service::ServiceState::Active => "active (running)",
        crate::service::ServiceState::Inactive => "inactive",
        crate::service::ServiceState::Unknown => "unknown",
    }
}

/// Drive an on-demand status dump and read the result: find the daemon via its
/// PID file, send SIGUSR1, wait briefly for the state file to be refreshed, then
/// parse it. Returns `None` if the daemon is not running or did not respond.
pub fn refresh_and_read<T: DeserializeOwned>(state_path: &Path, pid_path: &Path) -> Option<T> {
    let pid = read_pid(pid_path)?;
    if !process_alive(pid) || !process_is_signedpulse(pid) {
        return None;
    }
    let before = file_mtime(state_path);
    // Best-effort signal; even if it fails we still try to read any stale file.
    let _ = send_dump_signal(pid);
    // Poll up to ~1s for the daemon to rewrite the file.
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(20));
        let now = file_mtime(state_path);
        if now != before && now.is_some() {
            break;
        }
    }
    read_snapshot(state_path)
}

/// Resolve the state path for a component and drive a status refresh. When
/// `configured` is set, only that path is used (both daemon and `status` honor
/// the same explicit `state_file`). Otherwise each default candidate location is
/// probed until one yields a live snapshot — handling the case where the daemon
/// and `status` resolved different default paths from their environments.
pub fn refresh_and_read_component<T: DeserializeOwned>(
    component: &str,
    configured: Option<&str>,
) -> Option<T> {
    let paths = match configured {
        Some(p) => vec![PathBuf::from(p)],
        None => state_path_candidates(component),
    };
    for sp in paths {
        if let Some(snap) = refresh_and_read::<T>(&sp, &pid_path(&sp)) {
            return Some(snap);
        }
    }
    None
}

fn file_mtime(path: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn temp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "signedpulse-status-test-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        p
    }

    #[test]
    fn server_snapshot_round_trips() {
        let mut snap = ServerStatusSnapshot {
            started_at_unix: 1000,
            pid: 42,
            verified: 3,
            ..Default::default()
        };
        snap.last_pulse = Some(PulseInfo {
            source_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            source_port: 5555,
            at_unix: 1234,
        });
        snap.clients.insert(
            "client-001".into(),
            PulseInfo {
                source_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
                source_port: 5555,
                at_unix: 1234,
            },
        );

        let path = temp("server.state.json");
        write_snapshot(&path, &snap).unwrap();
        let read: ServerStatusSnapshot = read_snapshot(&path).unwrap();
        assert_eq!(read, snap);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_snapshot_returns_none_for_missing_file() {
        let path = temp("missing.state.json");
        assert!(read_snapshot::<ServerStatusSnapshot>(&path).is_none());
    }

    #[test]
    fn default_state_path_honors_xdg_runtime_dir() {
        // Note: relies on process-wide env; kept self-contained and restored.
        let prev = std::env::var_os("XDG_RUNTIME_DIR");
        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1234");
        assert_eq!(
            default_state_path("server"),
            PathBuf::from("/run/user/1234/signedpulse/server.state.json")
        );
        std::env::remove_var("XDG_RUNTIME_DIR");
        assert_eq!(
            default_state_path("client"),
            PathBuf::from("/run/signedpulse/client.state.json")
        );
        match prev {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }

    #[test]
    fn state_path_candidates_include_run_even_when_xdg_is_set() {
        let prev = std::env::var_os("XDG_RUNTIME_DIR");
        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/0");
        let c = state_path_candidates("server");
        // The XDG path is tried first, but /run must also be probed so `status`
        // finds a system-service daemon that wrote there (the reported bug).
        assert_eq!(
            c[0],
            PathBuf::from("/run/user/0/signedpulse/server.state.json")
        );
        assert!(c.contains(&PathBuf::from("/run/signedpulse/server.state.json")));
        // No duplicate when XDG already equals /run/user/0.
        assert_eq!(c.iter().filter(|p| p.starts_with("/run/user/0")).count(), 1);
        match prev {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }

    #[test]
    fn pid_path_is_sibling_with_pid_extension() {
        assert_eq!(
            pid_path(Path::new("/run/signedpulse/server.state.json")),
            PathBuf::from("/run/signedpulse/server.state.pid")
        );
    }

    #[test]
    fn pidfile_round_trips() {
        let path = temp("server.pid");
        write_pidfile(&path).unwrap();
        assert_eq!(read_pid(&path), Some(std::process::id() as i32));
        let _ = std::fs::remove_file(&path);
    }
}
