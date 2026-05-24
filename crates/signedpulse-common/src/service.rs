//! Helpers for installing the server/client as a background service: systemd
//! units on Linux and a launchd LaunchAgent on macOS. Rendering and file
//! placement live here so both binaries share one implementation.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where a service should be installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceTarget {
    /// Linux system-wide unit in `/etc/systemd/system`.
    SystemdSystem,
    /// Linux per-user unit in `~/.config/systemd/user`.
    SystemdUser,
    /// macOS LaunchAgent in `~/Library/LaunchAgents`.
    LaunchdAgent,
}

/// Everything needed to render and place a service definition.
pub struct ServiceSpec {
    /// systemd unit base name, e.g. `signedpulse-server`.
    pub unit_name: String,
    /// Human-readable description.
    pub description: String,
    /// Absolute path to the binary to launch.
    pub exec_path: PathBuf,
    /// Arguments passed to the binary (e.g. `["--config", "/etc/.../x.toml"]`).
    pub args: Vec<String>,
    /// launchd label, e.g. `com.signedpulse.client`.
    pub launchd_label: String,
}

/// Result of an install attempt.
pub struct InstallReport {
    /// Where the unit/plist was written.
    pub path: PathBuf,
    /// Commands needed to (re)load and start the service.
    pub activation_commands: Vec<String>,
    /// True if this tool successfully ran the activation commands itself.
    pub activated: bool,
    /// Optional human note (e.g. why activation was skipped or failed).
    pub note: Option<String>,
}

/// Platform-appropriate default config path for a component ("server"/"client").
pub fn default_config_path(component: &str) -> PathBuf {
    PathBuf::from("/etc/signedpulse").join(format!("{component}.toml"))
}

/// Write a config file, creating parent directories. When `secret` is true the
/// file is created with owner-only (`0600`) permissions on unix, so a config
/// holding a private key is never world-readable.
pub fn write_config_file(path: &Path, contents: &str, secret: bool) -> io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mode = if secret { 0o600 } else { 0o644 };
    // Write to a unique temp in the same directory with O_EXCL + perms set at
    // creation + no symlink follow, then atomically rename over the target. A
    // crash can never leave a partially written (or world-readable) secret.
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode).custom_flags(libc::O_NOFOLLOW);
    }
    let _ = mode;
    let mut f = opts.open(&tmp)?;
    f.write_all(contents.as_bytes())?;
    f.sync_all().ok();
    drop(f);
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Resolve a service-manager tool to an absolute path so an attacker-controlled
/// `$PATH` (e.g. under `sudo`) can't substitute a malicious `systemctl`/`launchctl`.
/// Fails closed: returns `None` if the tool is not found in a trusted location,
/// rather than falling back to a `$PATH`-resolved bare name.
fn resolve_tool(name: &str) -> Option<PathBuf> {
    for dir in ["/usr/bin", "/bin", "/usr/sbin", "/sbin"] {
        let p = Path::new(dir).join(name);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Quote a token for a systemd `ExecStart=` line: strip control characters
/// (notably newlines, which would otherwise terminate the directive and let an
/// attacker-influenced path inject further unit directives), then double-quote
/// and escape so embedded spaces/quotes/backslashes are handled by systemd's
/// own parser rather than splitting the command.
fn systemd_quote(s: &str) -> String {
    let cleaned: String = s.chars().filter(|c| !c.is_control()).collect();
    format!("\"{}\"", cleaned.replace('\\', "\\\\").replace('"', "\\\""))
}

fn exec_line(exec_path: &Path, args: &[String]) -> String {
    let mut line = systemd_quote(&exec_path.display().to_string());
    for a in args {
        line.push(' ');
        line.push_str(&systemd_quote(a));
    }
    line
}

/// Render a systemd unit file.
pub fn render_systemd_unit(spec: &ServiceSpec, user: bool) -> String {
    let wanted_by = if user {
        "default.target"
    } else {
        "multi-user.target"
    };
    // Strip control characters (notably newlines) from the description so it can
    // never terminate the `Description=` line and inject further unit directives.
    let description: String = spec
        .description
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    format!(
        "[Unit]\n\
         Description={description}\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exec}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         NoNewPrivileges=true\n\
         \n\
         [Install]\n\
         WantedBy={wanted_by}\n",
        description = description,
        exec = exec_line(&spec.exec_path, &spec.args),
        wanted_by = wanted_by,
    )
}

/// Minimal XML escaping for text inside a plist `<string>`.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Render a macOS launchd LaunchAgent plist.
pub fn render_launchd_plist(spec: &ServiceSpec) -> String {
    let mut program_args = format!(
        "    <string>{}</string>\n",
        xml_escape(&spec.exec_path.display().to_string())
    );
    for a in &spec.args {
        program_args.push_str(&format!("    <string>{}</string>\n", xml_escape(a)));
    }
    let label = xml_escape(&spec.launchd_label);
    // Write logs under the user's own (non-world-writable) Library/Logs rather
    // than a predictable path in the sticky `/tmp`, where a local attacker could
    // pre-plant a symlink or file to redirect/read the daemon's output. If HOME
    // is somehow unset, omit the log paths entirely instead of falling back to
    // an unsafe location.
    let log_section = match std::env::var_os("HOME") {
        Some(home) => {
            let dir = Path::new(&home).join("Library/Logs");
            format!(
                "         \x20 <key>StandardOutPath</key>\n\
                 \x20 <string>{out}</string>\n\
                 \x20 <key>StandardErrorPath</key>\n\
                 \x20 <string>{err}</string>\n",
                out = xml_escape(
                    &dir.join(format!("{}.out.log", spec.launchd_label))
                        .display()
                        .to_string()
                ),
                err = xml_escape(
                    &dir.join(format!("{}.err.log", spec.launchd_label))
                        .display()
                        .to_string()
                ),
            )
        }
        None => String::new(),
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \x20 <key>Label</key>\n\
         \x20 <string>{label}</string>\n\
         \x20 <key>ProgramArguments</key>\n\
         \x20 <array>\n\
         {program_args}\
         \x20 </array>\n\
         \x20 <key>RunAtLoad</key>\n\
         \x20 <true/>\n\
         \x20 <key>KeepAlive</key>\n\
         \x20 <true/>\n\
         {log_section}\
         </dict>\n\
         </plist>\n",
        label = label,
        program_args = program_args,
        log_section = log_section,
    )
}

/// Render the service definition appropriate for `target`.
pub fn render(spec: &ServiceSpec, target: ServiceTarget) -> String {
    match target {
        ServiceTarget::SystemdSystem => render_systemd_unit(spec, false),
        ServiceTarget::SystemdUser => render_systemd_unit(spec, true),
        ServiceTarget::LaunchdAgent => render_launchd_plist(spec),
    }
}

/// Compute the file path where the definition should be installed.
pub fn unit_path(spec: &ServiceSpec, target: ServiceTarget) -> io::Result<PathBuf> {
    let home = || {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))
    };
    Ok(match target {
        ServiceTarget::SystemdSystem => {
            PathBuf::from("/etc/systemd/system").join(format!("{}.service", spec.unit_name))
        }
        ServiceTarget::SystemdUser => home()?
            .join(".config/systemd/user")
            .join(format!("{}.service", spec.unit_name)),
        ServiceTarget::LaunchdAgent => home()?
            .join("Library/LaunchAgents")
            .join(format!("{}.plist", spec.launchd_label)),
    })
}

/// The commands a user (or this tool) must run to activate the service.
pub fn activation_commands(spec: &ServiceSpec, target: ServiceTarget, path: &Path) -> Vec<String> {
    match target {
        ServiceTarget::SystemdSystem => vec![
            "systemctl daemon-reload".to_string(),
            format!("systemctl enable --now {}", spec.unit_name),
        ],
        ServiceTarget::SystemdUser => vec![
            "systemctl --user daemon-reload".to_string(),
            format!("systemctl --user enable --now {}", spec.unit_name),
        ],
        ServiceTarget::LaunchdAgent => {
            vec![format!("launchctl load -w {}", path.display())]
        }
    }
}

/// Write the service definition and, if `activate` is true, attempt to run the
/// activation commands. Activation failures are reported, not fatal.
pub fn install(
    spec: &ServiceSpec,
    target: ServiceTarget,
    activate: bool,
) -> io::Result<InstallReport> {
    let path = unit_path(spec, target)?;
    // Write through the no-symlink-follow helper (0644 for the unit/plist).
    write_config_file(&path, &render(spec, target), false)?;

    let commands = activation_commands(spec, target, &path);
    let mut report = InstallReport {
        path,
        activation_commands: commands.clone(),
        activated: false,
        note: None,
    };

    if !activate {
        report.note = Some("activation skipped; run the commands below to start it".to_string());
        return Ok(report);
    }

    match run_activation(target, &report.path, spec) {
        Ok(()) => report.activated = true,
        Err(e) => {
            report.note = Some(format!(
                "could not activate automatically ({e}); run the commands below manually"
            ));
        }
    }
    Ok(report)
}

fn run_activation(target: ServiceTarget, path: &Path, spec: &ServiceSpec) -> io::Result<()> {
    let mut invocations: Vec<(&str, Vec<String>)> = Vec::new();
    match target {
        ServiceTarget::SystemdSystem => {
            invocations.push(("systemctl", vec!["daemon-reload".into()]));
            invocations.push((
                "systemctl",
                vec!["enable".into(), "--now".into(), spec.unit_name.clone()],
            ));
        }
        ServiceTarget::SystemdUser => {
            invocations.push(("systemctl", vec!["--user".into(), "daemon-reload".into()]));
            invocations.push((
                "systemctl",
                vec![
                    "--user".into(),
                    "enable".into(),
                    "--now".into(),
                    spec.unit_name.clone(),
                ],
            ));
        }
        ServiceTarget::LaunchdAgent => {
            invocations.push((
                "launchctl",
                vec!["load".into(), "-w".into(), path.display().to_string()],
            ));
        }
    }

    for (program, args) in invocations {
        let tool = resolve_tool(program).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("`{program}` not found in a trusted system location"),
            )
        })?;
        let status = Command::new(tool).args(&args).status()?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "`{program} {}` exited with {status}",
                args.join(" ")
            )));
        }
    }
    Ok(())
}

/// Whether the OS service manager reports the service as running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceState {
    Active,
    Inactive,
    /// Could not determine (no service manager, or service not installed).
    Unknown,
}

/// Best-effort query of the OS service manager. Returns the state plus a short
/// human description of how it was determined. Never fails — an unavailable
/// service manager yields `Unknown`. Read-only.
pub fn query_service(unit_name: &str, launchd_label: &str) -> (ServiceState, String) {
    if cfg!(target_os = "macos") {
        // `launchctl list <label>` exits 0 when the agent is loaded.
        let launchctl = match resolve_tool("launchctl") {
            Some(p) => p,
            None => return (ServiceState::Unknown, "launchctl unavailable".into()),
        };
        match Command::new(launchctl)
            .arg("list")
            .arg(launchd_label)
            .status()
        {
            Ok(s) if s.success() => (ServiceState::Active, "launchctl: loaded".into()),
            Ok(_) => (ServiceState::Inactive, "launchctl: not loaded".into()),
            Err(_) => (ServiceState::Unknown, "launchctl unavailable".into()),
        }
    } else {
        // Try the system manager, then the per-user manager.
        if let Some(state) = systemctl_is_active(&[], unit_name) {
            return (state, "systemctl".into());
        }
        if let Some(state) = systemctl_is_active(&["--user"], unit_name) {
            return (state, "systemctl --user".into());
        }
        (ServiceState::Unknown, "systemctl unavailable".into())
    }
}

fn systemctl_is_active(prefix: &[&str], unit_name: &str) -> Option<ServiceState> {
    let output = Command::new(resolve_tool("systemctl")?)
        .args(prefix)
        .arg("is-active")
        .arg(unit_name)
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    match stdout.trim() {
        "active" => Some(ServiceState::Active),
        // `inactive`/`failed`/`activating` etc. mean "known but not active".
        "inactive" | "failed" | "deactivating" | "activating" => Some(ServiceState::Inactive),
        // "unknown" (unit not loaded) — let the caller try the next manager.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> ServiceSpec {
        ServiceSpec {
            unit_name: "signedpulse-server".into(),
            description: "SignedPulse server".into(),
            exec_path: PathBuf::from("/usr/local/bin/signedpulse-server"),
            args: vec!["--config".into(), "/etc/signedpulse/server.toml".into()],
            launchd_label: "com.signedpulse.server".into(),
        }
    }

    #[test]
    fn systemd_unit_contains_exec_and_install_target() {
        let unit = render_systemd_unit(&spec(), false);
        // Args are systemd-quoted to defeat whitespace/newline injection.
        assert!(unit.contains(
            "ExecStart=\"/usr/local/bin/signedpulse-server\" \"--config\" \"/etc/signedpulse/server.toml\""
        ));
        assert!(unit.contains("WantedBy=multi-user.target"));
        assert!(unit.contains("Restart=on-failure"));
    }

    #[test]
    fn systemd_quote_strips_newlines_preventing_directive_injection() {
        let s = ServiceSpec {
            args: vec!["--config".into(), "/x\nExecStartPre=/bin/touch /pwn".into()],
            ..spec()
        };
        let unit = render_systemd_unit(&s, false);
        // The injected newline must not survive to start a new directive.
        assert!(!unit.contains("\nExecStartPre="));
    }

    #[test]
    fn systemd_user_unit_uses_default_target() {
        let unit = render_systemd_unit(&spec(), true);
        assert!(unit.contains("WantedBy=default.target"));
    }

    #[test]
    fn launchd_plist_lists_each_program_argument() {
        let plist = render_launchd_plist(&spec());
        assert!(plist.contains("<string>/usr/local/bin/signedpulse-server</string>"));
        assert!(plist.contains("<string>--config</string>"));
        assert!(plist.contains("<string>/etc/signedpulse/server.toml</string>"));
        assert!(plist.contains("<key>Label</key>"));
        assert!(plist.contains("<string>com.signedpulse.server</string>"));
    }

    #[test]
    fn unit_path_for_system_is_in_etc() {
        let p = unit_path(&spec(), ServiceTarget::SystemdSystem).unwrap();
        assert_eq!(
            p,
            PathBuf::from("/etc/systemd/system/signedpulse-server.service")
        );
    }

    #[test]
    fn activation_commands_match_target() {
        let s = spec();
        let cmds = activation_commands(&s, ServiceTarget::SystemdSystem, Path::new("/x"));
        assert_eq!(cmds[0], "systemctl daemon-reload");
        assert_eq!(cmds[1], "systemctl enable --now signedpulse-server");
    }
}
