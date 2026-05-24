//! Command execution, abstracted behind a trait so tests can mock it.
//!
//! Safety properties of the real executor:
//!   * No shell is involved by default. The configured `argv` is executed
//!     directly via `tokio::process::Command`, so client-derived values can
//!     never be interpreted as shell syntax.
//!   * Placeholders (`{ip}`, `{client_id}`, `{source_port}`) are substituted
//!     into individual argv elements as literal strings.
//!   * Executions are bounded by a semaphore (`max_concurrent`) and each run
//!     has a hard timeout.

use async_trait::async_trait;
use std::net::IpAddr;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Outcome of a command execution.
#[derive(Debug, Clone)]
pub struct CommandResult {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error("failed to spawn command: {0}")]
    Spawn(String),
    #[error("error while waiting for command: {0}")]
    Wait(String),
    #[error("server is at max concurrent executions")]
    AtCapacity,
}

/// Abstraction over "run the configured hook". The real implementation spawns a
/// process; tests substitute a mock that records calls.
#[async_trait]
pub trait CommandExecutor: Send + Sync {
    async fn execute(
        &self,
        client_id: &str,
        source_ip: IpAddr,
        source_port: u16,
        param: Option<&str>,
    ) -> Result<CommandResult, CommandError>;
}

/// Substitute the supported placeholders in a single argv element. Values are
/// inserted literally; there is no shell or glob interpretation anywhere. The
/// `param` is the decrypted client-supplied value (empty string when absent).
pub fn substitute_placeholders(
    arg: &str,
    ip: IpAddr,
    client_id: &str,
    source_port: u16,
    param: &str,
) -> String {
    arg.replace("{ip}", &ip.to_string())
        .replace("{client_id}", client_id)
        .replace("{source_port}", &source_port.to_string())
        .replace("{param}", param)
}

/// Build the fully substituted argv from a template.
pub fn build_argv(
    template: &[String],
    ip: IpAddr,
    client_id: &str,
    source_port: u16,
    param: &str,
) -> Vec<String> {
    template
        .iter()
        .map(|a| substitute_placeholders(a, ip, client_id, source_port, param))
        .collect()
}

/// The production executor: runs the configured argv as a child process.
pub struct ProcessExecutor {
    argv_template: Vec<String>,
    working_dir: Option<String>,
    timeout: Duration,
    allow_shell: bool,
    semaphore: Arc<Semaphore>,
}

impl ProcessExecutor {
    pub fn new(
        argv_template: Vec<String>,
        working_dir: Option<String>,
        timeout: Duration,
        max_concurrent: usize,
        allow_shell: bool,
    ) -> Self {
        ProcessExecutor {
            argv_template,
            working_dir,
            timeout,
            allow_shell,
            semaphore: Arc::new(Semaphore::new(max_concurrent.max(1))),
        }
    }

    fn build_command(
        &self,
        ip: IpAddr,
        client_id: &str,
        source_port: u16,
        param: &str,
    ) -> tokio::process::Command {
        let argv = build_argv(&self.argv_template, ip, client_id, source_port, param);

        let mut cmd = if self.allow_shell {
            // Dangerous path, opt-in only. The substituted argv elements are
            // joined into a single shell string. This re-introduces shell
            // parsing and is therefore gated behind the explicit config flag.
            let joined = argv.join(" ");
            let mut c = tokio::process::Command::new("sh");
            c.arg("-c").arg(joined);
            c
        } else {
            // `argv` is non-empty in practice (config validation rejects an empty
            // command.argv); fall back to a no-op rather than panic-index if it
            // ever isn't.
            let program = argv.first().map(String::as_str).unwrap_or("/bin/false");
            let mut c = tokio::process::Command::new(program);
            c.args(argv.get(1..).unwrap_or(&[]));
            c
        };

        if let Some(dir) = &self.working_dir {
            cmd.current_dir(dir);
        }
        // Run the hook with a sanitized environment: clear inherited variables
        // (PATH, LD_PRELOAD, IFS, BASH_ENV, …) and set a minimal trusted PATH.
        // The daemon often runs as root, so this completes the no-shell hardening
        // and prevents a polluted environment from influencing the hook.
        cmd.env_clear().env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
        // Do not leak the parent's stdin; capture nothing we do not need.
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        cmd
    }
}

#[async_trait]
impl CommandExecutor for ProcessExecutor {
    async fn execute(
        &self,
        client_id: &str,
        source_ip: IpAddr,
        source_port: u16,
        param: Option<&str>,
    ) -> Result<CommandResult, CommandError> {
        // Bound concurrency; refuse rather than queue unboundedly.
        let _permit = self
            .semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| CommandError::AtCapacity)?;

        let mut child = self
            .build_command(source_ip, client_id, source_port, param.unwrap_or(""))
            .spawn()
            .map_err(|e| CommandError::Spawn(e.to_string()))?;

        match tokio::time::timeout(self.timeout, child.wait()).await {
            Ok(Ok(status)) => Ok(CommandResult {
                exit_code: status.code(),
                timed_out: false,
            }),
            Ok(Err(e)) => Err(CommandError::Wait(e.to_string())),
            Err(_elapsed) => {
                // Timed out: kill the child so it does not linger.
                let _ = child.kill().await;
                Ok(CommandResult {
                    exit_code: None,
                    timed_out: true,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
    }

    #[test]
    fn substitutes_all_placeholders() {
        assert_eq!(
            substitute_placeholders("{ip}", ip(), "c1", 5555, "P"),
            "203.0.113.7"
        );
        assert_eq!(
            substitute_placeholders("{client_id}", ip(), "c1", 5555, "P"),
            "c1"
        );
        assert_eq!(
            substitute_placeholders("{source_port}", ip(), "c1", 5555, "P"),
            "5555"
        );
        assert_eq!(
            substitute_placeholders("{param}", ip(), "c1", 5555, "deploy-v1"),
            "deploy-v1"
        );
    }

    #[test]
    fn leaves_non_placeholder_text_untouched() {
        assert_eq!(
            substitute_placeholders("--addr={ip}:{source_port}", ip(), "c", 80, ""),
            "--addr=203.0.113.7:80"
        );
        assert_eq!(
            substitute_placeholders("/usr/local/sbin/hook", ip(), "c", 80, ""),
            "/usr/local/sbin/hook"
        );
    }

    #[test]
    fn build_argv_substitutes_each_element_independently() {
        let template = vec![
            "/usr/local/sbin/signedpulse-hook".to_string(),
            "{ip}".to_string(),
            "{client_id}".to_string(),
            "{param}".to_string(),
        ];
        let argv = build_argv(&template, ip(), "c1", 5555, "the-param");
        assert_eq!(
            argv,
            vec![
                "/usr/local/sbin/signedpulse-hook",
                "203.0.113.7",
                "c1",
                "the-param"
            ]
        );
    }

    #[test]
    fn placeholder_values_are_not_shell_interpreted_in_argv_mode() {
        // A hostile client_id/param with shell metacharacters stays a single
        // literal argv element; nothing splits or expands it.
        let template = vec![
            "/bin/true".to_string(),
            "{client_id}".to_string(),
            "{param}".to_string(),
        ];
        let argv = build_argv(&template, ip(), "x; rm -rf /", 0, "$(reboot)");
        assert_eq!(argv[1], "x; rm -rf /");
        assert_eq!(argv[2], "$(reboot)");
    }

    #[tokio::test]
    async fn process_executor_runs_true_successfully() {
        let exec = ProcessExecutor::new(
            vec!["/bin/true".to_string()],
            None,
            Duration::from_secs(5),
            2,
            false,
        );
        let res = exec.execute("c", ip(), 1, None).await.unwrap();
        assert_eq!(res.exit_code, Some(0));
        assert!(!res.timed_out);
    }

    #[tokio::test]
    async fn process_executor_times_out_long_command() {
        let exec = ProcessExecutor::new(
            vec!["/bin/sleep".to_string(), "5".to_string()],
            None,
            Duration::from_millis(150),
            2,
            false,
        );
        let res = exec.execute("c", ip(), 1, None).await.unwrap();
        assert!(res.timed_out);
    }
}
