//! Library surface of the SignedPulse server: the verification pipeline plus the
//! CLI entry point (`cli::run_cli`), exposed so the `signedpulse` umbrella crate
//! can provide the binary and integration tests can drive the server directly.

pub mod cli;
pub mod command_runner;
pub mod nonce_store;
pub mod rate_limit;
pub mod seen_cache;
pub mod server;

/// Test helpers, also usable from integration tests in `tests/`.
pub mod testing {
    use crate::command_runner::{CommandError, CommandExecutor, CommandResult};
    use async_trait::async_trait;
    use std::net::IpAddr;
    use std::sync::{Arc, Mutex};

    /// One recorded invocation of the mock executor.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Execution {
        pub client_id: String,
        pub source_ip: IpAddr,
        pub source_port: u16,
        pub param: Option<String>,
        pub is_new: bool,
    }

    /// A `CommandExecutor` that records its calls instead of running anything.
    #[derive(Clone, Default)]
    pub struct MockCommandExecutor {
        executions: Arc<Mutex<Vec<Execution>>>,
    }

    impl MockCommandExecutor {
        pub fn new() -> Self {
            Self::default()
        }

        /// Snapshot of all recorded executions, in order.
        pub fn executions(&self) -> Vec<Execution> {
            self.executions.lock().unwrap().clone()
        }

        pub fn count(&self) -> usize {
            self.executions.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl CommandExecutor for MockCommandExecutor {
        async fn execute(
            &self,
            client_id: &str,
            source_ip: IpAddr,
            source_port: u16,
            param: Option<&str>,
            is_new: bool,
        ) -> Result<CommandResult, CommandError> {
            self.executions.lock().unwrap().push(Execution {
                client_id: client_id.to_string(),
                source_ip,
                source_port,
                param: param.map(|s| s.to_string()),
                is_new,
            });
            Ok(CommandResult {
                exit_code: Some(0),
                timed_out: false,
            })
        }
    }
}
