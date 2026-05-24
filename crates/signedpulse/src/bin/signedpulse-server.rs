//! The `signedpulse-server` binary: a thin wrapper over the server crate's CLI.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    signedpulse_server::cli::run_cli().await
}
