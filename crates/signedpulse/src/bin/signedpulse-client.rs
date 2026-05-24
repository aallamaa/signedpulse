//! The `signedpulse-client` binary: a thin wrapper over the client crate's CLI.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    signedpulse_client::cli::run_cli().await
}
