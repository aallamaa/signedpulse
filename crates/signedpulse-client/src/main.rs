//! `signedpulse-client` binary entry point.

mod client;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use client::Client;
use signedpulse_common::config::ClientConfig;
use signedpulse_common::crypto;
use signedpulse_common::protocol::ClientId;
use signedpulse_common::service::{self, ServiceSpec, ServiceTarget};
use signedpulse_common::status::{self, ClientStatusSnapshot};

#[derive(Parser, Debug)]
#[command(
    name = "signedpulse-client",
    about = "Periodically proves the client's real UDP source IP to a SignedPulse server",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Path to the client TOML config file (used by `run` and `install-service`).
    #[arg(long, default_value = "/etc/signedpulse/client.toml", global = true)]
    config: PathBuf,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a config and keypair, then print what to add on the server.
    Init(InitArgs),
    /// Generate a new Ed25519 keypair and print the config snippets.
    GenerateKey,
    /// Install (and start) this client as a background service.
    InstallService(InstallArgs),
    /// Show live status of the running client (local-only).
    Status,
}

#[derive(clap::Args, Debug)]
struct InitArgs {
    /// Server address, e.g. "203.0.113.10" or "203.0.113.10:7370".
    #[arg(long)]
    server: String,
    /// Server's base64 X25519 public key (printed by `signedpulse-server init`).
    /// Required for the default encrypted mode.
    #[arg(long)]
    server_key: Option<String>,
    /// 256-bit client id (64 hex). Defaults to a freshly generated random id.
    #[arg(long)]
    client_id: Option<String>,
    /// Optional human-friendly label for server logs/status.
    #[arg(long)]
    label: Option<String>,
    /// Must match the server's server_id.
    #[arg(long, default_value = "signedpulse-main")]
    server_id: String,
    /// Seconds between pulses.
    #[arg(long, default_value_t = 300)]
    interval: u64,
    /// Send cleartext binary instead of sealed datagrams (not recommended).
    #[arg(long)]
    no_encryption: bool,
    /// Overwrite an existing config file.
    #[arg(long)]
    force: bool,
}

#[derive(clap::Args, Debug)]
struct InstallArgs {
    /// Install a per-user systemd unit instead of a system-wide one (Linux).
    #[arg(long)]
    user: bool,
    /// Only print the service definition; do not write or start anything.
    #[arg(long)]
    print: bool,
}

const DEFAULT_PORT: u16 = 7370;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Init(args)) => init(args, &cli.config),
        Some(Command::GenerateKey) => {
            generate_key();
            Ok(())
        }
        Some(Command::InstallService(args)) => install_service(args, &cli.config),
        Some(Command::Status) => status(&cli.config),
        None => {
            init_logging();
            let config = ClientConfig::load(&cli.config)?;
            let client = Client::from_config(config)?;
            client.run_forever().await
        }
    }
}

fn status(config_path: &std::path::Path) -> anyhow::Result<()> {
    let config = ClientConfig::load(config_path)?;
    let state_path = config
        .client
        .state_file
        .clone()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| status::default_state_path("client"));

    let (svc_state, svc_how) =
        service::query_service("signedpulse-client", "com.signedpulse.client");
    println!(
        "service:    {} [{svc_how}]",
        status::service_word(svc_state)
    );
    println!(
        "config:     {}  client_id={}  server={}",
        config_path.display(),
        config.client.client_id,
        config.client.server_addr
    );

    let snapshot: Option<ClientStatusSnapshot> =
        status::refresh_and_read(&state_path, &status::pid_path(&state_path));
    match snapshot {
        None => {
            println!(
                "status:     no live data (client not running, or could not refresh state file)"
            );
        }
        Some(s) => {
            match s.last_success_at_unix {
                Some(t) => println!("last pulse: OK  {}", status::ago(t)),
                None => println!("last pulse: none succeeded yet"),
            }
            // Next pulse ≈ last attempt + interval.
            if let Some(attempt) = s.last_attempt_at_unix {
                let next_in = (attempt as i128 + s.interval_seconds as i128
                    - status::now_unix() as i128)
                    .clamp(i64::MIN as i128, i64::MAX as i128) as i64;
                if next_in > 0 {
                    println!("next pulse: in ~{}", status::duration_words(next_in));
                } else {
                    println!("next pulse: due now");
                }
            }
            println!("last result: {}", s.last_result);
        }
    }
    Ok(())
}

fn init(args: InitArgs, config_path: &std::path::Path) -> anyhow::Result<()> {
    if config_path.exists() && !args.force {
        anyhow::bail!(
            "config {} already exists; pass --force to overwrite",
            config_path.display()
        );
    }

    let wire_encryption = !args.no_encryption;
    if wire_encryption && args.server_key.is_none() {
        anyhow::bail!(
            "encrypted mode (default) needs --server-key (run `signedpulse-server init` to print \
             it), or pass --no-encryption"
        );
    }

    // A fresh random 256-bit client id unless the caller supplied one.
    let client_id = match args.client_id {
        Some(id) => {
            ClientId::from_hex(&id).map_err(|_| anyhow::anyhow!("--client-id must be 64 hex"))?;
            id
        }
        None => ClientId(crypto::Nonce::generate().0).to_hex(),
    };
    let server_addr = normalize_addr(&args.server);
    let keys = crypto::generate_keypair();

    let mut config = format!(
        "# Generated by `signedpulse-client init`.\n\
         [client]\n\
         client_id = \"{client_id}\"\n\
         server_addr = \"{server_addr}\"\n\
         server_id = \"{server_id}\"\n\
         interval_seconds = {interval}\n\
         private_key = \"{private_key}\"\n\
         challenge_timeout_seconds = 5\n\
         retries = 3\n\
         wire_encryption = {wire_encryption}\n",
        client_id = client_id,
        server_addr = server_addr,
        server_id = args.server_id,
        interval = args.interval,
        private_key = keys.private_key_b64,
        wire_encryption = wire_encryption,
    );
    if let Some(key) = &args.server_key {
        config.push_str(&format!("server_encryption_key = \"{key}\"\n"));
    }

    service::write_config_file(config_path, &config, true).map_err(|e| {
        anyhow::anyhow!(
            "failed to write {} ({e}). If this is a system path, re-run with sudo.",
            config_path.display()
        )
    })?;

    let label_arg = args
        .label
        .as_ref()
        .map(|l| format!(" --label \"{l}\""))
        .unwrap_or_default();

    println!(
        "Wrote client config to {} (mode 0600).",
        config_path.display()
    );
    println!();
    println!("=== Do this on the SERVER to authorize this client ===");
    println!();
    println!("Run:");
    println!(
        "  signedpulse-server add-client --client-id \"{}\" --public-key \"{}\"{}",
        client_id, keys.public_key_b64, label_arg
    );
    println!();
    println!("…or add this block to the server's config manually:");
    println!();
    println!("  [[clients]]");
    println!("  client_id = \"{client_id}\"");
    println!("  public_key = \"{}\"", keys.public_key_b64);
    if let Some(l) = &args.label {
        println!("  label = \"{l}\"");
    }
    println!();
    println!("Then start this client (or run `signedpulse-client install-service`).");
    Ok(())
}

fn install_service(args: InstallArgs, config_path: &std::path::Path) -> anyhow::Result<()> {
    let exec_path = std::env::current_exe()?;
    let spec = ServiceSpec {
        unit_name: "signedpulse-client".into(),
        description: "SignedPulse client".into(),
        exec_path,
        args: vec!["--config".into(), config_path.display().to_string()],
        launchd_label: "com.signedpulse.client".into(),
    };

    // Auto-detect: macOS uses launchd; Linux uses systemd (system or --user).
    let target = if args.user {
        ServiceTarget::SystemdUser
    } else if cfg!(target_os = "macos") {
        ServiceTarget::LaunchdAgent
    } else {
        ServiceTarget::SystemdSystem
    };

    if args.print {
        print!("{}", service::render(&spec, target));
        return Ok(());
    }

    let report = service::install(&spec, target, true).map_err(|e| {
        anyhow::anyhow!("failed to install service ({e}). For a system service, re-run with sudo.")
    })?;
    report_install(&report);
    Ok(())
}

fn report_install(report: &service::InstallReport) {
    println!("Installed service definition at {}.", report.path.display());
    if report.activated {
        println!("Service activated and started.");
    } else {
        if let Some(note) = &report.note {
            println!("{note}");
        }
        for cmd in &report.activation_commands {
            println!("  {cmd}");
        }
    }
}

/// Append the default port if the user gave a bare host/IP.
fn normalize_addr(input: &str) -> String {
    if input.parse::<std::net::SocketAddr>().is_ok() {
        return input.to_string();
    }
    // A bare IPv6 literal would already contain ':'; only add a port when there
    // is no ':' at all (i.e. a hostname or IPv4 without a port).
    if input.contains(':') {
        input.to_string()
    } else {
        format!("{input}:{DEFAULT_PORT}")
    }
}

fn generate_key() {
    let keys = crypto::generate_keypair();
    println!("# SignedPulse Ed25519 keypair");
    println!("# Keep the private key secret. Place it in the CLIENT config:");
    println!();
    println!("[client]");
    println!("private_key = \"{}\"", keys.private_key_b64);
    println!();
    println!("# Place the public key in the SERVER config under the matching client:");
    println!();
    println!("[[clients]]");
    println!("client_id = \"REPLACE_ME\"");
    println!("public_key = \"{}\"", keys.public_key_b64);
}

fn init_logging() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).with_target(false).init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_addr_adds_default_port() {
        assert_eq!(normalize_addr("203.0.113.10"), "203.0.113.10:7370");
        assert_eq!(normalize_addr("example.com"), "example.com:7370");
    }

    #[test]
    fn normalize_addr_keeps_explicit_port() {
        assert_eq!(normalize_addr("203.0.113.10:9999"), "203.0.113.10:9999");
        assert_eq!(normalize_addr("example.com:5000"), "example.com:5000");
    }
}
