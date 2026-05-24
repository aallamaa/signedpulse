//! `signedpulse-server` binary entry point.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use signedpulse_common::config::ServerConfig;
use signedpulse_common::crypto;
use signedpulse_common::service::{self, ServiceSpec, ServiceTarget};
use signedpulse_common::status::{self, ServerStatusSnapshot};
use signedpulse_server::command_runner::ProcessExecutor;
use signedpulse_server::server::Server;
use tokio::net::UdpSocket;
use tracing::info;

#[derive(Parser, Debug)]
#[command(
    name = "signedpulse-server",
    about = "Verifies signed UDP pulses from authorized clients and runs a configured hook command",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Path to the server TOML config file.
    #[arg(long, default_value = "/etc/signedpulse/server.toml", global = true)]
    config: PathBuf,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Write a starter server config.
    Init(InitArgs),
    /// Authorize a client by appending it to the server config.
    AddClient(AddClientArgs),
    /// Install (and start) the server as a background service.
    InstallService(InstallArgs),
    /// Show live status of the running server (local-only).
    Status,
}

#[derive(clap::Args, Debug)]
struct InitArgs {
    /// UDP address to bind.
    #[arg(long, default_value = "0.0.0.0:7370")]
    bind: String,
    /// This server's identity (clients must use the same server_id).
    #[arg(long, default_value = "signedpulse-main")]
    server_id: String,
    /// Path to the hook program run on a verified pulse.
    #[arg(long, default_value = "/usr/local/sbin/signedpulse-hook")]
    hook: String,
    /// Accept cleartext binary packets instead of requiring sealed datagrams.
    #[arg(long)]
    no_encryption: bool,
    /// Overwrite an existing config file.
    #[arg(long)]
    force: bool,
}

#[derive(clap::Args, Debug)]
struct AddClientArgs {
    /// 256-bit client id as 64 hex chars (from `signedpulse-client init`).
    #[arg(long)]
    client_id: String,
    /// The client's base64 Ed25519 public key (from `signedpulse-client init`).
    #[arg(long)]
    public_key: String,
    /// Optional human-friendly label for logs/status.
    #[arg(long)]
    label: Option<String>,
}

#[derive(clap::Args, Debug)]
struct InstallArgs {
    /// Install a per-user systemd unit instead of a system-wide one.
    #[arg(long)]
    user: bool,
    /// Only print the service definition; do not write or start anything.
    #[arg(long)]
    print: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Init(args)) => init(args, &cli.config),
        Some(Command::AddClient(args)) => add_client(args, &cli.config),
        Some(Command::InstallService(args)) => install_service(args, &cli.config),
        Some(Command::Status) => status(&cli.config),
        None => run(&cli.config).await,
    }
}

fn status(config_path: &Path) -> anyhow::Result<()> {
    let config = ServerConfig::load(config_path)?;
    let state_path = config
        .server
        .state_file
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(|| status::default_state_path("server"));

    let (svc_state, svc_how) =
        service::query_service("signedpulse-server", "com.signedpulse.server");
    println!("service:   {} [{svc_how}]", status::service_word(svc_state));
    println!(
        "config:    {}  bind={}  server_id={}  clients={}",
        config_path.display(),
        config.server.bind,
        config.server.server_id,
        config.clients.len()
    );

    let snapshot: Option<ServerStatusSnapshot> =
        status::refresh_and_read(&state_path, &status::pid_path(&state_path));
    match snapshot {
        None => {
            println!(
                "status:    no live data (server not running, or could not refresh state file)"
            );
        }
        Some(s) => {
            println!(
                "pid:       {}   uptime: {}",
                s.pid,
                status::duration_words(status::now_unix().saturating_sub(s.started_at_unix))
            );
            match &s.last_pulse {
                Some(p) => println!(
                    "last pulse: {}:{}  {}",
                    p.source_ip,
                    p.source_port,
                    status::ago(p.at_unix)
                ),
                None => println!("last pulse: none yet"),
            }
            match &s.last_hook {
                Some(h) => println!(
                    "last hook:  \"{}\" -> {}  {}  {}",
                    h.client_id,
                    h.source_ip,
                    if h.timed_out {
                        "timed out".to_string()
                    } else {
                        format!(
                            "exit {}",
                            h.exit_code
                                .map(|c| c.to_string())
                                .unwrap_or_else(|| "?".into())
                        )
                    },
                    status::ago(h.at_unix)
                ),
                None => println!("last hook:  none yet"),
            }
            println!(
                "counters:  hello={} verified={} rejected={} replays={}",
                s.hello_accepted, s.verified, s.rejected, s.replays
            );
            if !s.clients.is_empty() {
                println!("clients:");
                for (id, p) in &s.clients {
                    println!(
                        "  {:<20} {}:{}  {}",
                        id,
                        p.source_ip,
                        p.source_port,
                        status::ago(p.at_unix)
                    );
                }
            }
        }
    }
    Ok(())
}

async fn run(config_path: &Path) -> anyhow::Result<()> {
    init_logging();
    let config = ServerConfig::load(config_path)?;

    // Build the production command executor from config.
    let executor = Arc::new(ProcessExecutor::new(
        config.command.argv.clone(),
        config.command.working_dir.clone(),
        Duration::from_secs(config.server.command_timeout_seconds),
        config.command.max_concurrent,
        config.command.allow_shell,
    ));

    if config.command.allow_shell {
        // Loud warning: with a shell, the client-supplied {param} (and {ip}) are
        // concatenated into the `sh -c` string, so a single authorized — or
        // compromised — client can achieve remote code execution as this process'
        // user. The leading-`-` guard on {param} does NOT prevent shell injection.
        tracing::warn!(
            "command.allow_shell is ENABLED — argv is run through `sh -c`, so the \
             client-supplied {{param}} becomes SHELL CODE (remote code execution as \
             this user). Only enable in fully trusted setups, and never with \
             {{param}}/{{ip}} in the argv on an untrusted network."
        );
    }

    let bind_addr = config.server.bind.clone();
    let socket = UdpSocket::bind(&bind_addr).await?;

    let server = Arc::new(Server::from_config(config, executor)?);

    // Graceful shutdown on Ctrl-C / SIGTERM.
    let shutdown = async {
        let ctrl_c = async {
            let _ = tokio::signal::ctrl_c().await;
        };
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
            tokio::select! {
                _ = ctrl_c => {},
                _ = term.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            ctrl_c.await;
        }
    };

    server.run(socket, shutdown).await?;
    info!("server stopped cleanly");
    Ok(())
}

fn init(args: InitArgs, config_path: &Path) -> anyhow::Result<()> {
    if config_path.exists() && !args.force {
        anyhow::bail!(
            "config {} already exists; pass --force to overwrite",
            config_path.display()
        );
    }

    // Generate the X25519 keypair for packet/param decryption.
    let (enc_secret_b64, enc_public_b64) = crypto::generate_encryption_keypair();
    let wire = if args.no_encryption {
        "off"
    } else {
        "required"
    };

    // The config holds the X25519 secret, so write it 0600.
    let config = format!(
        "# Generated by `signedpulse-server init`.\n\
         [server]\n\
         bind = \"{bind}\"\n\
         server_id = \"{server_id}\"\n\
         nonce_ttl_seconds = 30\n\
         command_timeout_seconds = 10\n\
         client_cooldown_seconds = 60\n\
         max_packet_size = 2048\n\
         hello_rate_max = 30\n\
         hello_rate_window_seconds = 60\n\
         hello_max_skew_seconds = 30\n\
         max_faulty_packets = 10\n\
         blacklist_seconds = 300\n\
         wire_encryption = \"{wire}\"\n\
         encryption_private_key = \"{enc_secret}\"\n\
         \n\
         [command]\n\
         # Placeholders {{ip}}, {{client_id}}, {{source_port}}, {{param}} are\n\
         # substituted as literal arguments. No shell unless allow_shell = true.\n\
         argv = [\"{hook}\", \"{{ip}}\", \"{{client_id}}\", \"{{param}}\"]\n\
         working_dir = \"/\"\n\
         max_concurrent = 4\n\
         allow_shell = false\n\
         \n\
         # Authorize clients with: signedpulse-server add-client --client-id HEX --public-key KEY\n",
        bind = args.bind,
        server_id = args.server_id,
        hook = args.hook,
        wire = wire,
        enc_secret = enc_secret_b64,
    );

    service::write_config_file(config_path, &config, true).map_err(|e| {
        anyhow::anyhow!(
            "failed to write {} ({e}). If this is a system path, re-run with sudo.",
            config_path.display()
        )
    })?;
    println!(
        "Wrote server config to {} (mode 0600).",
        config_path.display()
    );
    println!();
    println!("=== Give this encryption public key to clients ===");
    println!("  signedpulse-client init --server <HOST> --server-key \"{enc_public_b64}\"");
    println!();
    println!(
        "Next: authorize clients with `signedpulse-server add-client`, then start the server."
    );
    Ok(())
}

fn add_client(args: AddClientArgs, config_path: &Path) -> anyhow::Result<()> {
    // The config must already exist and be valid.
    let existing = ServerConfig::load(config_path).map_err(|e| {
        anyhow::anyhow!(
            "cannot load {} ({e}); run `signedpulse-server init` first",
            config_path.display()
        )
    })?;

    // Validate the id and public key before touching the file.
    signedpulse_common::protocol::ClientId::from_hex(&args.client_id)
        .map_err(|_| anyhow::anyhow!("--client-id must be 64 hex characters (256 bits)"))?;
    crypto::load_verifying_key(&args.public_key)
        .map_err(|e| anyhow::anyhow!("invalid --public-key: {e}"))?;

    // Reject a label that could break out of the TOML string it's written into.
    if let Some(label) = &args.label {
        if label
            .chars()
            .any(|c| c == '"' || c == '\\' || c.is_control())
        {
            anyhow::bail!("--label must not contain quotes, backslashes, or control characters");
        }
    }

    // Reject duplicates so client lookups stay unambiguous.
    if existing
        .clients
        .iter()
        .any(|c| c.client_id.eq_ignore_ascii_case(&args.client_id))
    {
        anyhow::bail!("client_id {:?} is already authorized", args.client_id);
    }

    // Append a new array-of-tables entry. Appending at EOF keeps existing
    // content intact and is always valid TOML.
    let mut text = std::fs::read_to_string(config_path)?;
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&format!(
        "\n[[clients]]\nclient_id = \"{}\"\npublic_key = \"{}\"\n",
        args.client_id, args.public_key
    ));
    if let Some(label) = &args.label {
        text.push_str(&format!("label = \"{label}\"\n"));
    }
    // The server config holds the X25519 secret, so rewrite it 0600 (and without
    // following a symlink) — std::fs::write would re-create it world-readable.
    service::write_config_file(config_path, &text, true)?;

    // Re-load to confirm the file still parses and report the new count.
    let updated = ServerConfig::load(config_path)?;
    println!(
        "Authorized client {:?}. The config now has {} client(s).",
        args.client_id,
        updated.clients.len()
    );
    println!("Restart the server (e.g. `systemctl restart signedpulse-server`) to apply.");
    Ok(())
}

fn install_service(args: InstallArgs, config_path: &Path) -> anyhow::Result<()> {
    let exec_path = std::env::current_exe()?;
    let spec = ServiceSpec {
        unit_name: "signedpulse-server".into(),
        description: "SignedPulse server".into(),
        exec_path,
        args: vec!["--config".into(), config_path.display().to_string()],
        launchd_label: "com.signedpulse.server".into(),
    };
    let target = if args.user {
        ServiceTarget::SystemdUser
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
    Ok(())
}

fn init_logging() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).with_target(false).init();
}
