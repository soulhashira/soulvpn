mod client;
mod config;
mod control;
mod crypto;
mod monitor;
mod packet;
mod route;
mod server;
mod stats;
mod tun_dev;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use config::{encode_key, write_keypair_files, ClientConfig, ServerConfig};
use crypto::{generate_keypair, public_from_private};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "soulvpn",
    about = "System-wide VPN: Noise_IK over UDP into a TUN device",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a new X25519 keypair.
    ///
    /// Default: private key on stdout, public key on stderr (script-friendly).
    /// Use --write-dir to write `NAME.priv` (0600) + `NAME.pub` instead.
    Genkey {
        /// Write key files into this directory instead of printing.
        #[arg(long)]
        write_dir: Option<PathBuf>,
        /// Basename for key files (default: "key" → key.priv / key.pub).
        #[arg(long, default_value = "key")]
        name: String,
    },
    /// Derive the public key from a base64 private key (stdin or arg).
    Pubkey {
        /// Base64 private key. If omitted, read one line from stdin.
        private_key: Option<String>,
    },
    /// Run the VPN server (requires root / CAP_NET_ADMIN).
    Server {
        #[arg(short, long)]
        config: PathBuf,
        /// Unix control socket for status/on/off/monitor.
        #[arg(long, default_value = control::DEFAULT_CONTROL_SOCKET)]
        control_socket: PathBuf,
    },
    /// Run the VPN client (requires root / CAP_NET_ADMIN).
    Client {
        #[arg(short, long)]
        config: PathBuf,
        /// Unix control socket for status/on/off/monitor.
        #[arg(long, default_value = control::DEFAULT_CONTROL_SOCKET)]
        control_socket: PathBuf,
    },
    /// Print one-shot status from the running daemon.
    Status {
        #[arg(long, default_value = control::DEFAULT_CONTROL_SOCKET)]
        control_socket: PathBuf,
        /// Emit JSON instead of human text.
        #[arg(long)]
        json: bool,
    },
    /// Enable the data plane (reinstall full-tunnel routes on the client).
    On {
        #[arg(long, default_value = control::DEFAULT_CONTROL_SOCKET)]
        control_socket: PathBuf,
    },
    /// Disable the data plane (remove full-tunnel routes; process stays up).
    ///
    /// Warning: without kill_switch this restores clearnet. With kill_switch,
    /// `off` also removes the kill switch so clearnet works again (explicit opt-out).
    Off {
        #[arg(long, default_value = control::DEFAULT_CONTROL_SOCKET)]
        control_socket: PathBuf,
    },
    /// Live terminal dashboard (activity + on/off).
    Monitor {
        #[arg(long, default_value = control::DEFAULT_CONTROL_SOCKET)]
        control_socket: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Control-plane commands stay quiet unless RUST_LOG is set.
    let default_filter = match &cli.cmd {
        Command::Status { .. }
        | Command::On { .. }
        | Command::Off { .. }
        | Command::Monitor { .. }
        | Command::Genkey { .. }
        | Command::Pubkey { .. } => "warn",
        _ => "info",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter)),
        )
        .init();

    match cli.cmd {
        Command::Genkey { write_dir, name } => {
            let (privk, pubk) = generate_keypair()?;
            if let Some(dir) = write_dir {
                if name.contains('/') || name.contains("..") {
                    bail!("invalid key name");
                }
                let (priv_path, pub_path) = write_keypair_files(&dir, &name, &privk, &pubk)?;
                eprintln!("wrote {} (mode 0600)", priv_path.display());
                eprintln!("wrote {}", pub_path.display());
                println!("{}", priv_path.display());
            } else {
                // Script-friendly: private on stdout, public on stderr.
                // Script-friendly: private on stdout, public on stderr (raw base64).
                println!("{}", encode_key(&privk));
                eprintln!("{}", encode_key(&pubk));
            }
        }
        Command::Pubkey { private_key } => {
            let key = match private_key {
                Some(k) => k,
                None => {
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line)?;
                    line
                }
            };
            let privk = config::decode_key(&key)?;
            println!("{}", encode_key(&public_from_private(&privk)));
        }
        Command::Server {
            config,
            control_socket,
        } => {
            let cfg = ServerConfig::load(&config)?;
            server::run(cfg, control_socket).await?;
        }
        Command::Client {
            config,
            control_socket,
        } => {
            let cfg = ClientConfig::load(&config)?;
            client::run(cfg, control_socket).await?;
        }
        Command::Status {
            control_socket,
            json,
        } => {
            let snap = control::request(&control_socket, "status").await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&snap)?);
            } else {
                println!("{}", snap.format_human());
            }
        }
        Command::On { control_socket } => {
            let snap = control::request(&control_socket, "on").await?;
            println!(
                "enabled  [{}]  tx={} rx={}",
                if snap.enabled { "ON" } else { "OFF" },
                snap.tx_packets,
                snap.rx_packets
            );
        }
        Command::Off { control_socket } => {
            let snap = control::request(&control_socket, "off").await?;
            println!(
                "disabled  [{}]  tx={} rx={}",
                if snap.enabled { "ON" } else { "OFF" },
                snap.tx_packets,
                snap.rx_packets
            );
        }
        Command::Monitor { control_socket } => {
            monitor::run(&control_socket).await?;
        }
    }
    Ok(())
}
