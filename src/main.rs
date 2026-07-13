mod client;
mod config;
mod crypto;
mod route;
mod server;
mod tun_dev;

use anyhow::Result;
use clap::{Parser, Subcommand};
use config::{encode_key, ClientConfig, ServerConfig};
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
    /// Generate a new X25519 keypair (prints base64 private + public).
    Genkey,
    /// Derive the public key from a base64 private key (stdin or arg).
    Pubkey {
        /// Base64 private key. If omitted, read one line from stdin.
        private_key: Option<String>,
    },
    /// Run the VPN server (requires root / CAP_NET_ADMIN).
    Server {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Run the VPN client (requires root / CAP_NET_ADMIN).
    Client {
        #[arg(short, long)]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Command::Genkey => {
            let (privk, pubk) = generate_keypair()?;
            println!("{}", encode_key(&privk));
            eprintln!("{}", encode_key(&pubk));
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
        Command::Server { config } => {
            let cfg = ServerConfig::load(&config)?;
            server::run(cfg).await?;
        }
        Command::Client { config } => {
            let cfg = ClientConfig::load(&config)?;
            client::run(cfg).await?;
        }
    }
    Ok(())
}
