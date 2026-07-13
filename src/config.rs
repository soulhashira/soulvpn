use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    /// Base64 X25519 private key.
    pub private_key: String,
    /// TUN address, e.g. 10.66.66.1/24.
    pub address: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Enable IP forwarding + MASQUERADE on the default egress iface.
    #[serde(default)]
    pub nat: bool,
    pub peers: Vec<PeerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PeerConfig {
    /// Base64 X25519 public key of the peer.
    pub public_key: String,
    /// Tunnel IP assigned to this peer, e.g. 10.66.66.2.
    pub allowed_ip: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    pub endpoint: SocketAddr,
    /// Base64 X25519 private key.
    pub private_key: String,
    /// Base64 X25519 public key of the server.
    pub server_public_key: String,
    /// Client TUN address, e.g. 10.66.66.2/24.
    pub address: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Install full-tunnel routes (0.0.0.0/1 + 128.0.0.0/1 via TUN).
    #[serde(default = "default_true")]
    pub redirect_all: bool,
}

fn default_mtu() -> u16 {
    1400
}

fn default_true() -> bool {
    true
}

impl ServerConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read server config {}", path.display()))?;
        let cfg: Self = toml::from_str(&text).context("parse server config")?;
        if cfg.peers.is_empty() {
            bail!("server config must list at least one peer");
        }
        Ok(cfg)
    }
}

impl ClientConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read client config {}", path.display()))?;
        toml::from_str(&text).context("parse client config")
    }
}

/// Decode a 32-byte key from standard base64.
pub fn decode_key(s: &str) -> Result<[u8; 32]> {
    let bytes = B64.decode(s.trim()).context("base64-decode key")?;
    if bytes.len() != 32 {
        bail!("key must be 32 bytes, got {}", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn encode_key(key: &[u8; 32]) -> String {
    B64.encode(key)
}

/// Split "10.66.66.1/24" into (ip, prefix).
pub fn parse_cidr(s: &str) -> Result<(std::net::Ipv4Addr, u8)> {
    let (ip, prefix) = s
        .split_once('/')
        .context("address must be CIDR, e.g. 10.66.66.1/24")?;
    let ip: std::net::Ipv4Addr = ip.parse().context("parse IPv4 address")?;
    let prefix: u8 = prefix.parse().context("parse prefix length")?;
    if prefix > 32 {
        bail!("prefix length must be <= 32");
    }
    Ok((ip, prefix))
}

/// Extract bare IPv4 from "10.66.66.2" or "10.66.66.2/32".
pub fn parse_ipv4(s: &str) -> Result<std::net::Ipv4Addr> {
    let host = s.split('/').next().unwrap_or(s);
    host.parse().context("parse IPv4")
}
