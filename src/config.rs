use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    /// Base64 X25519 private key (inline). Prefer `private_key_file` when possible.
    #[serde(default)]
    pub private_key: Option<String>,
    /// Path to a file containing the base64 private key (single line).
    #[serde(default)]
    pub private_key_file: Option<PathBuf>,
    /// TUN address, e.g. 10.66.66.1/24.
    pub address: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Enable IP forwarding + MASQUERADE on the default egress iface.
    #[serde(default)]
    pub nat: bool,
    /// Max handshake attempts per source IP per window (default 10).
    #[serde(default = "default_hs_rate")]
    pub handshake_rate_limit: u32,
    /// Sliding window length for handshake rate limit in seconds (default 10).
    #[serde(default = "default_hs_window")]
    pub handshake_rate_window_secs: u64,
    /// Drop idle sessions after this many seconds without data/keepalive (default 180).
    #[serde(default = "default_session_idle")]
    pub session_idle_secs: u64,
    /// Unix socket mode bits, e.g. "0600" (default). Use "0660" with a shared group.
    #[serde(default = "default_control_mode")]
    pub control_mode: String,
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
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub private_key_file: Option<PathBuf>,
    /// Base64 X25519 public key of the server.
    #[serde(default)]
    pub server_public_key: Option<String>,
    #[serde(default)]
    pub server_public_key_file: Option<PathBuf>,
    /// Client TUN address, e.g. 10.66.66.2/24.
    pub address: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Install full-tunnel routes (0.0.0.0/1 + 128.0.0.0/1 via TUN).
    #[serde(default = "default_true")]
    pub redirect_all: bool,
    /// Drop clearnet egress while the tunnel is enabled (fail-closed).
    #[serde(default)]
    pub kill_switch: bool,
    /// Disable IPv6 (blackhole ::/1 + 8000::/1) while running to avoid leaks.
    #[serde(default = "default_true")]
    pub disable_ipv6: bool,
    /// Optional DNS servers written to /etc/resolv.conf (restored on exit).
    #[serde(default)]
    pub dns: Vec<String>,
    /// Encrypted keepalive interval in seconds (0 = off). Default 25.
    #[serde(default = "default_keepalive")]
    pub keepalive_secs: u64,
    /// Force re-handshake after this many seconds (0 = off). Default 120.
    #[serde(default = "default_rekey")]
    pub rekey_secs: u64,
    /// Re-handshake if no decryptable traffic for this many seconds. Default 45.
    #[serde(default = "default_reconnect")]
    pub reconnect_timeout_secs: u64,
    /// Unix socket mode bits, e.g. "0600".
    #[serde(default = "default_control_mode")]
    pub control_mode: String,
}

fn default_mtu() -> u16 {
    1400
}

fn default_true() -> bool {
    true
}

fn default_hs_rate() -> u32 {
    10
}

fn default_hs_window() -> u64 {
    10
}

fn default_session_idle() -> u64 {
    180
}

fn default_keepalive() -> u64 {
    25
}

fn default_rekey() -> u64 {
    120
}

fn default_reconnect() -> u64 {
    45
}

fn default_control_mode() -> String {
    "0600".into()
}

impl ServerConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read server config {}", path.display()))?;
        let cfg: Self = toml::from_str(&text).context("parse server config")?;
        if cfg.peers.is_empty() {
            bail!("server config must list at least one peer");
        }
        parse_mode(&cfg.control_mode).context("control_mode")?;
        if cfg.mtu < 576 || cfg.mtu > 9000 {
            bail!("mtu must be between 576 and 9000");
        }
        // Validate peers parse and are unique.
        let (server_ip, prefix) = parse_cidr(&cfg.address)?;
        let network = network_addr(server_ip, prefix);
        let mut seen_ips = std::collections::HashSet::new();
        let mut seen_keys = std::collections::HashSet::new();
        for p in &cfg.peers {
            let tip = parse_ipv4(&p.allowed_ip)?;
            let pk = resolve_key_inline(&p.public_key)?;
            if !seen_ips.insert(tip) {
                bail!("duplicate peer allowed_ip {tip}");
            }
            if !seen_keys.insert(pk) {
                bail!("duplicate peer public_key");
            }
            if !ip_in_network(tip, network, prefix) {
                bail!(
                    "peer allowed_ip {tip} is outside server tunnel network {}/{}",
                    network,
                    prefix
                );
            }
            if tip == server_ip {
                bail!("peer allowed_ip {tip} must not equal the server address");
            }
            if tip == network {
                bail!("peer allowed_ip {tip} must not be the network address");
            }
        }
        // Ensure private key is resolvable.
        let _ = cfg.load_private_key()?;
        Ok(cfg)
    }

    pub fn load_private_key(&self) -> Result<[u8; 32]> {
        load_key_material(
            self.private_key.as_deref(),
            self.private_key_file.as_deref(),
        )
    }
}

impl ClientConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read client config {}", path.display()))?;
        let cfg: Self = toml::from_str(&text).context("parse client config")?;
        parse_mode(&cfg.control_mode).context("control_mode")?;
        if cfg.mtu < 576 || cfg.mtu > 9000 {
            bail!("mtu must be between 576 and 9000");
        }
        let _ = cfg.load_private_key()?;
        let _ = cfg.load_server_public_key()?;
        for d in &cfg.dns {
            d.parse::<std::net::Ipv4Addr>()
                .with_context(|| format!("dns entry must be IPv4 address, got {d}"))?;
        }
        Ok(cfg)
    }

    pub fn load_private_key(&self) -> Result<[u8; 32]> {
        load_key_material(
            self.private_key.as_deref(),
            self.private_key_file.as_deref(),
        )
    }

    pub fn load_server_public_key(&self) -> Result<[u8; 32]> {
        load_key_material(
            self.server_public_key.as_deref(),
            self.server_public_key_file.as_deref(),
        )
    }
}

fn load_key_material(inline: Option<&str>, file: Option<&Path>) -> Result<[u8; 32]> {
    match (inline, file) {
        (Some(s), None) => decode_key(s),
        (None, Some(path)) => {
            check_key_file_permissions(path)?;
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("read key file {}", path.display()))?;
            decode_key(text.lines().next().unwrap_or("").trim())
        }
        (Some(s), Some(path)) => {
            // Prefer file when both set; still validate inline matches if present.
            check_key_file_permissions(path)?;
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("read key file {}", path.display()))?;
            let from_file = decode_key(text.lines().next().unwrap_or("").trim())?;
            let from_inline = decode_key(s)?;
            if from_file != from_inline {
                bail!(
                    "private_key and private_key_file disagree ({})",
                    path.display()
                );
            }
            Ok(from_file)
        }
        (None, None) => bail!("set private_key or private_key_file (or server_public_key[_file])"),
    }
}

fn resolve_key_inline(s: &str) -> Result<[u8; 32]> {
    decode_key(s)
}

/// Warn (via Result::Err only for world-writable; soft-warn for group-readable).
pub fn check_key_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta =
            std::fs::metadata(path).with_context(|| format!("stat key file {}", path.display()))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "key file {} mode is {:04o}; refuse to load (want 0600 or tighter)",
                path.display(),
                mode
            );
        }
    }
    let _ = path;
    Ok(())
}

/// Parse octal mode string like "0600" or "600".
pub fn parse_mode(s: &str) -> Result<u32> {
    let t = s.trim().trim_start_matches("0o");
    u32::from_str_radix(t, 8).with_context(|| format!("invalid mode {s:?}"))
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

pub fn network_addr(ip: std::net::Ipv4Addr, prefix: u8) -> std::net::Ipv4Addr {
    if prefix == 0 {
        return std::net::Ipv4Addr::new(0, 0, 0, 0);
    }
    let mask = u32::MAX << (32 - prefix);
    std::net::Ipv4Addr::from(u32::from(ip) & mask)
}

pub fn ip_in_network(ip: std::net::Ipv4Addr, network: std::net::Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - prefix);
    (u32::from(ip) & mask) == (u32::from(network) & mask)
}

/// Write a private key file as 0600 and optional public sibling.
pub fn write_keypair_files(
    dir: &Path,
    prefix: &str,
    privk: &[u8; 32],
    pubk: &[u8; 32],
) -> Result<(PathBuf, PathBuf)> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let priv_path = dir.join(format!("{prefix}.priv"));
    let pub_path = dir.join(format!("{prefix}.pub"));
    std::fs::write(&priv_path, format!("{}\n", encode_key(privk)))
        .with_context(|| format!("write {}", priv_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::write(&pub_path, format!("{}\n", encode_key(pubk)))
        .with_context(|| format!("write {}", pub_path.display()))?;
    Ok((priv_path, pub_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_parse() {
        assert_eq!(parse_mode("0600").unwrap(), 0o600);
        assert_eq!(parse_mode("660").unwrap(), 0o660);
    }

    #[test]
    fn network_membership() {
        let net = "10.66.66.0".parse().unwrap();
        assert!(ip_in_network("10.66.66.2".parse().unwrap(), net, 24));
        assert!(!ip_in_network("10.66.67.2".parse().unwrap(), net, 24));
    }
}
