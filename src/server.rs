use crate::config::{decode_key, parse_cidr, parse_ipv4, ServerConfig};
use crate::crypto::{HandshakeResponder, Session, MAX_MESSAGE};
use crate::route;
use crate::tun_dev;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use tun::AbstractDevice;

struct PeerMeta {
    public_key: [u8; 32],
    tunnel_ip: Ipv4Addr,
}

struct LiveSession {
    session: Session,
    peer_addr: SocketAddr,
    #[allow(dead_code)]
    tunnel_ip: Ipv4Addr,
}

struct State {
    /// session_index → live session
    by_index: HashMap<u32, LiveSession>,
    /// tunnel_ip → session_index
    by_ip: HashMap<Ipv4Addr, u32>,
    /// public_key → peer meta (from config)
    peers: HashMap<[u8; 32], PeerMeta>,
}

pub async fn run(cfg: ServerConfig) -> Result<()> {
    let private = decode_key(&cfg.private_key)?;
    let (addr, prefix) = parse_cidr(&cfg.address)?;

    let mut peers = HashMap::new();
    for p in &cfg.peers {
        let pk = decode_key(&p.public_key)?;
        let tip = parse_ipv4(&p.allowed_ip)?;
        peers.insert(
            pk,
            PeerMeta {
                public_key: pk,
                tunnel_ip: tip,
            },
        );
        info!(peer = %tip, "configured peer");
    }

    let state = Arc::new(Mutex::new(State {
        by_index: HashMap::new(),
        by_ip: HashMap::new(),
        peers,
    }));

    let sock = UdpSocket::bind(cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    let sock = Arc::new(sock);
    info!(listen = %cfg.listen, "UDP listening");

    let tun = tun_dev::create("soulvpn0", addr, prefix, cfg.mtu)?;
    let tun_name = tun.tun_name().unwrap_or_else(|_| "soulvpn0".into());
    info!(%tun_name, %addr, prefix, "TUN up");

    if cfg.nat {
        // Subnet for MASQUERADE, e.g. 10.66.66.0/24
        let network = ipv4_network(addr, prefix);
        let cidr = format!("{network}/{prefix}");
        route::setup_nat(&cidr)?;
    }

    let (mut tun_r, mut tun_w) = tokio::io::split(tun);

    // UDP → TUN
    let state_in = Arc::clone(&state);
    let sock_in = Arc::clone(&sock);
    let private_in = private;
    let downlink = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_MESSAGE];
        let mut plain = vec![0u8; MAX_MESSAGE];
        loop {
            let (n, src) = match sock_in.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    error!("UDP recv: {e}");
                    break;
                }
            };
            if n == 0 {
                continue;
            }
            match buf[0] {
                1 => {
                    // Handshake init
                    match handle_handshake(&private_in, &buf[..n], src, &state_in).await {
                        Ok(response) => {
                            if let Err(e) = sock_in.send_to(&response, src).await {
                                warn!("send handshake response: {e}");
                            } else {
                                info!(%src, "handshake accepted");
                            }
                        }
                        Err(e) => warn!(%src, "handshake rejected: {e}"),
                    }
                }
                _ => {
                    // Data: first 4 bytes are session index
                    if n < 12 {
                        continue;
                    }
                    let index = u32::from_le_bytes(buf[0..4].try_into().unwrap());
                    let mut guard = state_in.lock().await;
                    let Some(live) = guard.by_index.get_mut(&index) else {
                        warn!(index, %src, "unknown session");
                        continue;
                    };
                    // Roaming: update peer addr
                    live.peer_addr = src;
                    match live.session.decrypt(&buf[..n], &mut plain) {
                        Ok(len) => {
                            drop(guard);
                            if let Err(e) = tun_w.write_all(&plain[..len]).await {
                                error!("TUN write: {e}");
                                break;
                            }
                        }
                        Err(e) => warn!(index, "decrypt: {e}"),
                    }
                }
            }
        }
    });

    // TUN → UDP
    let state_out = Arc::clone(&state);
    let sock_out = Arc::clone(&sock);
    let uplink = tokio::spawn(async move {
        let mut plain = vec![0u8; MAX_MESSAGE];
        let mut wire = vec![0u8; MAX_MESSAGE];
        loop {
            let n = match tun_r.read(&mut plain).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    error!("TUN read: {e}");
                    break;
                }
            };
            let Some(dst) = ipv4_dst(&plain[..n]) else {
                continue;
            };
            let mut guard = state_out.lock().await;
            let Some(&index) = guard.by_ip.get(&dst) else {
                // Not a known peer; drop (or could be broadcast — ignore).
                continue;
            };
            let Some(live) = guard.by_index.get_mut(&index) else {
                continue;
            };
            let peer = live.peer_addr;
            match live.session.encrypt(&plain[..n], &mut wire) {
                Ok(len) => {
                    drop(guard);
                    if let Err(e) = sock_out.send_to(&wire[..len], peer).await {
                        warn!(%peer, "UDP send: {e}");
                    }
                }
                Err(e) => warn!("encrypt: {e}"),
            }
        }
    });

    tokio::select! {
        _ = uplink => {},
        _ = downlink => {},
        _ = tokio::signal::ctrl_c() => {
            info!("ctrl-c, shutting down");
        }
    }

    Ok(())
}

async fn handle_handshake(
    private: &[u8; 32],
    msg: &[u8],
    src: SocketAddr,
    state: &Arc<Mutex<State>>,
) -> Result<Vec<u8>> {
    let responder = HandshakeResponder::new(private)?;
    let (session, response) = responder.finish(msg)?;
    let remote = session
        .remote_static()
        .context("missing remote static after IK")?;

    let mut guard = state.lock().await;
    let meta = guard
        .peers
        .get(&remote)
        .with_context(|| format!("unknown peer public key from {src}"))?
        .clone_meta();

    // Drop any previous session for this tunnel IP.
    if let Some(old_idx) = guard.by_ip.remove(&meta.tunnel_ip) {
        guard.by_index.remove(&old_idx);
    }

    let index = session.index;
    guard.by_ip.insert(meta.tunnel_ip, index);
    guard.by_index.insert(
        index,
        LiveSession {
            session,
            peer_addr: src,
            tunnel_ip: meta.tunnel_ip,
        },
    );
    info!(%src, peer = %meta.tunnel_ip, index, "session established");
    Ok(response)
}

impl PeerMeta {
    fn clone_meta(&self) -> PeerMeta {
        PeerMeta {
            public_key: self.public_key,
            tunnel_ip: self.tunnel_ip,
        }
    }
}

fn ipv4_dst(packet: &[u8]) -> Option<Ipv4Addr> {
    // Need at least IPv4 header with dest.
    if packet.len() < 20 {
        return None;
    }
    // Version nibble
    if packet[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ))
}

fn ipv4_network(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }
    let mask = u32::MAX << (32 - prefix);
    Ipv4Addr::from(u32::from(addr) & mask)
}
