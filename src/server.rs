use crate::config::{decode_key, parse_cidr, parse_ipv4, ServerConfig};
use crate::control::{self, EnableHook};
use crate::crypto::{HandshakeResponder, Session, MAX_MESSAGE};
use crate::route;
use crate::stats::{Role, RuntimeStats};
use crate::tun_dev;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{watch, Mutex};
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
    by_index: HashMap<u32, LiveSession>,
    by_ip: HashMap<Ipv4Addr, u32>,
    peers: HashMap<[u8; 32], PeerMeta>,
}

pub async fn run(cfg: ServerConfig, control_socket: PathBuf) -> Result<()> {
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
        let network = ipv4_network(addr, prefix);
        let cidr = format!("{network}/{prefix}");
        route::setup_nat(&cidr)?;
    }

    let stats = RuntimeStats::new(
        Role::Server,
        cfg.listen.to_string(),
        cfg.address.clone(),
        tun_name.clone(),
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let on_enable: EnableHook = Arc::new(|on| {
        if on {
            info!("data plane enabled");
        } else {
            info!("data plane disabled (handshakes still accepted)");
        }
    });
    let control_stats = Arc::clone(&stats);
    let control_task = tokio::spawn(async move {
        if let Err(e) = control::serve(control_socket, control_stats, on_enable, shutdown_rx).await
        {
            warn!("control socket: {e}");
        }
    });

    let (mut tun_r, mut tun_w) = tokio::io::split(tun);

    // UDP → TUN
    let state_in = Arc::clone(&state);
    let sock_in = Arc::clone(&sock);
    let private_in = private;
    let stats_in = Arc::clone(&stats);
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
                1 => match handle_handshake(&private_in, &buf[..n], src, &state_in, &stats_in)
                    .await
                {
                    Ok(response) => {
                        if let Err(e) = sock_in.send_to(&response, src).await {
                            warn!("send handshake response: {e}");
                        } else {
                            info!(%src, "handshake accepted");
                        }
                    }
                    Err(e) => {
                        stats_in.record_handshake_fail();
                        warn!(%src, "handshake rejected: {e}");
                    }
                },
                _ => {
                    if !stats_in.is_enabled() {
                        continue;
                    }
                    if n < 12 {
                        continue;
                    }
                    let index = u32::from_le_bytes(buf[0..4].try_into().unwrap());
                    let mut guard = state_in.lock().await;
                    let Some(live) = guard.by_index.get_mut(&index) else {
                        warn!(index, %src, "unknown session");
                        continue;
                    };
                    live.peer_addr = src;
                    match live.session.decrypt(&buf[..n], &mut plain) {
                        Ok(len) => {
                            drop(guard);
                            match tun_w.write_all(&plain[..len]).await {
                                Ok(()) => stats_in.record_rx(len as u64),
                                Err(e) => {
                                    error!("TUN write: {e}");
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            stats_in.record_decrypt_err();
                            warn!(index, "decrypt: {e}");
                        }
                    }
                }
            }
        }
    });

    // TUN → UDP
    let state_out = Arc::clone(&state);
    let sock_out = Arc::clone(&sock);
    let stats_out = Arc::clone(&stats);
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
            if !stats_out.is_enabled() {
                continue;
            }
            let Some(dst) = ipv4_dst(&plain[..n]) else {
                continue;
            };
            let mut guard = state_out.lock().await;
            let Some(&index) = guard.by_ip.get(&dst) else {
                continue;
            };
            let Some(live) = guard.by_index.get_mut(&index) else {
                continue;
            };
            let peer = live.peer_addr;
            match live.session.encrypt(&plain[..n], &mut wire) {
                Ok(len) => {
                    drop(guard);
                    match sock_out.send_to(&wire[..len], peer).await {
                        Ok(_) => stats_out.record_tx(n as u64),
                        Err(e) => warn!(%peer, "UDP send: {e}"),
                    }
                }
                Err(e) => {
                    stats_out.record_encrypt_err();
                    warn!("encrypt: {e}");
                }
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

    let _ = shutdown_tx.send(true);
    let _ = control_task.await;
    Ok(())
}

async fn handle_handshake(
    private: &[u8; 32],
    msg: &[u8],
    src: SocketAddr,
    state: &Arc<Mutex<State>>,
    stats: &RuntimeStats,
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
    let sessions = guard.by_index.len() as u64;
    drop(guard);
    stats.set_sessions(sessions);
    stats.record_handshake_ok();
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
    if packet.len() < 20 {
        return None;
    }
    if packet[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[16],
        packet[17],
        packet[18],
        packet[19],
    ))
}

fn ipv4_network(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }
    let mask = u32::MAX << (32 - prefix);
    Ipv4Addr::from(u32::from(addr) & mask)
}
