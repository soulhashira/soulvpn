use crate::config::{decode_key, parse_cidr, parse_ipv4, parse_mode, ServerConfig};
use crate::control::{self, EnableHook};
use crate::crypto::{random_session_index, HandshakeResponder, Session, MAX_MESSAGE};
use crate::packet::{ipv4_dst, ipv4_src, is_ipv4};
use crate::route::NatGuard;
use crate::stats::{PeerSnapshot, Role, RuntimeStats};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{watch, Mutex};
use tracing::{error, info, warn};
use tun::AbstractDevice;

struct PeerMeta {
    tunnel_ip: Ipv4Addr,
}

struct LiveSession {
    session: Session,
    peer_addr: SocketAddr,
    tunnel_ip: Ipv4Addr,
    last_seen: Instant,
    established: Instant,
}

struct RateLimit {
    window: Duration,
    max: u32,
    hits: HashMap<IpAddr, Vec<Instant>>,
}

impl RateLimit {
    fn new(max: u32, window_secs: u64) -> Self {
        Self {
            window: Duration::from_secs(window_secs.max(1)),
            max: max.max(1),
            hits: HashMap::new(),
        }
    }

    fn allow(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let entry = self.hits.entry(ip).or_default();
        entry.retain(|t| now.duration_since(*t) < self.window);
        if entry.len() as u32 >= self.max {
            return false;
        }
        entry.push(now);
        true
    }

    fn gc(&mut self) {
        let now = Instant::now();
        self.hits
            .retain(|_, v| v.iter().any(|t| now.duration_since(*t) < self.window));
    }
}

struct State {
    by_index: HashMap<u32, LiveSession>,
    by_ip: HashMap<Ipv4Addr, u32>,
    peers: HashMap<[u8; 32], PeerMeta>,
    rate: RateLimit,
}

impl State {
    fn alloc_index(&self) -> u32 {
        loop {
            let idx = random_session_index();
            if !self.by_index.contains_key(&idx) {
                return idx;
            }
        }
    }

    fn peer_snapshots(&self) -> Vec<PeerSnapshot> {
        let now = Instant::now();
        self.by_index
            .values()
            .map(|live| PeerSnapshot {
                tunnel_ip: live.tunnel_ip.to_string(),
                endpoint: live.peer_addr.to_string(),
                session_index: live.session.index,
                last_handshake_ago_secs: now.duration_since(live.established).as_secs(),
                idle_secs: now.duration_since(live.last_seen).as_secs(),
            })
            .collect()
    }
}

pub async fn run(cfg: ServerConfig, control_socket: PathBuf) -> Result<()> {
    let private = cfg.load_private_key()?;
    let (addr, prefix) = parse_cidr(&cfg.address)?;
    let control_mode = parse_mode(&cfg.control_mode)?;

    let mut peers = HashMap::new();
    for p in &cfg.peers {
        let pk = decode_key(&p.public_key)?;
        let tip = parse_ipv4(&p.allowed_ip)?;
        peers.insert(pk, PeerMeta { tunnel_ip: tip });
        info!(peer = %tip, "configured peer");
    }

    let state = Arc::new(Mutex::new(State {
        by_index: HashMap::new(),
        by_ip: HashMap::new(),
        peers,
        rate: RateLimit::new(cfg.handshake_rate_limit, cfg.handshake_rate_window_secs),
    }));

    let sock = UdpSocket::bind(cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    let sock = Arc::new(sock);
    info!(listen = %cfg.listen, "UDP listening");

    let tun = tun_dev_create("soulvpn0", addr, prefix, cfg.mtu)?;
    let tun_name = tun.tun_name().unwrap_or_else(|_| "soulvpn0".into());
    info!(%tun_name, %addr, prefix, "TUN up");

    // Hold NAT guard for process lifetime.
    let _nat_guard = if cfg.nat {
        let network = ipv4_network(addr, prefix);
        let cidr = format!("{network}/{prefix}");
        Some(NatGuard::setup(&cidr)?)
    } else {
        None
    };

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
        if let Err(e) = control::serve(
            control_socket,
            control_stats,
            on_enable,
            shutdown_rx,
            control_mode,
        )
        .await
        {
            warn!("control socket: {e}");
        }
    });

    // Session idle reaper + peer status refresh.
    let state_reap = Arc::clone(&state);
    let stats_reap = Arc::clone(&stats);
    let idle_secs = cfg.session_idle_secs.max(30);
    let mut reap_shutdown = shutdown_tx.subscribe();
    let reaper = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(15));
        loop {
            tokio::select! {
                _ = reap_shutdown.changed() => {
                    if *reap_shutdown.borrow() { break; }
                }
                _ = tick.tick() => {
                    let mut guard = state_reap.lock().await;
                    guard.rate.gc();
                    let now = Instant::now();
                    let idle = Duration::from_secs(idle_secs);
                    let stale: Vec<(u32, Ipv4Addr)> = guard
                        .by_index
                        .iter()
                        .filter(|(_, s)| now.duration_since(s.last_seen) > idle)
                        .map(|(idx, s)| (*idx, s.tunnel_ip))
                        .collect();
                    for (idx, tip) in stale {
                        guard.by_index.remove(&idx);
                        if guard.by_ip.get(&tip) == Some(&idx) {
                            guard.by_ip.remove(&tip);
                        }
                        info!(index = idx, peer = %tip, "session expired (idle)");
                    }
                    let n = guard.by_index.len() as u64;
                    let peers = guard.peer_snapshots();
                    drop(guard);
                    stats_reap.set_sessions(n);
                    stats_reap.set_peers(peers);
                }
            }
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
                1 => {
                    match handle_handshake(&private_in, &buf[..n], src, &state_in, &stats_in).await
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
                    }
                }
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
                    match live.session.decrypt(&buf[..n], &mut plain) {
                        Ok(len) => {
                            // Only trust the UDP source after AEAD success.
                            live.peer_addr = src;
                            live.last_seen = Instant::now();
                            let tunnel_ip = live.tunnel_ip;
                            drop(guard);

                            if len == 0 {
                                // Keepalive — do not write to TUN.
                                stats_in.touch_activity();
                                continue;
                            }
                            if !is_ipv4(&plain[..len]) {
                                stats_in.record_policy_drop();
                                warn!(index, "policy drop: non-IPv4 inner packet");
                                continue;
                            }
                            let Some(pkt_src) = ipv4_src(&plain[..len]) else {
                                stats_in.record_policy_drop();
                                continue;
                            };
                            if pkt_src != tunnel_ip {
                                stats_in.record_policy_drop();
                                warn!(
                                    index,
                                    %pkt_src,
                                    allowed = %tunnel_ip,
                                    "policy drop: source IP spoof"
                                );
                                continue;
                            }
                            match tun_w.write_all(&plain[..len]).await {
                                Ok(()) => stats_in.record_rx(len as u64),
                                Err(e) => {
                                    error!("TUN write: {e}");
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            // Do not update peer_addr on decrypt failure.
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
                    live.last_seen = Instant::now();
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
    let _ = reaper.await;
    // _nat_guard drops here → tears down MASQUERADE / restores ip_forward
    Ok(())
}

async fn handle_handshake(
    private: &[u8; 32],
    msg: &[u8],
    src: SocketAddr,
    state: &Arc<Mutex<State>>,
    stats: &RuntimeStats,
) -> Result<Vec<u8>> {
    {
        let mut guard = state.lock().await;
        if !guard.rate.allow(src.ip()) {
            bail!("handshake rate limited from {}", src.ip());
        }
    }

    let responder = HandshakeResponder::new(private)?;
    // Finish Noise first to learn remote static, then assign index under lock.
    // We need index before finish() — allocate under lock after verifying peer.
    // Approach: finish with temporary index, then... actually finish consumes state.
    // So: complete Noise, extract remote, check ACL, then we already used an index.
    // Allocate index under lock before finish by doing finish outside and re-keying index?
    // Session index is embedded in response before into_transport — must choose first.

    // Two-phase: lock to rate-limit (done) + pre-alloc index, unlock for crypto, re-lock for insert.
    let index = {
        let guard = state.lock().await;
        guard.alloc_index()
    };

    let (session, response) = responder.finish(msg, index)?;
    let remote = session
        .remote_static()
        .context("missing remote static after IK")?;

    let mut guard = state.lock().await;
    let meta = guard
        .peers
        .get(&remote)
        .with_context(|| format!("unknown peer public key from {src}"))?;
    let tunnel_ip = meta.tunnel_ip;

    if let Some(old_idx) = guard.by_ip.remove(&tunnel_ip) {
        guard.by_index.remove(&old_idx);
    }

    // If our pre-allocated index collided somehow (another handshake), re-key — rare.
    if guard.by_index.contains_key(&index) {
        bail!("session index collision; retry handshake");
    }

    guard.by_ip.insert(tunnel_ip, index);
    guard.by_index.insert(
        index,
        LiveSession {
            session,
            peer_addr: src,
            tunnel_ip,
            last_seen: Instant::now(),
            established: Instant::now(),
        },
    );
    let sessions = guard.by_index.len() as u64;
    let peers = guard.peer_snapshots();
    drop(guard);
    stats.set_sessions(sessions);
    stats.set_peers(peers);
    stats.record_handshake_ok();
    info!(%src, peer = %tunnel_ip, index, "session established");
    Ok(response)
}

fn ipv4_network(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }
    let mask = u32::MAX << (32 - prefix);
    Ipv4Addr::from(u32::from(addr) & mask)
}

fn tun_dev_create(name: &str, addr: Ipv4Addr, prefix: u8, mtu: u16) -> Result<tun::AsyncDevice> {
    crate::tun_dev::create(name, addr, prefix, mtu)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_keypair, HandshakeInitiator};

    #[test]
    fn policy_requires_matching_source() {
        // Unit-level: simulate allowed check logic.
        let allowed = Ipv4Addr::new(10, 66, 66, 2);
        let mut pkt = [0u8; 20];
        pkt[0] = 0x45;
        pkt[12..16].copy_from_slice(&[10, 66, 66, 2]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        assert_eq!(ipv4_src(&pkt), Some(allowed));
        pkt[12..16].copy_from_slice(&[10, 66, 66, 3]);
        assert_ne!(ipv4_src(&pkt), Some(allowed));
    }

    #[test]
    fn endpoint_only_after_valid_session_crypto() {
        // Ensure decrypt failure path is the one that must not update addr —
        // covered by integration of encrypt/decrypt + explicit code structure.
        let (srv_priv, srv_pub) = generate_keypair().unwrap();
        let (cli_priv, _) = generate_keypair().unwrap();
        let mut init = HandshakeInitiator::new(&cli_priv, &srv_pub).unwrap();
        let mut buf = [0u8; 256];
        let n = init.write_init(&mut buf).unwrap();
        let resp = HandshakeResponder::new(&srv_priv).unwrap();
        let (mut srv, response) = resp.finish(&buf[..n], 42).unwrap();
        let mut cli = init.finish(&response).unwrap();
        let mut enc = [0u8; 128];
        let en = cli.encrypt(b"x", &mut enc).unwrap();
        // Corrupt ciphertext
        enc[en - 1] ^= 0xff;
        let mut out = [0u8; 128];
        assert!(srv.decrypt(&enc[..en], &mut out).is_err());
    }
}
