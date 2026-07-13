use crate::config::{parse_cidr, parse_mode, ClientConfig};
use crate::control::{self, EnableHook};
use crate::crypto::{HandshakeInitiator, Session, MAX_MESSAGE};
use crate::route::{ClientRouteOpts, ClientRoutes};
use crate::stats::{Role, RuntimeStats};
use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{watch, Mutex};
use tokio::time::{timeout, Duration};
use tracing::{error, info, warn};
use tun::AbstractDevice;

struct SessionSlot {
    session: Session,
    established: Instant,
    last_rx: Instant,
    last_tx: Instant,
}

pub async fn run(cfg: ClientConfig, control_socket: PathBuf) -> Result<()> {
    let private = cfg.load_private_key()?;
    let server_pub = cfg.load_server_public_key()?;
    let (addr, prefix) = parse_cidr(&cfg.address)?;
    let control_mode = parse_mode(&cfg.control_mode)?;
    let kill_switch = cfg.kill_switch;
    let endpoint = cfg.endpoint;

    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("bind client UDP")?;
    sock.connect(endpoint)
        .await
        .context("connect to server endpoint")?;
    info!(endpoint = %endpoint, local = %sock.local_addr()?, "UDP ready");

    // Serialize UDP recv between downlink and handshake/rekey.
    let recv_gate = Arc::new(Mutex::new(()));

    let session = handshake(&sock, &recv_gate, &private, &server_pub).await?;
    let now = Instant::now();
    let session = Arc::new(Mutex::new(SessionSlot {
        session,
        established: now,
        last_rx: now,
        last_tx: now,
    }));
    info!("handshake complete");

    let tun = crate::tun_dev::create("soulvpn", addr, prefix, cfg.mtu)?;
    let tun_name = tun.tun_name().unwrap_or_else(|_| "soulvpn".into());
    info!(%tun_name, %addr, prefix, "TUN up");

    let routes = ClientRoutes::install(
        endpoint,
        &tun_name,
        ClientRouteOpts {
            redirect_all: cfg.redirect_all,
            kill_switch,
            disable_ipv6: cfg.disable_ipv6,
            dns: cfg.dns.clone(),
        },
    )?;
    let routes = Arc::new(Mutex::new(routes));

    let stats = RuntimeStats::new(
        Role::Client,
        endpoint.to_string(),
        cfg.address.clone(),
        tun_name.clone(),
    );
    stats.record_handshake_ok();
    stats.set_sessions(1);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let routes_hook = Arc::clone(&routes);
    let stats_hook = Arc::clone(&stats);
    let on_enable: EnableHook = Arc::new(move |on| {
        let routes = Arc::clone(&routes_hook);
        let stats = Arc::clone(&stats_hook);
        std::thread::spawn(move || {
            let mut g = routes.blocking_lock();
            if on {
                if let Err(e) = g.reenable_with_ks(endpoint, kill_switch) {
                    warn!("re-enable routes: {e}");
                } else {
                    info!("tunnel enabled");
                }
            } else {
                g.teardown();
                info!("tunnel disabled (routes removed, process stays up)");
            }
            stats.set_enabled(on);
        });
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

    let (mut tun_r, mut tun_w) = tokio::io::split(tun);
    let sock = Arc::new(sock);

    let sess_up = Arc::clone(&session);
    let sock_up = Arc::clone(&sock);
    let stats_up = Arc::clone(&stats);
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
            if !stats_up.is_enabled() {
                continue;
            }
            let mut guard = sess_up.lock().await;
            match guard.session.encrypt(&plain[..n], &mut wire) {
                Ok(len) => {
                    guard.last_tx = Instant::now();
                    drop(guard);
                    match sock_up.send(&wire[..len]).await {
                        Ok(_) => stats_up.record_tx(n as u64),
                        Err(e) => {
                            error!("UDP send: {e}");
                            break;
                        }
                    }
                }
                Err(e) => {
                    stats_up.record_encrypt_err();
                    warn!("encrypt: {e}");
                }
            }
        }
    });

    let sess_dn = Arc::clone(&session);
    let sock_dn = Arc::clone(&sock);
    let stats_dn = Arc::clone(&stats);
    let gate_dn = Arc::clone(&recv_gate);
    let downlink = tokio::spawn(async move {
        let mut wire = vec![0u8; MAX_MESSAGE];
        let mut plain = vec![0u8; MAX_MESSAGE];
        loop {
            let n = {
                let _gate = gate_dn.lock().await;
                match sock_dn.recv(&mut wire).await {
                    Ok(n) => n,
                    Err(e) => {
                        error!("UDP recv: {e}");
                        break;
                    }
                }
            };
            if !stats_dn.is_enabled() {
                // Still consume packets so the socket buffer doesn't fill;
                // do not feed TUN while disabled.
                continue;
            }
            let mut guard = sess_dn.lock().await;
            match guard.session.decrypt(&wire[..n], &mut plain) {
                Ok(len) => {
                    guard.last_rx = Instant::now();
                    drop(guard);
                    if len == 0 {
                        stats_dn.touch_activity();
                        continue;
                    }
                    match tun_w.write_all(&plain[..len]).await {
                        Ok(()) => stats_dn.record_rx(len as u64),
                        Err(e) => {
                            error!("TUN write: {e}");
                            break;
                        }
                    }
                }
                Err(e) => {
                    stats_dn.record_decrypt_err();
                    warn!("decrypt: {e}");
                }
            }
        }
    });

    // Keepalive / rekey / reconnect maintenance.
    let sess_m = Arc::clone(&session);
    let sock_m = Arc::clone(&sock);
    let gate_m = Arc::clone(&recv_gate);
    let stats_m = Arc::clone(&stats);
    let private_m = private;
    let server_pub_m = server_pub;
    let keepalive = Duration::from_secs(cfg.keepalive_secs);
    let rekey = Duration::from_secs(cfg.rekey_secs);
    let reconnect = Duration::from_secs(cfg.reconnect_timeout_secs.max(10));
    let mut maint_shutdown = shutdown_tx.subscribe();
    let maintenance = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut wire = vec![0u8; 64];
        loop {
            tokio::select! {
                _ = maint_shutdown.changed() => {
                    if *maint_shutdown.borrow() { break; }
                }
                _ = tick.tick() => {
                    if !stats_m.is_enabled() {
                        continue;
                    }
                    let now = Instant::now();
                    let (need_rekey, need_reconnect, need_keepalive) = {
                        let g = sess_m.lock().await;
                        let age = now.duration_since(g.established);
                        let idle_rx = now.duration_since(g.last_rx);
                        let idle_tx = now.duration_since(g.last_tx);
                        let need_rekey = cfg.rekey_secs > 0 && age >= rekey;
                        let need_reconnect = idle_rx >= reconnect;
                        let need_keepalive = cfg.keepalive_secs > 0
                            && idle_tx >= keepalive
                            && idle_rx >= keepalive;
                        (need_rekey, need_reconnect, need_keepalive)
                    };

                    if need_rekey || need_reconnect {
                        let reason = if need_reconnect { "silence" } else { "rekey" };
                        info!(reason, "re-handshaking");
                        match handshake(&sock_m, &gate_m, &private_m, &server_pub_m).await {
                            Ok(new_sess) => {
                                let mut g = sess_m.lock().await;
                                g.session = new_sess;
                                g.established = Instant::now();
                                g.last_rx = Instant::now();
                                g.last_tx = Instant::now();
                                stats_m.record_handshake_ok();
                                if need_reconnect {
                                    stats_m.record_reconnect();
                                }
                                info!("re-handshake complete");
                            }
                            Err(e) => {
                                stats_m.record_handshake_fail();
                                warn!("re-handshake failed: {e}");
                            }
                        }
                        continue;
                    }

                    if need_keepalive {
                        let mut g = sess_m.lock().await;
                        match g.session.encrypt(&[], &mut wire) {
                            Ok(len) => {
                                g.last_tx = Instant::now();
                                drop(g);
                                if let Err(e) = sock_m.send(&wire[..len]).await {
                                    warn!("keepalive send: {e}");
                                }
                            }
                            Err(e) => warn!("keepalive encrypt: {e}"),
                        }
                    }
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
    let _ = maintenance.await;
    // Drop routes → full teardown including host route / KS / DNS / IPv6.
    drop(routes);
    Ok(())
}

async fn handshake(
    sock: &UdpSocket,
    recv_gate: &Mutex<()>,
    private: &[u8; 32],
    server_pub: &[u8; 32],
) -> Result<Session> {
    const ATTEMPTS: u32 = 10;
    const WAIT: Duration = Duration::from_secs(2);

    for attempt in 1..=ATTEMPTS {
        let mut init = HandshakeInitiator::new(private, server_pub)?;
        let mut buf = [0u8; 256];
        let n = init.write_init(&mut buf)?;
        sock.send(&buf[..n]).await.context("send handshake init")?;
        info!(attempt, "handshake init sent");

        let mut resp = [0u8; 256];
        // Hold recv gate so downlink doesn't steal the response.
        let result = {
            let _gate = recv_gate.lock().await;
            timeout(WAIT, sock.recv(&mut resp)).await
        };
        match result {
            Ok(Ok(len)) => match init.finish(&resp[..len]) {
                Ok(session) => return Ok(session),
                Err(e) => {
                    warn!("handshake finish failed: {e}");
                }
            },
            Ok(Err(e)) => warn!("recv error during handshake: {e}"),
            Err(_) => warn!("handshake timeout"),
        }
    }
    bail!("handshake failed after {ATTEMPTS} attempts")
}
