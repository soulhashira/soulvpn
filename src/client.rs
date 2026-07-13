use crate::config::{decode_key, parse_cidr, ClientConfig};
use crate::control::{self, EnableHook};
use crate::crypto::{HandshakeInitiator, Session, MAX_MESSAGE};
use crate::route::ClientRoutes;
use crate::stats::{Role, RuntimeStats};
use crate::tun_dev;
use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{watch, Mutex};
use tokio::time::{timeout, Duration};
use tracing::{error, info, warn};
use tun::AbstractDevice;

pub async fn run(cfg: ClientConfig, control_socket: PathBuf) -> Result<()> {
    let private = decode_key(&cfg.private_key)?;
    let server_pub = decode_key(&cfg.server_public_key)?;
    let (addr, prefix) = parse_cidr(&cfg.address)?;

    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("bind client UDP")?;
    sock.connect(cfg.endpoint)
        .await
        .context("connect to server endpoint")?;
    info!(endpoint = %cfg.endpoint, local = %sock.local_addr()?, "UDP ready");

    let session = handshake(&sock, &private, &server_pub).await?;
    let session = Arc::new(Mutex::new(session));
    info!("handshake complete");

    let tun = tun_dev::create("soulvpn", addr, prefix, cfg.mtu)?;
    let tun_name = tun.tun_name().unwrap_or_else(|_| "soulvpn".into());
    info!(%tun_name, %addr, prefix, "TUN up");

    let routes = ClientRoutes::install(cfg.endpoint, &tun_name, cfg.redirect_all)?;
    let routes = Arc::new(Mutex::new(routes));

    let stats = RuntimeStats::new(
        Role::Client,
        cfg.endpoint.to_string(),
        cfg.address.clone(),
        tun_name.clone(),
    );
    stats.record_handshake_ok();
    stats.set_sessions(1);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Toggle full-tunnel routes when the control plane flips enable.
    let routes_hook = Arc::clone(&routes);
    let stats_hook = Arc::clone(&stats);
    let on_enable: EnableHook = Arc::new(move |on| {
        let routes = Arc::clone(&routes_hook);
        let stats = Arc::clone(&stats_hook);
        // Route ops are sync + short; run on a blocking thread so we don't stall the runtime.
        std::thread::spawn(move || {
            let mut g = routes.blocking_lock();
            if on {
                if let Err(e) = g.reenable() {
                    warn!("re-enable routes: {e}");
                } else {
                    info!("tunnel enabled");
                }
            } else {
                g.teardown();
                info!("tunnel disabled (routes removed, process stays up)");
            }
            // Keep stats flag in sync if hook is ever called outside control.rs
            stats.set_enabled(on);
        });
    });

    let control_stats = Arc::clone(&stats);
    let control_task = tokio::spawn(async move {
        if let Err(e) = control::serve(control_socket, control_stats, on_enable, shutdown_rx).await
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
            match guard.encrypt(&plain[..n], &mut wire) {
                Ok(len) => {
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
    let downlink = tokio::spawn(async move {
        let mut wire = vec![0u8; MAX_MESSAGE];
        let mut plain = vec![0u8; MAX_MESSAGE];
        loop {
            let n = match sock_dn.recv(&mut wire).await {
                Ok(n) => n,
                Err(e) => {
                    error!("UDP recv: {e}");
                    break;
                }
            };
            if !stats_dn.is_enabled() {
                continue;
            }
            let mut guard = sess_dn.lock().await;
            match guard.decrypt(&wire[..n], &mut plain) {
                Ok(len) => {
                    drop(guard);
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

    tokio::select! {
        _ = uplink => {},
        _ = downlink => {},
        _ = tokio::signal::ctrl_c() => {
            info!("ctrl-c, shutting down");
        }
    }

    let _ = shutdown_tx.send(true);
    let _ = control_task.await;
    // Drop routes → full teardown including host route.
    drop(routes);
    Ok(())
}

async fn handshake(
    sock: &UdpSocket,
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
        match timeout(WAIT, sock.recv(&mut resp)).await {
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
