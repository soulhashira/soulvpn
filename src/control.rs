//! Local Unix control socket: status / on / off.
//!
//! Wire format: u32 LE length + JSON body.
//! Request:  {"op":"status"|"on"|"off"|"quit"}
//! Response: {"ok":true,"status":{…}} | {"ok":false,"error":"…"}

use crate::stats::{RuntimeStats, StatusSnapshot};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use tracing::{info, warn};

pub const DEFAULT_CONTROL_SOCKET: &str = "/run/soulvpn/control.sock";

#[derive(Debug, Deserialize)]
struct Request {
    op: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Response {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<StatusSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

/// Callback when enable state is toggled by the control plane.
pub type EnableHook = Arc<dyn Fn(bool) + Send + Sync>;

/// Serve the control socket until `shutdown` flips or process exits.
pub async fn serve(
    path: PathBuf,
    stats: Arc<RuntimeStats>,
    on_enable: EnableHook,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create control dir {}", parent.display()))?;
    }
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)
        .with_context(|| format!("bind control socket {}", path.display()))?;
    // Personal box: any local user can monitor/toggle.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666));
    }
    info!(path = %path.display(), "control socket listening");

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _)) => {
                        let stats = Arc::clone(&stats);
                        let on_enable = Arc::clone(&on_enable);
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, stats, on_enable).await {
                                warn!("control client: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        warn!("control accept: {e}");
                    }
                }
            }
        }
    }

    let _ = std::fs::remove_file(&path);
    Ok(())
}

async fn handle_client(
    mut stream: UnixStream,
    stats: Arc<RuntimeStats>,
    on_enable: EnableHook,
) -> Result<()> {
    let req = read_msg::<Request>(&mut stream).await?;
    let resp = match req.op.as_str() {
        "status" => Response {
            ok: true,
            status: Some(stats.snapshot()),
            error: None,
            message: None,
        },
        "on" => {
            if !stats.is_enabled() {
                stats.set_enabled(true);
                on_enable(true);
            }
            Response {
                ok: true,
                status: Some(stats.snapshot()),
                error: None,
                message: Some("enabled".into()),
            }
        }
        "off" => {
            if stats.is_enabled() {
                stats.set_enabled(false);
                on_enable(false);
            }
            Response {
                ok: true,
                status: Some(stats.snapshot()),
                error: None,
                message: Some("disabled".into()),
            }
        }
        other => Response {
            ok: false,
            status: None,
            error: Some(format!("unknown op: {other}")),
            message: None,
        },
    };
    write_msg(&mut stream, &resp).await
}

// ── Client helpers (status / on / off CLI) ─────────────────────────────────

pub async fn request(path: &Path, op: &str) -> Result<StatusSnapshot> {
    let mut stream = UnixStream::connect(path)
        .await
        .with_context(|| {
            format!(
                "connect control socket {} (is soulvpn server/client running?)",
                path.display()
            )
        })?;
    write_msg(&mut stream, &serde_json::json!({ "op": op })).await?;
    let resp: Response = read_msg(&mut stream).await?;
    if !resp.ok {
        bail!(resp.error.unwrap_or_else(|| "control request failed".into()));
    }
    resp.status
        .context("control response missing status payload")
}

async fn read_msg<T: for<'de> Deserialize<'de>>(stream: &mut UnixStream) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("read control frame length")?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > 1 << 20 {
        bail!("invalid control frame length {len}");
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .await
        .context("read control frame body")?;
    serde_json::from_slice(&body).context("parse control JSON")
}

async fn write_msg<T: Serialize>(stream: &mut UnixStream, msg: &T) -> Result<()> {
    let body = serde_json::to_vec(msg).context("encode control JSON")?;
    let len = (body.len() as u32).to_le_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::{Role, RuntimeStats};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn status_on_off_roundtrip() {
        let dir = tempfile_dir();
        let sock = dir.join("control.sock");
        let stats = RuntimeStats::new(Role::Client, "1.2.3.4:51820", "10.66.66.2/24", "soulvpn");
        stats.record_tx(100);
        stats.record_rx(50);

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_hook = Arc::clone(&calls);
        let last = Arc::new(AtomicUsize::new(2)); // 2 = unset
        let last_hook = Arc::clone(&last);
        let on_enable: EnableHook = Arc::new(move |on| {
            calls_hook.fetch_add(1, Ordering::SeqCst);
            last_hook.store(usize::from(on), Ordering::SeqCst);
        });

        let (tx, rx) = watch::channel(false);
        let serve_stats = Arc::clone(&stats);
        let serve_path = sock.clone();
        let handle = tokio::spawn(async move {
            serve(serve_path, serve_stats, on_enable, rx).await.unwrap();
        });

        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(sock.exists(), "control socket did not appear");

        let snap = request(&sock, "status").await.unwrap();
        assert!(snap.enabled);
        assert_eq!(snap.tx_packets, 1);
        assert_eq!(snap.rx_packets, 1);
        assert_eq!(snap.role, Role::Client);

        let snap = request(&sock, "off").await.unwrap();
        assert!(!snap.enabled);
        assert!(!stats.is_enabled());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(last.load(Ordering::SeqCst), 0);

        // Idempotent: already off → no second hook call.
        let snap = request(&sock, "off").await.unwrap();
        assert!(!snap.enabled);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let snap = request(&sock, "on").await.unwrap();
        assert!(snap.enabled);
        assert!(stats.is_enabled());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(last.load(Ordering::SeqCst), 1);

        let _ = tx.send(true);
        let _ = handle.await;
        let _ = std::fs::remove_dir_all(dir);
    }

    fn tempfile_dir() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "soulvpn-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
