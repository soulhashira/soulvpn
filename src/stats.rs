//! Shared runtime stats + enable flag for the control plane.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Client,
    Server,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerSnapshot {
    pub tunnel_ip: String,
    pub endpoint: String,
    pub session_index: u32,
    pub last_handshake_ago_secs: u64,
    pub idle_secs: u64,
}

#[derive(Debug)]
pub struct RuntimeStats {
    pub role: Role,
    pub started: Instant,
    endpoint: String,
    address: String,
    tun_name: String,
    enabled: AtomicBool,
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    encrypt_errors: AtomicU64,
    decrypt_errors: AtomicU64,
    policy_drops: AtomicU64,
    handshakes_ok: AtomicU64,
    handshakes_fail: AtomicU64,
    reconnects: AtomicU64,
    active_sessions: AtomicU64,
    last_activity_ms: AtomicU64,
    peers: Mutex<Vec<PeerSnapshot>>,
}

impl RuntimeStats {
    pub fn new(
        role: Role,
        endpoint: impl Into<String>,
        address: impl Into<String>,
        tun_name: impl Into<String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            role,
            started: Instant::now(),
            endpoint: endpoint.into(),
            address: address.into(),
            tun_name: tun_name.into(),
            enabled: AtomicBool::new(true),
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            encrypt_errors: AtomicU64::new(0),
            decrypt_errors: AtomicU64::new(0),
            policy_drops: AtomicU64::new(0),
            handshakes_ok: AtomicU64::new(0),
            handshakes_fail: AtomicU64::new(0),
            reconnects: AtomicU64::new(0),
            active_sessions: AtomicU64::new(0),
            last_activity_ms: AtomicU64::new(now_ms()),
            peers: Mutex::new(Vec::new()),
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Release);
        self.touch();
    }

    pub fn record_tx(&self, bytes: u64) {
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.touch();
    }

    pub fn record_rx(&self, bytes: u64) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.touch();
    }

    /// Mark liveness without counting traffic (keepalives).
    pub fn touch_activity(&self) {
        self.touch();
    }

    pub fn record_encrypt_err(&self) {
        self.encrypt_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_decrypt_err(&self) {
        self.decrypt_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_policy_drop(&self) {
        self.policy_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_handshake_ok(&self) {
        self.handshakes_ok.fetch_add(1, Ordering::Relaxed);
        self.touch();
    }

    pub fn record_handshake_fail(&self) {
        self.handshakes_fail.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_reconnect(&self) {
        self.reconnects.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_sessions(&self, n: u64) {
        self.active_sessions.store(n, Ordering::Relaxed);
    }

    pub fn set_peers(&self, peers: Vec<PeerSnapshot>) {
        if let Ok(mut g) = self.peers.lock() {
            *g = peers;
        }
    }

    fn touch(&self) {
        self.last_activity_ms.store(now_ms(), Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> StatusSnapshot {
        let peers = self.peers.lock().map(|g| g.clone()).unwrap_or_default();
        StatusSnapshot {
            role: self.role,
            enabled: self.is_enabled(),
            uptime_secs: self.started.elapsed().as_secs(),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            encrypt_errors: self.encrypt_errors.load(Ordering::Relaxed),
            decrypt_errors: self.decrypt_errors.load(Ordering::Relaxed),
            policy_drops: self.policy_drops.load(Ordering::Relaxed),
            handshakes_ok: self.handshakes_ok.load(Ordering::Relaxed),
            handshakes_fail: self.handshakes_fail.load(Ordering::Relaxed),
            reconnects: self.reconnects.load(Ordering::Relaxed),
            active_sessions: self.active_sessions.load(Ordering::Relaxed),
            last_activity_ms: self.last_activity_ms.load(Ordering::Relaxed),
            endpoint: self.endpoint.clone(),
            address: self.address.clone(),
            tun_name: self.tun_name.clone(),
            pid: std::process::id(),
            peers,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusSnapshot {
    pub role: Role,
    pub enabled: bool,
    pub uptime_secs: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub encrypt_errors: u64,
    pub decrypt_errors: u64,
    #[serde(default)]
    pub policy_drops: u64,
    pub handshakes_ok: u64,
    pub handshakes_fail: u64,
    #[serde(default)]
    pub reconnects: u64,
    pub active_sessions: u64,
    pub last_activity_ms: u64,
    pub endpoint: String,
    pub address: String,
    pub tun_name: String,
    pub pid: u32,
    #[serde(default)]
    pub peers: Vec<PeerSnapshot>,
}

impl StatusSnapshot {
    pub fn format_human(&self) -> String {
        let state = if self.enabled { "ON " } else { "OFF" };
        let mut out = format!(
            "soulvpn {role:?}  [{state}]  pid {pid}\n\
             endpoint   {endpoint}\n\
             address    {address}\n\
             tun        {tun}\n\
             uptime     {uptime}\n\
             sessions   {sessions}\n\
             tx         {tx_p} pkts  {tx_b}\n\
             rx         {rx_p} pkts  {rx_b}\n\
             handshakes ok={ok}  fail={fail}  reconnects={rc}\n\
             errors     encrypt={ee}  decrypt={de}  policy={pd}\n\
             last act   {ago} ago",
            role = self.role,
            state = state,
            pid = self.pid,
            endpoint = self.endpoint,
            address = self.address,
            tun = self.tun_name,
            uptime = format_duration(Duration::from_secs(self.uptime_secs)),
            sessions = self.active_sessions,
            tx_p = self.tx_packets,
            tx_b = format_bytes(self.tx_bytes),
            rx_p = self.rx_packets,
            rx_b = format_bytes(self.rx_bytes),
            ok = self.handshakes_ok,
            fail = self.handshakes_fail,
            rc = self.reconnects,
            ee = self.encrypt_errors,
            de = self.decrypt_errors,
            pd = self.policy_drops,
            ago = format_duration(Duration::from_millis(
                now_ms().saturating_sub(self.last_activity_ms)
            )),
        );
        if !self.peers.is_empty() {
            out.push_str("\npeers:\n");
            for p in &self.peers {
                out.push_str(&format!(
                    "  {tip}  via {ep}  idx={idx}  hs={hs}s ago  idle={idle}s\n",
                    tip = p.tunnel_ip,
                    ep = p.endpoint,
                    idx = p.session_index,
                    hs = p.last_handshake_ago_secs,
                    idle = p.idle_secs,
                ));
            }
        }
        out
    }
}

pub fn format_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.2} {}", UNITS[i])
    }
}

pub fn format_duration(d: Duration) -> String {
    let s = d.as_secs();
    let h = s / 3600;
    let m = (s % 3600) / 60;
    let sec = s % 60;
    if h > 0 {
        format!("{h}h{m:02}m{sec:02}s")
    } else if m > 0 {
        format!("{m}m{sec:02}s")
    } else {
        format!("{sec}s")
    }
}

pub fn format_rate(bytes_per_sec: f64) -> String {
    format!("{}/s", format_bytes(bytes_per_sec.max(0.0) as u64))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
