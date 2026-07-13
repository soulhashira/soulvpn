//! Linux route / NAT helpers. Requires root or CAP_NET_ADMIN.

use anyhow::{bail, Context, Result};
use std::net::{Ipv4Addr, SocketAddr};
use std::process::Command;
use tracing::{info, warn};

/// Snapshot of routes installed by the client so we can tear them down.
#[derive(Debug, Default)]
pub struct ClientRoutes {
    pub server_host: Option<Ipv4Addr>,
    pub via_gateway: Option<Ipv4Addr>,
    pub via_dev: Option<String>,
    pub redirect_all: bool,
    pub tun_name: String,
}

impl ClientRoutes {
    /// Install:
    /// 1. Host route to VPN server via original default gateway.
    /// 2. Full-tunnel split default (0.0.0.0/1 + 128.0.0.0/1 → TUN).
    pub fn install(endpoint: SocketAddr, tun_name: &str, redirect_all: bool) -> Result<Self> {
        let mut state = ClientRoutes {
            server_host: None,
            via_gateway: None,
            via_dev: None,
            redirect_all,
            tun_name: tun_name.to_string(),
        };

        let server_ip = match endpoint {
            SocketAddr::V4(a) => *a.ip(),
            SocketAddr::V6(_) => {
                warn!("IPv6 endpoint: skipping host-route install");
                return Ok(state);
            }
        };

        let (gateway, dev) = default_route().context("detect default route")?;
        info!(%gateway, %dev, "default route");

        // Keep the path to the VPN server outside the tunnel.
        run(&[
            "ip",
            "route",
            "replace",
            &server_ip.to_string(),
            "via",
            &gateway.to_string(),
            "dev",
            &dev,
        ])?;
        state.server_host = Some(server_ip);
        state.via_gateway = Some(gateway);
        state.via_dev = Some(dev);

        if redirect_all {
            run(&["ip", "route", "replace", "0.0.0.0/1", "dev", tun_name])?;
            run(&["ip", "route", "replace", "128.0.0.0/1", "dev", tun_name])?;
            info!("full-tunnel routes installed via {tun_name}");
        }

        Ok(state)
    }
    pub fn teardown(&mut self) {
        if self.redirect_all {
            let _ = run(&["ip", "route", "del", "0.0.0.0/1", "dev", &self.tun_name]);
            let _ = run(&["ip", "route", "del", "128.0.0.0/1", "dev", &self.tun_name]);
            // Keep host route while process lives so re-enable can re-add tunnel routes.
            // Only drop host route on full drop (process exit) via take().
        }
        info!("full-tunnel routes removed (host route kept)");
    }

    /// Re-install full-tunnel split defaults (host route must already exist).
    pub fn reenable(&mut self) -> Result<()> {
        if self.redirect_all {
            run(&["ip", "route", "replace", "0.0.0.0/1", "dev", &self.tun_name])?;
            run(&["ip", "route", "replace", "128.0.0.0/1", "dev", &self.tun_name])?;
            info!("full-tunnel routes reinstalled via {}", self.tun_name);
        }
        Ok(())
    }

    fn teardown_all(&mut self) {
        if self.redirect_all {
            let _ = run(&["ip", "route", "del", "0.0.0.0/1", "dev", &self.tun_name]);
            let _ = run(&["ip", "route", "del", "128.0.0.0/1", "dev", &self.tun_name]);
        }
        if let (Some(host), Some(gw), Some(dev)) = (
            self.server_host.take(),
            self.via_gateway.take(),
            self.via_dev.take(),
        ) {
            let _ = run(&[
                "ip",
                "route",
                "del",
                &host.to_string(),
                "via",
                &gw.to_string(),
                "dev",
                &dev,
            ]);
        }
        info!("client routes fully torn down");
    }
}

impl Drop for ClientRoutes {
    fn drop(&mut self) {
        self.teardown_all();
    }
}

/// Enable IPv4 forwarding and MASQUERADE outbound traffic from the tunnel subnet.
pub fn setup_nat(tun_cidr: &str) -> Result<()> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1").context("enable ip_forward")?;
    let egress = default_egress_dev().context("detect egress iface for MASQUERADE")?;
    // Idempotent-ish: ignore "rule exists" failures.
    let _ = run(&[
        "iptables",
        "-t",
        "nat",
        "-C",
        "POSTROUTING",
        "-s",
        tun_cidr,
        "-o",
        &egress,
        "-j",
        "MASQUERADE",
    ]);
    run(&[
        "iptables",
        "-t",
        "nat",
        "-A",
        "POSTROUTING",
        "-s",
        tun_cidr,
        "-o",
        &egress,
        "-j",
        "MASQUERADE",
    ])?;
    info!(%tun_cidr, %egress, "NAT MASQUERADE installed");
    Ok(())
}

fn default_route() -> Result<(Ipv4Addr, String)> {
    let out = Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .context("ip route show default")?;
    if !out.status.success() {
        bail!(
            "ip route show default failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // "default via 192.168.1.1 dev eth0 ..."
    let mut gateway = None;
    let mut dev = None;
    let mut parts = text.split_whitespace();
    while let Some(tok) = parts.next() {
        match tok {
            "via" => gateway = parts.next().and_then(|s| s.parse().ok()),
            "dev" => dev = parts.next().map(|s| s.to_string()),
            _ => {}
        }
    }
    match (gateway, dev) {
        (Some(g), Some(d)) => Ok((g, d)),
        _ => bail!("could not parse default route: {text}"),
    }
}

fn default_egress_dev() -> Result<String> {
    Ok(default_route()?.1)
}

fn run(args: &[&str]) -> Result<()> {
    let status = Command::new(args[0])
        .args(&args[1..])
        .status()
        .with_context(|| format!("spawn {}", args[0]))?;
    if !status.success() {
        bail!("command failed ({status}): {}", args.join(" "));
    }
    Ok(())
}
