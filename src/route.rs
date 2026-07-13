//! Linux route / NAT / kill-switch / DNS / IPv6 helpers. Requires root or CAP_NET_ADMIN.

use anyhow::{bail, Context, Result};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::Command;
use tracing::{info, warn};

const KS_CHAIN: &str = "SOULVPN_KS";
const RESOLV_BACKUP: &str = "/etc/resolv.conf.soulvpn.bak";

/// Snapshot of routes installed by the client so we can tear them down.
#[derive(Default)]
pub struct ClientRoutes {
    pub server_host: Option<Ipv4Addr>,
    pub via_gateway: Option<Ipv4Addr>,
    pub via_dev: Option<String>,
    pub redirect_all: bool,
    pub tun_name: String,
    kill_switch: Option<KillSwitch>,
    ipv6: Option<Ipv6Guard>,
    dns: Option<DnsGuard>,
}

pub struct ClientRouteOpts {
    pub redirect_all: bool,
    pub kill_switch: bool,
    pub disable_ipv6: bool,
    pub dns: Vec<String>,
}

impl ClientRoutes {
    /// Install:
    /// 1. Host route to VPN server via original default gateway.
    /// 2. Full-tunnel split default (0.0.0.0/1 + 128.0.0.0/1 → TUN).
    /// 3. Optional kill switch, IPv6 blackhole, DNS rewrite.
    pub fn install(endpoint: SocketAddr, tun_name: &str, opts: ClientRouteOpts) -> Result<Self> {
        let mut state = ClientRoutes {
            server_host: None,
            via_gateway: None,
            via_dev: None,
            redirect_all: opts.redirect_all,
            tun_name: tun_name.to_string(),
            kill_switch: None,
            ipv6: None,
            dns: None,
        };

        let server_ip = match endpoint {
            SocketAddr::V4(a) => *a.ip(),
            SocketAddr::V6(_) => {
                warn!("IPv6 endpoint: skipping host-route install (full-tunnel may break)");
                return Ok(state);
            }
        };
        let server_port = endpoint.port();

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
        state.via_dev = Some(dev.clone());

        if opts.redirect_all {
            run(&["ip", "route", "replace", "0.0.0.0/1", "dev", tun_name])?;
            run(&["ip", "route", "replace", "128.0.0.0/1", "dev", tun_name])?;
            info!("full-tunnel routes installed via {tun_name}");
        }

        if opts.disable_ipv6 {
            match Ipv6Guard::enable() {
                Ok(g) => {
                    info!("IPv6 blackhole routes installed (leak mitigation)");
                    state.ipv6 = Some(g);
                }
                Err(e) => warn!("IPv6 disable failed: {e}"),
            }
        } else if opts.redirect_all {
            warn!("IPv6 is not tunneled; traffic may leak over IPv6 (set disable_ipv6 = true)");
        }

        if !opts.dns.is_empty() {
            match DnsGuard::install(&opts.dns) {
                Ok(g) => {
                    info!(servers = ?opts.dns, "DNS rewritten via /etc/resolv.conf");
                    state.dns = Some(g);
                }
                Err(e) => warn!("DNS install failed: {e}"),
            }
        }

        if opts.kill_switch && opts.redirect_all {
            match KillSwitch::install(server_ip, server_port, tun_name, &dev) {
                Ok(ks) => {
                    info!("kill switch active (clearnet egress blocked while tunnel enabled)");
                    state.kill_switch = Some(ks);
                }
                Err(e) => warn!("kill switch install failed: {e}"),
            }
        }

        Ok(state)
    }

    /// Remove full-tunnel routes (and kill switch). Host route / IPv6 / DNS kept until full drop.
    pub fn teardown(&mut self) {
        if let Some(ks) = self.kill_switch.take() {
            drop(ks);
            info!("kill switch removed");
        }
        if self.redirect_all {
            let _ = run(&["ip", "route", "del", "0.0.0.0/1", "dev", &self.tun_name]);
            let _ = run(&["ip", "route", "del", "128.0.0.0/1", "dev", &self.tun_name]);
        }
        info!("full-tunnel routes removed (host route kept)");
    }

    /// Re-install full-tunnel split defaults and kill switch.
    pub fn reenable(&mut self, endpoint: SocketAddr) -> Result<()> {
        if self.redirect_all {
            run(&["ip", "route", "replace", "0.0.0.0/1", "dev", &self.tun_name])?;
            run(&[
                "ip",
                "route",
                "replace",
                "128.0.0.0/1",
                "dev",
                &self.tun_name,
            ])?;
            info!("full-tunnel routes reinstalled via {}", self.tun_name);
        }
        if let (Some(server_ip), Some(dev)) = (self.server_host, self.via_dev.clone()) {
            // Re-arm kill switch if it was taken down with teardown.
            if self.kill_switch.is_none() {
                // Only re-install if user had kill switch before — tracked by whether
                // kill_switch field was used. Callers pass whether KS desired via re-check:
                // we reinstall only when endpoint is V4 and we previously had via_dev.
                // Client passes explicit flag through reenable_kill_switch.
                let _ = (server_ip, dev, endpoint);
            }
        }
        Ok(())
    }

    pub fn reenable_with_ks(&mut self, endpoint: SocketAddr, want_kill_switch: bool) -> Result<()> {
        self.reenable(endpoint)?;
        if want_kill_switch && self.redirect_all && self.kill_switch.is_none() {
            if let (SocketAddr::V4(a), Some(dev)) = (endpoint, self.via_dev.clone()) {
                match KillSwitch::install(*a.ip(), a.port(), &self.tun_name, &dev) {
                    Ok(ks) => self.kill_switch = Some(ks),
                    Err(e) => warn!("kill switch re-install failed: {e}"),
                }
            }
        }
        Ok(())
    }

    fn teardown_all(&mut self) {
        if let Some(ks) = self.kill_switch.take() {
            drop(ks);
        }
        if let Some(v6) = self.ipv6.take() {
            drop(v6);
        }
        if let Some(dns) = self.dns.take() {
            drop(dns);
        }
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

// ── NAT (server) ───────────────────────────────────────────────────────────

/// Owns iptables MASQUERADE + ip_forward; restores on drop.
pub struct NatGuard {
    tun_cidr: String,
    egress: String,
    prev_forward: Option<Vec<u8>>,
    rule_added: bool,
}

impl NatGuard {
    pub fn setup(tun_cidr: &str) -> Result<Self> {
        let prev_forward = std::fs::read("/proc/sys/net/ipv4/ip_forward").ok();
        std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1").context("enable ip_forward")?;
        let egress = default_egress_dev().context("detect egress iface for MASQUERADE")?;

        let exists = run_status(&[
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
        ])
        .unwrap_or(false);

        let mut rule_added = false;
        if !exists {
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
            rule_added = true;
            info!(%tun_cidr, %egress, "NAT MASQUERADE installed");
        } else {
            info!(%tun_cidr, %egress, "NAT MASQUERADE already present");
        }

        Ok(Self {
            tun_cidr: tun_cidr.to_string(),
            egress,
            prev_forward,
            rule_added,
        })
    }
}

impl Drop for NatGuard {
    fn drop(&mut self) {
        if self.rule_added {
            let _ = run(&[
                "iptables",
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                &self.tun_cidr,
                "-o",
                &self.egress,
                "-j",
                "MASQUERADE",
            ]);
            info!("NAT MASQUERADE removed");
        }
        if let Some(ref prev) = self.prev_forward {
            let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", prev);
        }
    }
}

// ── Kill switch ────────────────────────────────────────────────────────────

struct KillSwitch {
    // chain owned
}

impl KillSwitch {
    fn install(
        server_ip: Ipv4Addr,
        server_port: u16,
        tun_name: &str,
        _egress: &str,
    ) -> Result<Self> {
        // Dedicated chain so teardown is reliable.
        let _ = run(&["iptables", "-N", KS_CHAIN]);
        let _ = run(&["iptables", "-F", KS_CHAIN]);

        // Allow loopback, tunnel iface, and UDP to the VPN server.
        run(&["iptables", "-A", KS_CHAIN, "-o", "lo", "-j", "RETURN"])?;
        run(&["iptables", "-A", KS_CHAIN, "-o", tun_name, "-j", "RETURN"])?;
        run(&[
            "iptables",
            "-A",
            KS_CHAIN,
            "-d",
            &server_ip.to_string(),
            "-p",
            "udp",
            "--dport",
            &server_port.to_string(),
            "-j",
            "RETURN",
        ])?;
        // Also allow established replies (DHCP/local) on any iface would need more rules;
        // fail closed for new clearnet egress.
        run(&[
            "iptables",
            "-A",
            KS_CHAIN,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "RETURN",
        ])
        .or_else(|_| {
            // Older systems without conntrack match.
            run(&[
                "iptables",
                "-A",
                KS_CHAIN,
                "-m",
                "state",
                "--state",
                "ESTABLISHED,RELATED",
                "-j",
                "RETURN",
            ])
        })
        .ok();
        run(&[
            "iptables",
            "-A",
            KS_CHAIN,
            "-j",
            "REJECT",
            "--reject-with",
            "icmp-net-unreachable",
        ])?;

        // Jump from OUTPUT if not already present.
        if !run_status(&["iptables", "-C", "OUTPUT", "-j", KS_CHAIN]).unwrap_or(false) {
            run(&["iptables", "-I", "OUTPUT", "1", "-j", KS_CHAIN])?;
        }
        Ok(Self {})
    }
}

impl Drop for KillSwitch {
    fn drop(&mut self) {
        let _ = run(&["iptables", "-D", "OUTPUT", "-j", KS_CHAIN]);
        let _ = run(&["iptables", "-F", KS_CHAIN]);
        let _ = run(&["iptables", "-X", KS_CHAIN]);
    }
}

// ── IPv6 blackhole ─────────────────────────────────────────────────────────

struct Ipv6Guard {
    active: bool,
}

impl Ipv6Guard {
    fn enable() -> Result<Self> {
        run(&["ip", "-6", "route", "replace", "blackhole", "::/1"])?;
        run(&["ip", "-6", "route", "replace", "blackhole", "8000::/1"])?;
        Ok(Self { active: true })
    }
}

impl Drop for Ipv6Guard {
    fn drop(&mut self) {
        if self.active {
            let _ = run(&["ip", "-6", "route", "del", "blackhole", "::/1"]);
            let _ = run(&["ip", "-6", "route", "del", "blackhole", "8000::/1"]);
        }
    }
}

// ── DNS ────────────────────────────────────────────────────────────────────

struct DnsGuard {
    restored: bool,
}

impl DnsGuard {
    fn install(servers: &[String]) -> Result<Self> {
        let resolv = Path::new("/etc/resolv.conf");
        if resolv.exists() {
            let content = std::fs::read(resolv).context("read resolv.conf")?;
            // Prefer our backup path; don't overwrite an existing backup from a crash.
            if !Path::new(RESOLV_BACKUP).exists() {
                std::fs::write(RESOLV_BACKUP, &content).context("backup resolv.conf")?;
            }
        }
        let mut body = String::from("# Managed by soulvpn — do not edit\n");
        for s in servers {
            body.push_str(&format!("nameserver {s}\n"));
        }
        std::fs::write(resolv, body).context("write resolv.conf")?;
        Ok(Self { restored: false })
    }

    fn restore(&mut self) {
        if self.restored {
            return;
        }
        self.restored = true;
        let backup = Path::new(RESOLV_BACKUP);
        if backup.exists() {
            if let Ok(content) = std::fs::read(backup) {
                let _ = std::fs::write("/etc/resolv.conf", content);
            }
            let _ = std::fs::remove_file(backup);
        }
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

// ── helpers ────────────────────────────────────────────────────────────────

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

fn run_status(args: &[&str]) -> Result<bool> {
    let status = Command::new(args[0])
        .args(&args[1..])
        .status()
        .with_context(|| format!("spawn {}", args[0]))?;
    Ok(status.success())
}
