# soulvpn

System-wide VPN written in Rust. Encrypts traffic with **Noise_IK**
(`Noise_IK_25519_ChaChaPoly_BLAKE2s`) over UDP and pumps packets through a
Linux **TUN** device so all IPv4 internet traffic can be routed through the
tunnel.

```
┌────────────┐   UDP + Noise_IK   ┌────────────┐
│  client    │ ─────────────────► │  server    │
│  TUN eth0  │ ◄───────────────── │  TUN + NAT │
└────────────┘                    └────────────┘
      │                                 │
  0.0.0.0/1                         MASQUERADE
  128.0.0.0/1                       → internet
```

## Features

- Noise_IK handshake (mutual auth; client knows server static key)
- ChaCha20-Poly1305 transport encryption
- Explicit nonces + 1024-bit sliding replay window (UDP-safe)
- Random session index for multi-client + client roaming
- Inner-packet source IP policy (anti-spoof) on the server
- Full-tunnel client routes (`0.0.0.0/1` + `128.0.0.0/1`)
- Optional **kill switch**, **IPv6 blackhole**, and **DNS rewrite**
- Keepalive, timed rekey, and auto-reconnect on the client
- Optional server-side NAT (`iptables` MASQUERADE + `ip_forward`, torn down on exit)
- Handshake rate limiting + idle session expiry on the server
- Control plane: `status` / `on` / `off` / live `monitor` TUI (default mode `0600`)
- CLI: `genkey`, `pubkey`, `server`, `client`, `status`, `on`, `off`, `monitor`

## Requirements

- Linux (uses `ip` and optionally `iptables`)
- Root or `CAP_NET_ADMIN` to create TUN / change routes
- Rust 1.75+ to build

## Build

```bash
cargo build --release
# binary: target/release/soulvpn
```

## Quick start

### 1. Keys

```bash
# Write 0600 private + public files (recommended)
sudo mkdir -p /etc/soulvpn
sudo ./target/release/soulvpn genkey --write-dir /etc/soulvpn --name server
sudo ./target/release/soulvpn genkey --write-dir /etc/soulvpn --name client

# Or script-friendly (private on stdout, public on stderr):
./target/release/soulvpn genkey > server.priv
./target/release/soulvpn pubkey < server.priv > server.pub
chmod 600 server.priv
```

### 2. Config

See `examples/server.toml` and `examples/client.toml`. Minimal:

**server.toml**
```toml
listen = "0.0.0.0:51820"
private_key_file = "/etc/soulvpn/server.priv"
address = "10.66.66.1/24"
mtu = 1400
nat = true

[[peers]]
public_key = "<client public base64>"
allowed_ip = "10.66.66.2"
```

**client.toml**
```toml
endpoint = "YOUR.SERVER.IP:51820"
private_key_file = "/etc/soulvpn/client.priv"
server_public_key_file = "/etc/soulvpn/server.pub"
address = "10.66.66.2/24"
mtu = 1400
redirect_all = true
kill_switch = true
disable_ipv6 = true
# dns = ["1.1.1.1"]
```

Key material can be inline (`private_key = "..."`) or files
(`private_key_file`). Key **files** must be mode `0600` (or tighter);
world/group-readable key files are refused.

### 3. Run

```bash
# on the VPS / gateway
sudo ./target/release/soulvpn server -c server.toml

# on your laptop
sudo ./target/release/soulvpn client -c client.toml
```

With `redirect_all = true` the client:

1. Pins a host route to the VPN server via the original default gateway
2. Installs `0.0.0.0/1` and `128.0.0.0/1` via the TUN (covers all IPv4)
3. Optionally installs kill switch / IPv6 blackhole / DNS
4. Tears everything down on Ctrl-C / process exit

With `nat = true` the server enables `ip_forward` and adds a MASQUERADE rule
(idempotent; removed on clean shutdown).

### systemd

Example units live in `examples/`:

```bash
sudo cp target/release/soulvpn /usr/local/bin/
sudo cp examples/tmpfiles-soulvpn.conf /etc/tmpfiles.d/soulvpn.conf
sudo systemd-tmpfiles --create
sudo cp examples/soulvpn-server.service /etc/systemd/system/   # or client
sudo systemctl daemon-reload
sudo systemctl enable --now soulvpn-server
```

## Control plane & monitor

While `server` / `client` is running it listens on a Unix socket
(default `/run/soulvpn/control.sock`, override with `--control-socket` or
`SOULVPN_CONTROL_SOCKET`). **Default mode is `0600`** (owner only).

Override with config `control_mode = "0660"` or env `SOULVPN_CONTROL_MODE=0660`
if a shared group should monitor the daemon.

```bash
# one-shot
soulvpn status
soulvpn status --json
soulvpn off          # stop tunneling (client drops full-tunnel routes + kill switch)
soulvpn on           # resume tunneling

# live TUI — rates, counters, sparkline; keys: space toggle · o on · f off · q quit
soulvpn monitor
```

| Op | Client effect | Server effect |
|----|---------------|---------------|
| `off` | remove full-tunnel routes + kill switch; drop data-plane packets | drop data-plane packets (handshakes still accepted) |
| `on`  | reinstall routes (+ kill switch if configured); resume encrypt/decrypt | resume encrypt/decrypt |

Process stays up either way — only the data plane is gated.
**`off` is an explicit privacy opt-out** (clearnet resumes). For fail-closed
while the tunnel is *enabled*, use `kill_switch = true`.

## DNS

Optional client config:

```toml
dns = ["1.1.1.1", "9.9.9.9"]
```

Rewrites `/etc/resolv.conf` (backup at `/etc/resolv.conf.soulvpn.bak`) and
restores on exit. Point DNS at a resolver reachable through the tunnel.

## Protocol sketch

| Field | Size | Notes |
|-------|------|-------|
| Handshake init | `1 \|\| Noise` | type byte `1` |
| Handshake response | `1 \|\| u32 LE session \|\| Noise` | type byte `2` |
| Data | `u32 LE session \|\| u64 LE nonce \|\| ciphertext` | empty plaintext = keepalive |

After IK, the server maps the client's static public key → configured
`allowed_ip` and assigns a **random** session index. Data packets carry that
index so the server can look up the session without relying on the UDP source
address (roaming works). The UDP endpoint is updated **only after successful
AEAD decrypt**. Inner IPv4 source must equal the peer's `allowed_ip`.

## Security notes

- Treat this as a **personal** VPN, not a formally audited product.
- Private keys are raw 32-byte X25519 in standard base64; protect them (`0600` files).
- Control socket defaults to owner-only; do not set `0666` on shared hosts.
- Timed rekey (default 120s) + reconnect on silence (default 45s).
- No IPv6 *tunnel* path yet — client can blackhole IPv6 (`disable_ipv6 = true`).
- Do not expose the UDP port without knowing who holds the configured peer keys.
- Kill switch blocks new clearnet egress while the tunnel is enabled; `soulvpn off` removes it.

## License

MIT
