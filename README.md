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
- Explicit nonces + 64-bit sliding replay window (UDP-safe)
- Session index for multi-client + client roaming
- Full-tunnel client routes (`0.0.0.0/1` + `128.0.0.0/1`)
- Optional server-side NAT (`iptables` MASQUERADE + `ip_forward`)
- CLI: `genkey`, `pubkey`, `server`, `client`

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
# server
./target/release/soulvpn genkey > server.priv
./target/release/soulvpn pubkey < server.priv > server.pub

# client
./target/release/soulvpn genkey > client.priv
./target/release/soulvpn pubkey < client.priv > client.pub
```

`genkey` prints the **private** key on stdout and the **public** key on stderr.
`pubkey` derives the public key from a private key.

### 2. Config

See `examples/server.toml` and `examples/client.toml`. Minimal:

**server.toml**
```toml
listen = "0.0.0.0:51820"
private_key = "<server private>"
address = "10.66.66.1/24"
mtu = 1400
nat = true

[[peers]]
public_key = "<client public>"
allowed_ip = "10.66.66.2"
```

**client.toml**
```toml
endpoint = "YOUR.SERVER.IP:51820"
private_key = "<client private>"
server_public_key = "<server public>"
address = "10.66.66.2/24"
mtu = 1400
redirect_all = true
```

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
3. Tears both down on Ctrl-C / process exit

With `nat = true` the server enables `ip_forward` and adds
`iptables -t nat -A POSTROUTING -s <tunnel-subnet> -o <egress> -j MASQUERADE`.

## DNS

This binary does **not** rewrite `/etc/resolv.conf`. Point DNS at a resolver
reachable through the tunnel (e.g. `10.66.66.1` if you run one on the server,
or a public resolver) yourself, or use `resolvectl` / NetworkManager.

## Protocol sketch

| Field | Size | Notes |
|-------|------|-------|
| Handshake init | `1 \|\| Noise` | type byte `1` |
| Handshake response | `1 \|\| u32 LE session \|\| Noise` | type byte `2` |
| Data | `u32 LE session \|\| u64 LE nonce \|\| ciphertext` | |

After IK, the server maps the client's static public key → configured
`allowed_ip` and assigns a session index. Data packets carry that index so the
server can look up the session without relying on the UDP source address
(roaming works).

## Security notes

- Treat this as a **personal** VPN, not a audited product.
- Private keys are raw 32-byte X25519 in standard base64; protect them.
- No rekey yet — restart the client periodically on long-lived sessions.
- No IPv6 tunnel path yet.
- Do not expose the UDP port without knowing who holds the configured peer keys.

## License

MIT
