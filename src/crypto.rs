//! Noise_IK session + packet framing + replay window.
//!
//! Wire format (data):
//!   [session_index:u32 LE][nonce:u64 LE][ciphertext…]
//!
//! Handshake:
//!   type=1 init     → [1][payload…]
//!   type=2 response → [2][session_index:u32 LE][payload…]

use anyhow::{bail, Context, Result};
use snow::params::NoiseParams;
use snow::{Builder, TransportState};
use std::sync::atomic::{AtomicU32, Ordering};

pub const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
pub const MAX_MESSAGE: usize = 65535;
/// Max ciphertext room for one IP packet + Noise tag.
pub const MAX_PAYLOAD: usize = 65519;
const REPLAY_WINDOW: u64 = 64;

static NEXT_SESSION_INDEX: AtomicU32 = AtomicU32::new(1);

fn params() -> NoiseParams {
    NOISE_PARAMS.parse().expect("static noise params")
}

pub fn generate_keypair() -> Result<([u8; 32], [u8; 32])> {
    let kp = Builder::new(params()).generate_keypair()?;
    let mut privk = [0u8; 32];
    let mut pubk = [0u8; 32];
    privk.copy_from_slice(&kp.private);
    pubk.copy_from_slice(&kp.public);
    Ok((privk, pubk))
}

pub fn public_from_private(private: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(*private);
    let public = PublicKey::from(&secret);
    *public.as_bytes()
}

/// Sliding 64-bit replay window keyed on Noise nonce.
#[derive(Debug, Default)]
pub struct ReplayWindow {
    highest: u64,
    bitmap: u64,
}

impl ReplayWindow {
    /// Returns true if `nonce` is fresh and records it.
    pub fn check_and_update(&mut self, nonce: u64) -> bool {
        if nonce > self.highest {
            let shift = nonce - self.highest;
            if shift >= REPLAY_WINDOW {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << shift) | 1;
            }
            self.highest = nonce;
            return true;
        }
        let offset = self.highest - nonce;
        if offset >= REPLAY_WINDOW {
            return false;
        }
        let bit = 1u64 << offset;
        if self.bitmap & bit != 0 {
            return false;
        }
        self.bitmap |= bit;
        true
    }
}

pub struct Session {
    pub index: u32,
    transport: TransportState,
    /// Local sending counter; kept in lockstep with snow.
    send_nonce: u64,
    replay: ReplayWindow,
}

impl Session {
    fn from_transport(index: u32, transport: TransportState) -> Self {
        Self {
            index,
            transport,
            send_nonce: 0,
            replay: ReplayWindow::default(),
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<usize> {
        if plaintext.len() > MAX_PAYLOAD {
            bail!("payload too large: {}", plaintext.len());
        }
        // Header: session index + nonce.
        if out.len() < 12 + plaintext.len() + 16 {
            bail!("encrypt output buffer too small");
        }
        let nonce = self.send_nonce;
        out[0..4].copy_from_slice(&self.index.to_le_bytes());
        out[4..12].copy_from_slice(&nonce.to_le_bytes());
        let n = self
            .transport
            .write_message(plaintext, &mut out[12..])
            .context("noise encrypt")?;
        self.send_nonce = self.send_nonce.wrapping_add(1);
        Ok(12 + n)
    }

    pub fn decrypt(&mut self, packet: &[u8], out: &mut [u8]) -> Result<usize> {
        if packet.len() < 12 + 16 {
            bail!("data packet too short");
        }
        let index = u32::from_le_bytes(packet[0..4].try_into().unwrap());
        if index != self.index {
            bail!("session index mismatch");
        }
        let nonce = u64::from_le_bytes(packet[4..12].try_into().unwrap());
        if !self.replay.check_and_update(nonce) {
            bail!("replayed or stale nonce {nonce}");
        }
        self.transport.set_receiving_nonce(nonce);
        self.transport
            .read_message(&packet[12..], out)
            .context("noise decrypt")
    }

    /// Remote static public key (available after IK handshake).
    pub fn remote_static(&self) -> Option<[u8; 32]> {
        self.transport.get_remote_static().map(|s| {
            let mut k = [0u8; 32];
            k.copy_from_slice(s);
            k
        })
    }
}

// ── Handshake helpers ──────────────────────────────────────────────────────

pub struct HandshakeInitiator {
    state: snow::HandshakeState,
}

impl HandshakeInitiator {
    pub fn new(private: &[u8; 32], server_public: &[u8; 32]) -> Result<Self> {
        let state = Builder::new(params())
            .local_private_key(private)
            .remote_public_key(server_public)
            .build_initiator()?;
        Ok(Self { state })
    }

    /// Produce type-1 init message.
    pub fn write_init(&mut self, out: &mut [u8]) -> Result<usize> {
        if out.is_empty() {
            bail!("empty buffer");
        }
        out[0] = 1;
        let n = self.state.write_message(&[], &mut out[1..])?;
        Ok(1 + n)
    }

    /// Consume type-2 response and enter transport mode.
    pub fn finish(mut self, msg: &[u8]) -> Result<Session> {
        if msg.first() != Some(&2) {
            bail!("expected handshake response (type 2)");
        }
        if msg.len() < 1 + 4 {
            bail!("handshake response too short");
        }
        let index = u32::from_le_bytes(msg[1..5].try_into().unwrap());
        let mut buf = [0u8; MAX_MESSAGE];
        self.state.read_message(&msg[5..], &mut buf)?;
        let transport = self.state.into_transport_mode()?;
        Ok(Session::from_transport(index, transport))
    }
}

pub struct HandshakeResponder {
    state: snow::HandshakeState,
}

impl HandshakeResponder {
    pub fn new(private: &[u8; 32]) -> Result<Self> {
        let state = Builder::new(params())
            .local_private_key(private)
            .build_responder()?;
        Ok(Self { state })
    }

    /// Consume type-1 init, produce type-2 response, enter transport.
    pub fn finish(mut self, msg: &[u8]) -> Result<(Session, Vec<u8>)> {
        if msg.first() != Some(&1) {
            bail!("expected handshake init (type 1)");
        }
        let mut buf = [0u8; MAX_MESSAGE];
        self.state.read_message(&msg[1..], &mut buf)?;
        let index = NEXT_SESSION_INDEX.fetch_add(1, Ordering::Relaxed);
        let mut response = vec![0u8; 1 + 4 + 128];
        response[0] = 2;
        response[1..5].copy_from_slice(&index.to_le_bytes());
        let n = self.state.write_message(&[], &mut response[5..])?;
        response.truncate(5 + n);
        let transport = self.state.into_transport_mode()?;
        Ok((Session::from_transport(index, transport), response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_roundtrip() {
        let (srv_priv, srv_pub) = generate_keypair().unwrap();
        let (cli_priv, _cli_pub) = generate_keypair().unwrap();

        let mut init = HandshakeInitiator::new(&cli_priv, &srv_pub).unwrap();
        let mut buf = [0u8; 256];
        let n = init.write_init(&mut buf).unwrap();
        let init_msg = buf[..n].to_vec();

        let resp = HandshakeResponder::new(&srv_priv).unwrap();
        let (mut srv_sess, response) = resp.finish(&init_msg).unwrap();

        let mut cli_sess = init.finish(&response).unwrap();
        assert_eq!(cli_sess.index, srv_sess.index);

        let plain = b"hello over noise";
        let mut enc = [0u8; 256];
        let en = cli_sess.encrypt(plain, &mut enc).unwrap();
        let mut dec = [0u8; 256];
        let dn = srv_sess.decrypt(&enc[..en], &mut dec).unwrap();
        assert_eq!(&dec[..dn], plain);

        // reverse direction
        let en = srv_sess.encrypt(b"pong", &mut enc).unwrap();
        let dn = cli_sess.decrypt(&enc[..en], &mut dec).unwrap();
        assert_eq!(&dec[..dn], b"pong");
    }

    #[test]
    fn replay_window_rejects_duplicates() {
        let mut w = ReplayWindow::default();
        assert!(w.check_and_update(0));
        assert!(!w.check_and_update(0));
        assert!(w.check_and_update(5));
        assert!(w.check_and_update(3));
        assert!(!w.check_and_update(3));
        assert!(w.check_and_update(70)); // far ahead
        assert!(!w.check_and_update(5)); // outside window
    }

    #[test]
    fn public_from_private_matches_noise() {
        let (privk, pubk) = generate_keypair().unwrap();
        assert_eq!(public_from_private(&privk), pubk);
    }
}
