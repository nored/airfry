//! FairPlay SAP handshake — faithful port of doubletake's
//! internal/airplay/fairplay.go.
//!
//! Performs the two-phase /fp-setup exchange (m1->m2, m3->m4) via the in-house
//! `fpemu` interpreter, builds the 72-byte ekey, and derives the AES stream key
//! and IV through PlayFair.

#![allow(dead_code)]

use anyhow::{anyhow, bail, Context, Result};
use rand::RngCore;
use sha2::{Digest, Sha512};

use crate::playfair::playfair_decrypt;
use crate::rtsp::Transport;

/// Fixed FairPlay m1 blob: "FPLY" 03 01 01 00 00 00 00 04 02 00 03 bb (16 bytes).
const FAIRPLAY_M1: [u8; 16] = [
    0x46, 0x50, 0x4c, 0x59, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x03, 0xbb,
];

/// FairPlay-derived stream encryption material handed to the mirror stage.
pub struct FairPlayKeys {
    /// Final 16-byte AES stream key (SHA-512(streamKey || sharedSecret)[..16]
    /// when a pair-verify shared secret is present, else the raw PlayFair key).
    pub stream_key: [u8; 16],
    /// Random 16-byte stream IV.
    pub iv: [u8; 16],
    /// 72-byte wrapped ekey the mirror SETUP body must carry.
    pub ekey: Vec<u8>,
    /// 16-byte raw PlayFair AES key (IKM, before the optional SHA-512 hash).
    pub aes_key: [u8; 16],
    /// The FPLY-wrapped m3 sent during the handshake (needed for SETUP context).
    pub m3: Vec<u8>,
}

/// Run the FairPlay SAP handshake against the receiver. `shared_secret` is the
/// pair-verify X25519 secret (empty when unavailable / raw path).
pub fn fair_play_setup(
    transport: &mut Transport,
    shared_secret: &[u8],
) -> Result<FairPlayKeys> {
    // Phase 1: send m1, receive m2.
    let m1 = FAIRPLAY_M1.to_vec();
    let resp = transport
        .request(
            "POST",
            "/fp-setup",
            "application/octet-stream",
            &m1,
            &[("X-Apple-ET", "32")],
        )
        .context("fp-setup phase 1 (m1)")?;
    let m2 = resp.body;
    if m2.len() < 12 {
        bail!("m2 response too short: {} bytes", m2.len());
    }

    // Phase 2: compute m3 via the fpemu interpreter.
    let m3_raw = fpemu::fp_sap_exchange_m3(&m2).map_err(|e| anyhow!("FPSAPExchange: {e}"))?;

    // Ensure FPLY framing.
    let m3 = if m3_raw.len() < 4 || &m3_raw[..4] != b"FPLY" {
        fply_wrap(&m3_raw, 0x03)
    } else {
        m3_raw
    };

    let resp = transport
        .request(
            "POST",
            "/fp-setup",
            "application/octet-stream",
            &m3,
            &[("X-Apple-ET", "32")],
        )
        .context("fp-setup phase 2 (m3)")?;
    let m4 = resp.body;
    if m4.len() < 12 {
        bail!("m4 response too short: {} bytes", m4.len());
    }
    let _m4_payload = fply_unwrap(&m4);

    // Random stream IV.
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    // Build ekey and derive the audio/stream encryption key via PlayFair.
    // Both sender and receiver call playfair_decrypt(m3, ekey) with identical
    // inputs (m3 sent during FP handshake; ekey sent in SETUP body).
    let ekey = build_ekey();
    let aes_key = playfair_decrypt(&m3, &ekey);

    // Hash with the pair-verify shared secret (ECDH X25519) when available:
    // receiver computes SHA-512(fairplay_decrypt(ekey) || ecdh_secret)[..16].
    let mut stream_key = aes_key;
    if !shared_secret.is_empty() {
        let mut h = Sha512::new();
        h.update(aes_key);
        h.update(shared_secret);
        let digest = h.finalize();
        stream_key.copy_from_slice(&digest[..16]);
    }

    Ok(FairPlayKeys {
        stream_key,
        iv,
        ekey: ekey.to_vec(),
        aes_key,
        m3,
    })
}

/// Construct the 72-byte ekey with the FPLY header format.
///
/// Layout:
///   [0:4]   "FPLY"
///   [4:8]   01 02 01 00
///   [8:12]  00 00 00 3c  (0x3c = 60 = remaining bytes)
///   [12:16] 00 00 00 00  (padding)
///   [16:32] chunk1 (16 random bytes)
///   [32:56] padding (24 zero bytes)
///   [56:72] chunk2 (16 random bytes)
pub fn build_ekey() -> [u8; 72] {
    let mut ekey = [0u8; 72];
    ekey[0..4].copy_from_slice(b"FPLY");
    ekey[4] = 0x01;
    ekey[5] = 0x02;
    ekey[6] = 0x01;
    ekey[7] = 0x00;
    ekey[8] = 0x00;
    ekey[9] = 0x00;
    ekey[10] = 0x00;
    ekey[11] = 0x3c;
    rand::thread_rng().fill_bytes(&mut ekey[16..32]);
    rand::thread_rng().fill_bytes(&mut ekey[56..72]);
    ekey
}

/// Add FPLY framing to raw SAP data. If already FPLY-prefixed, returns as-is.
pub fn fply_wrap(data: &[u8], msg_type: u8) -> Vec<u8> {
    if data.len() >= 4 && &data[..4] == b"FPLY" {
        return data.to_vec();
    }
    let mut header = Vec::with_capacity(12 + data.len());
    header.extend_from_slice(b"FPLY");
    header.push(0x03);
    header.push(0x01);
    header.push(msg_type);
    header.push(0x00);
    let len = data.len() as u32;
    header.push((len >> 24) as u8);
    header.push((len >> 16) as u8);
    header.push((len >> 8) as u8);
    header.push(len as u8);
    header.extend_from_slice(data);
    header
}

/// Strip FPLY framing, returning the payload. Returns input as-is if unframed.
pub fn fply_unwrap(data: &[u8]) -> Vec<u8> {
    if data.len() >= 12 && &data[..4] == b"FPLY" {
        return data[12..].to_vec();
    }
    data.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn m1_layout() {
        assert_eq!(FAIRPLAY_M1.len(), 16);
        assert_eq!(&FAIRPLAY_M1[..4], b"FPLY");
        assert_eq!(
            FAIRPLAY_M1.to_vec(),
            vec![
                0x46, 0x50, 0x4c, 0x59, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00,
                0x03, 0xbb
            ]
        );
    }

    #[test]
    fn ekey_layout() {
        let ekey = build_ekey();
        assert_eq!(ekey.len(), 72);
        assert_eq!(&ekey[0..4], b"FPLY");
        assert_eq!(&ekey[4..8], &[0x01, 0x02, 0x01, 0x00]);
        assert_eq!(&ekey[8..12], &[0x00, 0x00, 0x00, 0x3c]);
        assert_eq!(&ekey[12..16], &[0x00, 0x00, 0x00, 0x00]);
        // Padding region [32:56] is all zeros.
        assert!(ekey[32..56].iter().all(|&b| b == 0));
        // Two random chunks are (almost surely) not all-zero.
        assert!(ekey[16..32].iter().any(|&b| b != 0));
        assert!(ekey[56..72].iter().any(|&b| b != 0));
    }

    #[test]
    fn fply_wrap_roundtrip() {
        let payload = vec![0xaa, 0xbb, 0xcc];
        let wrapped = fply_wrap(&payload, 0x03);
        assert_eq!(&wrapped[..4], b"FPLY");
        assert_eq!(&wrapped[4..8], &[0x03, 0x01, 0x03, 0x00]);
        assert_eq!(&wrapped[8..12], &[0x00, 0x00, 0x00, 0x03]);
        assert_eq!(&wrapped[12..], &payload[..]);
        // Already-wrapped data is returned unchanged.
        assert_eq!(fply_wrap(&wrapped, 0x03), wrapped);
    }
}
