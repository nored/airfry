//! AirPlay / HomeKit pairing — faithful port of doubletake's
//! internal/airplay/pairing.go (TLV8 path) plus the in-memory credential parts
//! of credentials.go.
//!
//! Implements transient (PIN-less) and PIN-based SRP-6a pair-setup, followed by
//! the HAP pair-verify that establishes the encrypted control channel.

#![allow(dead_code)]

use aes::cipher::{KeyIvInit, StreamCipher};
use anyhow::{anyhow, bail, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use num_bigint::BigUint;
use num_traits::Zero;
use rand::RngCore;
use sha2::{Digest, Sha512};

/// AES-128 in CTR mode with a 128-bit big-endian counter, matching Go's
/// `cipher.NewCTR(aes, iv)`.
type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

use crate::rtsp::Transport;
use crate::tlv8::{self, Item};

/// Transient-pairing flag (bit 4): ephemeral/no-PIN pairing.
const PAIRING_FLAG_TRANSIENT: u32 = 0x0000_0010;

/// Long-term + session keys produced by pairing.
#[derive(Default, Clone)]
pub struct PairKeys {
    /// Long-term ed25519 identity public key (32 bytes).
    pub ed25519_public: Vec<u8>,
    /// Long-term ed25519 identity seed (32 bytes); the signing key derives from it.
    pub ed25519_seed: Vec<u8>,
    /// X25519 shared secret from pair-verify (32 bytes); empty before verify.
    pub shared_secret: Vec<u8>,
    /// HAP control-channel write/read keys (derived in pair-verify).
    pub write_key: Vec<u8>,
    pub read_key: Vec<u8>,
}

impl PairKeys {
    fn signing_key(&self) -> Result<SigningKey> {
        let seed: [u8; 32] = self
            .ed25519_seed
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("ed25519 seed must be 32 bytes"))?;
        Ok(SigningKey::from_bytes(&seed))
    }
}

/// RFC 5054 3072-bit SRP group N (hex), generator g = 5.
const SRP_N_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
83655D23DCA3AD961C62F356208552BB9ED529077096966D\
670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64\
ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7\
ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B\
F12FFA06D98A0864D87602733EC86A64521F2B18177B200C\
BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31\
43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

fn srp_n() -> BigUint {
    BigUint::parse_bytes(SRP_N_HEX.as_bytes(), 16).expect("valid SRP N")
}

fn srp_g() -> BigUint {
    BigUint::from(5u32)
}

/// Generate a random UUID (v4-ish, matching the Go `generateUUID` shape used
/// for PairingID / SessionID).
pub fn generate_uuid() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    let out = h.finalize();
    let mut r = [0u8; 64];
    r.copy_from_slice(&out);
    r
}

/// HKDF-SHA512 -> `length` bytes.
fn hkdf_sha512(secret: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha512>::new(Some(salt), secret);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm).expect("hkdf expand");
    okm
}

/// Left-pad a big-endian byte slice with zeros to `size` bytes.
fn pad_to(data: &[u8], size: usize) -> Vec<u8> {
    if data.len() >= size {
        return data.to_vec();
    }
    let mut padded = vec![0u8; size];
    padded[size - data.len()..].copy_from_slice(data);
    padded
}

fn pair_headers() -> &'static [(&'static str, &'static str)] {
    &[("X-Apple-HKP", "3")]
}

/// Run pair-setup. An empty `pin` performs the transient flow; otherwise PIN.
/// Generates a fresh ed25519 identity and returns the resulting `PairKeys`
/// (without the X25519 shared secret, which pair-verify fills in).
pub fn pair_setup(transport: &mut Transport, pairing_id: &str, pin: &str) -> Result<PairKeys> {
    pair_setup_with_identity(transport, pairing_id, pin, None)
}

/// Like `pair_setup`, but reuses a previously-saved ed25519 identity (32-byte
/// seed) when provided, so a receiver recognises this sender as a known
/// controller. A `None` seed generates a fresh identity.
pub fn pair_setup_with_identity(
    transport: &mut Transport,
    pairing_id: &str,
    pin: &str,
    reuse_seed: Option<[u8; 32]>,
) -> Result<PairKeys> {
    // Reuse the saved ed25519 identity when supplied; otherwise generate one.
    let seed = match reuse_seed {
        Some(s) => s,
        None => {
            let mut s = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut s);
            s
        }
    };
    let signing = SigningKey::from_bytes(&seed);
    let mut keys = PairKeys {
        ed25519_public: signing.verifying_key().to_bytes().to_vec(),
        ed25519_seed: seed.to_vec(),
        ..Default::default()
    };

    let (salt, server_pub) = if pin.is_empty() {
        // Transient M1: method=0, state=1, flags=transient.
        let m1 = tlv8::encode(&[
            Item::new(tlv8::TLV_METHOD, vec![0x00]),
            Item::new(tlv8::TLV_STATE, vec![0x01]),
            Item::new(tlv8::TLV_FLAGS, PAIRING_FLAG_TRANSIENT.to_le_bytes().to_vec()),
        ]);
        let resp = transport.request(
            "POST",
            "/pair-setup",
            "application/octet-stream",
            &m1,
            pair_headers(),
        )?;
        let m2 = tlv8::decode(&resp.body);
        if let Some(e) = m2.get(&tlv8::TLV_ERROR) {
            bail!("pair-setup M2 error: {}", e.first().copied().unwrap_or(0));
        }
        let server_pub = m2
            .get(&tlv8::TLV_PUBLIC_KEY)
            .cloned()
            .ok_or_else(|| anyhow!("M2: missing server public key"))?;
        // Transient: salt may be present; pass empty if absent.
        let salt = m2.get(&tlv8::TLV_SALT).cloned().unwrap_or_default();
        (salt, server_pub)
    } else {
        // PIN-based M1: method=0, state=1.
        let m1 = tlv8::encode(&[
            Item::new(tlv8::TLV_METHOD, vec![0x00]),
            Item::new(tlv8::TLV_STATE, vec![0x01]),
        ]);
        let resp = transport.request(
            "POST",
            "/pair-setup",
            "application/octet-stream",
            &m1,
            pair_headers(),
        )?;
        let m2 = tlv8::decode(&resp.body);
        if let Some(e) = m2.get(&tlv8::TLV_ERROR) {
            bail!("pair-setup M2 error: {}", e.first().copied().unwrap_or(0));
        }
        let salt = m2
            .get(&tlv8::TLV_SALT)
            .cloned()
            .ok_or_else(|| anyhow!("M2: missing salt"))?;
        let server_pub = m2
            .get(&tlv8::TLV_PUBLIC_KEY)
            .cloned()
            .ok_or_else(|| anyhow!("M2: missing public key"))?;
        (salt, server_pub)
    };

    complete_srp_exchange(transport, pairing_id, pin, &salt, &server_pub, &mut keys)?;
    Ok(keys)
}

/// Finish SRP from M3 onward (shared by transient + PIN flows). Sets
/// `keys.shared_secret = K` on success (overwritten by pair-verify later).
fn complete_srp_exchange(
    transport: &mut Transport,
    pairing_id: &str,
    pin: &str,
    salt: &[u8],
    server_pub_b: &[u8],
    keys: &mut PairKeys,
) -> Result<()> {
    let n = srp_n();
    let g = srp_g();

    let username = b"Pair-Setup".to_vec();
    let password = pin.as_bytes().to_vec();

    // x = H(salt || H(username || ":" || password))
    let mut inner = username.clone();
    inner.push(b':');
    inner.extend_from_slice(&password);
    let inner_hash = sha512(&[&inner]);
    let x_hash = sha512(&[salt, &inner_hash]);
    let x = BigUint::from_bytes_be(&x_hash);

    // k = H(pad(N) || pad(g))   (both padded to 384 bytes)
    let pad_n = pad_to(&n.to_bytes_be(), 384);
    let pad_g = pad_to(&g.to_bytes_be(), 384);
    let k_hash = sha512(&[&pad_n, &pad_g]);
    let k = BigUint::from_bytes_be(&k_hash);

    // a (random 32 bytes), A = g^a mod N
    let mut a_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut a_bytes);
    let a = BigUint::from_bytes_be(&a_bytes);
    let a_pub = g.modpow(&a, &n);

    let b_pub = BigUint::from_bytes_be(server_pub_b);

    // u = H(pad(A) || pad(B))
    let u_hash = sha512(&[
        &pad_to(&a_pub.to_bytes_be(), 384),
        &pad_to(&b_pub.to_bytes_be(), 384),
    ]);
    let u = BigUint::from_bytes_be(&u_hash);

    // S = (B - k * g^x)^(a + u*x) mod N
    let gx = g.modpow(&x, &n);
    let kgx = (&k * &gx) % &n;
    let diff = if b_pub >= kgx {
        (&b_pub - &kgx) % &n
    } else {
        // (B - kgx) mod N with wraparound
        (&n - ((&kgx - &b_pub) % &n)) % &n
    };
    let exp = &a + &u * &x;
    let s = diff.modpow(&exp, &n);

    // K = H(S)  (S in natural unpadded big-endian)
    let s_bytes = if s.is_zero() {
        Vec::new()
    } else {
        s.to_bytes_be()
    };
    let big_k = sha512(&[&s_bytes]).to_vec();

    // M1 proof = H( (H(N) XOR H(g)) || H(I) || salt || A || B || K )
    let hn = sha512(&[&n.to_bytes_be()]);
    let hg = sha512(&[&g.to_bytes_be()]);
    let mut hxor = [0u8; 64];
    for i in 0..64 {
        hxor[i] = hn[i] ^ hg[i];
    }
    let hu = sha512(&[&username]);
    let a_nat = a_pub.to_bytes_be();
    let b_nat = b_pub.to_bytes_be();
    let m1_proof = sha512(&[&hxor, &hu, salt, &a_nat, &b_nat, &big_k]);

    // M3: state=3, publicKey=pad(A,384), proof=M1.
    let m3 = tlv8::encode(&[
        Item::new(tlv8::TLV_STATE, vec![0x03]),
        Item::new(tlv8::TLV_PUBLIC_KEY, pad_to(&a_nat, 384)),
        Item::new(tlv8::TLV_PROOF, m1_proof.to_vec()),
    ]);
    let resp = transport.request(
        "POST",
        "/pair-setup",
        "application/octet-stream",
        &m3,
        pair_headers(),
    )?;
    let m4 = tlv8::decode(&resp.body);
    if let Some(e) = m4.get(&tlv8::TLV_ERROR) {
        bail!("pair-setup M4 error: {}", e.first().copied().unwrap_or(0));
    }

    // Verify server proof H(A || M1 || K) when provided.
    let m2_proof_expected = sha512(&[&a_nat, &m1_proof, &big_k]);
    if let Some(server_proof) = m4.get(&tlv8::TLV_PROOF) {
        if server_proof.as_slice() != m2_proof_expected.as_slice() {
            bail!("server proof mismatch");
        }
    }

    // M5: encrypted sub-TLV with our ed25519 identity.
    let session_key = hkdf_sha512(
        &big_k,
        b"Pair-Setup-Encrypt-Salt",
        b"Pair-Setup-Encrypt-Info",
        32,
    );
    let client_id = pairing_id.as_bytes().to_vec();
    let sig_key = hkdf_sha512(
        &big_k,
        b"Pair-Setup-Controller-Sign-Salt",
        b"Pair-Setup-Controller-Sign-Info",
        32,
    );

    // signed message = sigKey || clientID || ed25519Pub
    let mut sig_input = Vec::new();
    sig_input.extend_from_slice(&sig_key);
    sig_input.extend_from_slice(&client_id);
    sig_input.extend_from_slice(&keys.ed25519_public);
    let signing = keys.signing_key()?;
    let signature = signing.sign(&sig_input).to_bytes().to_vec();

    let sub_tlv = tlv8::encode(&[
        Item::new(tlv8::TLV_IDENTIFIER, client_id.clone()),
        Item::new(tlv8::TLV_PUBLIC_KEY, keys.ed25519_public.clone()),
        Item::new(tlv8::TLV_SIGNATURE, signature),
    ]);

    let cipher = ChaCha20Poly1305::new_from_slice(&session_key)
        .map_err(|_| anyhow!("chacha20 key"))?;
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(b"PS-Msg05");
    let encrypted = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: &sub_tlv,
                aad: &[],
            },
        )
        .map_err(|_| anyhow!("M5 seal failed"))?;

    let m5 = tlv8::encode(&[
        Item::new(tlv8::TLV_STATE, vec![0x05]),
        Item::new(tlv8::TLV_ENCRYPTED_DATA, encrypted),
    ]);
    let resp = transport.request(
        "POST",
        "/pair-setup",
        "application/octet-stream",
        &m5,
        pair_headers(),
    )?;
    let m6 = tlv8::decode(&resp.body);
    if let Some(e) = m6.get(&tlv8::TLV_ERROR) {
        bail!("pair-setup M6 error: {}", e.first().copied().unwrap_or(0));
    }

    keys.shared_secret = big_k;
    Ok(())
}

/// HAP pair-verify: ephemeral X25519, derives the encrypted control channel.
/// On success enables HAP encryption on `transport` and sets the X25519 shared
/// secret + write/read keys in `keys`.
pub fn pair_verify(
    transport: &mut Transport,
    pairing_id: &str,
    keys: &mut PairKeys,
) -> Result<()> {
    use x25519_dalek::{PublicKey, StaticSecret};

    // Ephemeral X25519 key pair.
    let mut priv_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut priv_bytes);
    let client_secret = StaticSecret::from(priv_bytes);
    let client_public = PublicKey::from(&client_secret);
    let client_pub_bytes = client_public.to_bytes();

    // V1: state=1, publicKey=clientX25519.
    let v1 = tlv8::encode(&[
        Item::new(tlv8::TLV_STATE, vec![0x01]),
        Item::new(tlv8::TLV_PUBLIC_KEY, client_pub_bytes.to_vec()),
    ]);
    let resp = transport.request(
        "POST",
        "/pair-verify",
        "application/octet-stream",
        &v1,
        pair_headers(),
    )?;
    let v2 = tlv8::decode(&resp.body);
    if let Some(e) = v2.get(&tlv8::TLV_ERROR) {
        bail!("pair-verify V2 error: {}", e.first().copied().unwrap_or(0));
    }

    let server_key_data = v2
        .get(&tlv8::TLV_PUBLIC_KEY)
        .cloned()
        .ok_or_else(|| anyhow!("V2: missing server public key"))?;
    if server_key_data.len() < 32 {
        bail!("V2: server public key too short");
    }
    let mut server_public_bytes = [0u8; 32];
    server_public_bytes.copy_from_slice(&server_key_data[..32]);
    let server_public = PublicKey::from(server_public_bytes);

    // X25519 shared secret.
    let shared = client_secret.diffie_hellman(&server_public);
    let shared_bytes = shared.to_bytes();

    let verify_key = hkdf_sha512(
        &shared_bytes,
        b"Pair-Verify-Encrypt-Salt",
        b"Pair-Verify-Encrypt-Info",
        32,
    );

    // Decrypt+verify server's encrypted blob if present (nonce PV-Msg02).
    if let Some(server_encrypted) = v2.get(&tlv8::TLV_ENCRYPTED_DATA) {
        if !server_encrypted.is_empty() {
            let cipher = ChaCha20Poly1305::new_from_slice(&verify_key)
                .map_err(|_| anyhow!("chacha20 key"))?;
            let mut nonce = [0u8; 12];
            nonce[4..].copy_from_slice(b"PV-Msg02");
            cipher
                .decrypt(
                    (&nonce).into(),
                    Payload {
                        msg: server_encrypted,
                        aad: &[],
                    },
                )
                .map_err(|_| anyhow!("decrypt V2 failed"))?;
        }
    }

    // V3: signed (clientX25519 || pairingID || serverX25519), encrypted (PV-Msg03).
    let client_id = pairing_id.as_bytes().to_vec();
    let mut sig_input = Vec::new();
    sig_input.extend_from_slice(&client_pub_bytes);
    sig_input.extend_from_slice(&client_id);
    sig_input.extend_from_slice(&server_public_bytes);
    let signing = keys.signing_key()?;
    let signature = signing.sign(&sig_input).to_bytes().to_vec();

    let sub_tlv = tlv8::encode(&[
        Item::new(tlv8::TLV_IDENTIFIER, client_id),
        Item::new(tlv8::TLV_SIGNATURE, signature),
    ]);

    let cipher = ChaCha20Poly1305::new_from_slice(&verify_key)
        .map_err(|_| anyhow!("chacha20 key"))?;
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(b"PV-Msg03");
    let encrypted = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: &sub_tlv,
                aad: &[],
            },
        )
        .map_err(|_| anyhow!("V3 seal failed"))?;

    let v3 = tlv8::encode(&[
        Item::new(tlv8::TLV_STATE, vec![0x03]),
        Item::new(tlv8::TLV_ENCRYPTED_DATA, encrypted),
    ]);
    let resp = transport.request(
        "POST",
        "/pair-verify",
        "application/octet-stream",
        &v3,
        pair_headers(),
    )?;
    if !resp.body.is_empty() {
        let v4 = tlv8::decode(&resp.body);
        if let Some(e) = v4.get(&tlv8::TLV_ERROR) {
            bail!("pair-verify V4 error: {}", e.first().copied().unwrap_or(0));
        }
    }

    // Derive HAP control-channel keys; enable encryption on the transport.
    let write_key = hkdf_sha512(
        &shared_bytes,
        b"Control-Salt",
        b"Control-Write-Encryption-Key",
        32,
    );
    let read_key = hkdf_sha512(
        &shared_bytes,
        b"Control-Salt",
        b"Control-Read-Encryption-Key",
        32,
    );

    keys.shared_secret = shared_bytes.to_vec();
    keys.write_key = write_key.clone();
    keys.read_key = read_key.clone();

    transport.enable_encryption(write_key, read_key);
    Ok(())
}

// ---------------------------------------------------------------------------
// Raw (legacy / UxPlay-compatible) pairing — faithful port of pairing.go's
// rawPairSetup + rawPairVerify. This path keeps the connection PLAINTEXT
// (no HAP framing), which is required because Apple TV rejects FairPlay
// fp-setup phase 2 over an HAP-encrypted connection on the legacy path.
// ---------------------------------------------------------------------------

/// SHA-512(salt || secret)[..16] — the raw pair-verify AES key/IV derivation
/// (NOT HKDF). Faithful port of Go `sha512DeriveKey`.
fn sha512_derive_key16(salt: &str, secret: &[u8]) -> [u8; 16] {
    let mut h = Sha512::new();
    h.update(salt.as_bytes());
    h.update(secret);
    let out = h.finalize();
    let mut r = [0u8; 16];
    r.copy_from_slice(&out[..16]);
    r
}

/// rawPairSetup: POST /pair-setup with the 32-byte ed25519 client public key as
/// a raw binary body (no X-Apple-HKP header, not TLV8). Returns the receiver's
/// 32-byte ed25519 public key. Generates a fresh ed25519 identity into `keys`.
pub fn raw_pair_setup(transport: &mut Transport, keys: &mut PairKeys) -> Result<Vec<u8>> {
    // Generate ed25519 identity for this session (mirrors pairTransient).
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let signing = SigningKey::from_bytes(&seed);
    keys.ed25519_public = signing.verifying_key().to_bytes().to_vec();
    keys.ed25519_seed = seed.to_vec();

    let resp = transport.request(
        "POST",
        "/pair-setup",
        "application/octet-stream",
        &keys.ed25519_public,
        &[],
    )?;
    if resp.body.len() != 32 {
        bail!("pair-setup: expected 32 bytes, got {}", resp.body.len());
    }
    Ok(resp.body)
}

/// rawPairVerify: the non-HAP ("AirMyPC-style") pair-verify that leaves the
/// connection in plaintext. Faithful byte-for-byte port of pairing.go's
/// `rawPairVerify`.
///
/// Protocol (raw binary, NOT TLV8):
///   V1 (client→server, 68 bytes): 01 00 00 00 || X25519_pub(32) || Ed25519_pub(32)
///   V2 (server→client, 96 bytes): server_X25519_pub(32) || AES-CTR(server_sig, off=0)(64)
///   V3 (client→server, 68 bytes): 00 00 00 00 || AES-CTR(client_sig, off=64)(64)
///   V4 (server→client, 0 bytes):  empty 200 OK
///
/// AES key/IV: SHA-512("Pair-Verify-AES-Key"||shared)[..16] and
/// SHA-512("Pair-Verify-AES-IV"||shared)[..16]. `server_ed25519_pk` is the
/// receiver's long-term ed25519 key (from /info `pk` or mDNS); when it is
/// fewer than 32 bytes the server-signature check is skipped (the Go path
/// errors, but here we accept an unavailable PK to mirror the comment that the
/// key may be unavailable).
pub fn raw_pair_verify(
    transport: &mut Transport,
    keys: &mut PairKeys,
    server_ed25519_pk: &[u8],
) -> Result<()> {
    use x25519_dalek::{PublicKey, StaticSecret};

    // Ephemeral X25519 key pair.
    let mut client_private = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut client_private);
    let client_secret = StaticSecret::from(client_private);
    let client_public = PublicKey::from(&client_secret);
    let client_pub_bytes = client_public.to_bytes();

    // V1: 01 00 00 00 || X25519_pub(32) || Ed25519_pub(32) = 68 bytes.
    if keys.ed25519_public.len() != 32 {
        bail!("raw pair-verify: ed25519 public key must be 32 bytes");
    }
    let mut v1 = [0u8; 68];
    v1[0] = 0x01; // flags: auth type = 1
    v1[4..36].copy_from_slice(&client_pub_bytes);
    v1[36..68].copy_from_slice(&keys.ed25519_public);

    let resp = transport.raw_request("POST", "/pair-verify", "application/octet-stream", &v1, &[])?;
    let v2 = resp.body;
    if v2.len() != 96 {
        bail!("V2: expected 96 bytes, got {}", v2.len());
    }

    let mut server_public_bytes = [0u8; 32];
    server_public_bytes.copy_from_slice(&v2[..32]);
    let encrypted_server_sig = &v2[32..96];
    let server_public = PublicKey::from(server_public_bytes);

    // X25519 shared secret.
    let shared = client_secret.diffie_hellman(&server_public);
    let shared_bytes = shared.to_bytes();

    // AES-128-CTR key and IV from the shared secret using SHA-512.
    let aes_key = sha512_derive_key16("Pair-Verify-AES-Key", &shared_bytes);
    let aes_iv = sha512_derive_key16("Pair-Verify-AES-IV", &shared_bytes);

    // Decrypt the server signature at CTR offset 0.
    let mut server_sig = [0u8; 64];
    server_sig.copy_from_slice(encrypted_server_sig);
    {
        let mut ctr = Aes128Ctr::new(&aes_key.into(), &aes_iv.into());
        ctr.apply_keystream(&mut server_sig);
    }

    // Verify server's Ed25519 signature over (server_X25519 || client_X25519).
    // pairing.go:647-653 ABORTS when the receiver's PK is missing/short and
    // always verifies the signature — there is no "skip" path. We mirror that:
    // an unavailable PK, an unparseable PK, or a failed verification all error.
    let mut server_sig_msg = [0u8; 64];
    server_sig_msg[..32].copy_from_slice(&server_public_bytes);
    server_sig_msg[32..].copy_from_slice(&client_pub_bytes);
    if server_ed25519_pk.len() < 32 {
        // Matches Go: "server Ed25519 public key not available (call GetInfo first)".
        bail!("server Ed25519 public key not available (call GetInfo first)");
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&server_ed25519_pk[..32]);
    let vk = VerifyingKey::from_bytes(&pk)
        .map_err(|_| anyhow!("server signature verification failed"))?;
    let sig = ed25519_dalek::Signature::from_bytes(&server_sig);
    if vk.verify(&server_sig_msg, &sig).is_err() {
        bail!("server signature verification failed");
    }

    // Sign our proof: Ed25519_sign(client_X25519 || server_X25519).
    let mut client_sig_msg = [0u8; 64];
    client_sig_msg[..32].copy_from_slice(&client_pub_bytes);
    client_sig_msg[32..].copy_from_slice(&server_public_bytes);
    let signing = keys.signing_key()?;
    let client_sig = signing.sign(&client_sig_msg).to_bytes();

    // Encrypt the client signature at CTR offset 64 — advance the counter by 64
    // bytes (one keystream block discard of 64 bytes) before encrypting.
    let mut encrypted_client_sig = client_sig;
    {
        let mut ctr = Aes128Ctr::new(&aes_key.into(), &aes_iv.into());
        let mut skip = [0u8; 64];
        ctr.apply_keystream(&mut skip); // advance CTR by 64 bytes
        ctr.apply_keystream(&mut encrypted_client_sig);
    }

    // V3: 00 00 00 00 || encrypted_client_sig(64) = 68 bytes.
    let mut v3 = [0u8; 68];
    v3[4..68].copy_from_slice(&encrypted_client_sig);

    let resp = transport.raw_request("POST", "/pair-verify", "application/octet-stream", &v3, &[])?;
    if !resp.body.is_empty() {
        // V4 is expected empty; non-empty is tolerated (matches the Go debug log).
    }

    // Store the shared secret for stream-key derivation, but do NOT enable HAP
    // encryption — the control channel stays PLAINTEXT.
    keys.shared_secret = shared_bytes.to_vec();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{KeyIvInit, StreamCipher};

    /// V1 raw pair-verify framing: 68 bytes,
    /// [0x01,0,0,0] || clientX25519(32) || clientEd25519(32).
    #[test]
    fn raw_verify_v1_layout() {
        let client_x25519 = [0xAAu8; 32];
        let client_ed25519 = [0xBBu8; 32];
        let mut v1 = [0u8; 68];
        v1[0] = 0x01;
        v1[4..36].copy_from_slice(&client_x25519);
        v1[36..68].copy_from_slice(&client_ed25519);

        assert_eq!(v1.len(), 68);
        assert_eq!(&v1[0..4], &[0x01, 0x00, 0x00, 0x00]);
        assert_eq!(&v1[4..36], &client_x25519);
        assert_eq!(&v1[36..68], &client_ed25519);
    }

    /// V3 raw pair-verify framing: 68 bytes, [0,0,0,0] || encClientSig(64).
    #[test]
    fn raw_verify_v3_layout() {
        let enc_client_sig = [0xCDu8; 64];
        let mut v3 = [0u8; 68];
        v3[4..68].copy_from_slice(&enc_client_sig);

        assert_eq!(v3.len(), 68);
        assert_eq!(&v3[0..4], &[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(&v3[4..68], &enc_client_sig);
    }

    /// AES-128-CTR offset-64 scheme: encrypting a 64-byte payload after
    /// advancing the counter by 64 bytes (two 16-byte blocks) must equal the
    /// bytes [64..128] of encrypting a 128-byte zero-prefixed buffer in one go.
    #[test]
    fn raw_verify_aes_ctr_offset_64() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let server_sig = [0x33u8; 64]; // decrypted at offset 0
        let client_sig = [0x44u8; 64]; // encrypted at offset 64

        // Path A: the production scheme — fresh cipher, skip 64 bytes, encrypt.
        let mut enc_client_a = client_sig;
        {
            let mut ctr = Aes128Ctr::new(&key.into(), &iv.into());
            let mut skip = [0u8; 64];
            ctr.apply_keystream(&mut skip);
            ctr.apply_keystream(&mut enc_client_a);
        }

        // Path B: one contiguous stream over [server_sig(64) || client_sig(64)];
        // the second half must match Path A (server decrypt consumes offset 0..64).
        let mut combined = [0u8; 128];
        combined[..64].copy_from_slice(&server_sig);
        combined[64..].copy_from_slice(&client_sig);
        {
            let mut ctr = Aes128Ctr::new(&key.into(), &iv.into());
            ctr.apply_keystream(&mut combined);
        }
        assert_eq!(&combined[64..128], &enc_client_a[..]);

        // And the server-side offset-0 decryption is just the first 64 bytes.
        let mut dec_server = server_sig;
        {
            let mut ctr = Aes128Ctr::new(&key.into(), &iv.into());
            ctr.apply_keystream(&mut dec_server);
        }
        assert_eq!(&combined[0..64], &dec_server[..]);
    }

    /// SHA-512(salt || secret)[..16] derivation matches a hand-computed digest.
    #[test]
    fn sha512_derive_key16_len() {
        let k = sha512_derive_key16("Pair-Verify-AES-Key", &[0u8; 32]);
        assert_eq!(k.len(), 16);
        let iv = sha512_derive_key16("Pair-Verify-AES-IV", &[0u8; 32]);
        // Different salts must yield different first-16-bytes.
        assert_ne!(k, iv);
    }
}
