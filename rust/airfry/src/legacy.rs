//! Legacy AirPlay pairing for UxPlay-style receivers.
//!
//! UxPlay (and other AirPlay-1 mirroring receivers) do not speak the HomeKit
//! TLV8 pairing that `pairing.rs` implements for Apple TVs. They take:
//!   * no PIN: a raw 32-byte ed25519 `/pair-setup` (pairing::raw_pair_setup);
//!   * `-pin`: `/pair-pin-start`, then `/pair-setup-pin` with bplist bodies:
//!     SRP-6a (SHA-1, RFC 5054 2048-bit group, Apple's 40-byte session key),
//!     then the ed25519 keys swapped under AES-128-GCM;
//!   * then the raw `/pair-verify` both ways (pairing::raw_pair_verify).
//!
//! Server side: UxPlay lib/raop_handlers.h, lib/pairing.c, lib/srp.c.

use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::aes::Aes128;
use aes_gcm::{AesGcm, Nonce, Tag};
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use num_bigint::BigUint;
use plist::Value;
use rand::RngCore;
use sha1::{Digest, Sha1};
use sha2::Sha512;

use crate::info::ReceiverInfo;
use crate::pairing::{self, PairKeys};
use crate::rtsp::Transport;

/// AES-128-GCM with the 16-byte IV UxPlay uses (EVP_CTRL_GCM_SET_IVLEN 16).
type Aes128Gcm16 = AesGcm<Aes128, U16>;

/// Feature bits a HomeKit-pairing receiver sets: 38 (CoreUtils pairing and
/// encryption) and 46 (HomeKit pairing and access control). Every tvOS Apple
/// TV sets them; UxPlay (features 0x5A7FFEE6 / 0x527FFEE6) sets neither.
const FEATURES_HOMEKIT: u64 = (1 << 38) | (1 << 46);
/// Bit 27 "supports legacy pairing": UxPlay sets it only when run with -pin.
const FEATURE_LEGACY_PAIRING: u64 = 1 << 27;

/// True for a receiver that needs this module instead of the HomeKit path.
/// A failed GET /info leaves `features == 0`, which keeps the upstream path.
pub fn is_legacy_receiver(info: &ReceiverInfo) -> bool {
    info.features != 0 && info.features & FEATURES_HOMEKIT == 0
}

/// True when the receiver asks for its on-screen PIN (UxPlay -pin).
pub fn wants_pin(info: &ReceiverInfo) -> bool {
    info.features & FEATURE_LEGACY_PAIRING != 0
}

/// RFC 5054 2048-bit group, g = 2 (UxPlay SRP_NG_2048).
const N_2048_HEX: &str = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050\
A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50\
E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8\
55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B\
CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748\
544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6\
AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6\
94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";

fn sha1(parts: &[&[u8]]) -> [u8; 20] {
    let mut h = Sha1::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn sha512_16(label: &str, k: &[u8]) -> [u8; 16] {
    let mut h = Sha512::new();
    sha2::Digest::update(&mut h, label.as_bytes());
    sha2::Digest::update(&mut h, k);
    let out = sha2::Digest::finalize(h);
    let mut r = [0u8; 16];
    r.copy_from_slice(&out[..16]);
    r
}

/// Big-endian bytes left-padded to `len` (SRP PAD()).
fn pad(n: &BigUint, len: usize) -> Vec<u8> {
    let b = n.to_bytes_be();
    let mut out = vec![0u8; len.saturating_sub(b.len())];
    out.extend_from_slice(&b);
    out
}

/// Client side of csrp as UxPlay builds it (lib/srp.c, rfc5054_compat = 1,
/// APPLE_VARIANT). Big numbers are hashed in OpenSSL's minimal BN_bn2bin form
/// except where RFC 5054 pads (k, u). Returns (A, M, K).
struct SrpClient {
    a_pub: Vec<u8>,
    m: [u8; 20],
    k: Vec<u8>,
}

fn srp_client(user: &str, pin: &str, salt: &[u8], b_pub: &[u8], a_priv: &[u8]) -> Result<SrpClient> {
    let n = BigUint::parse_bytes(N_2048_HEX.as_bytes(), 16).expect("valid N");
    let g = BigUint::from(2u32);
    let nlen = 256;
    let b = BigUint::from_bytes_be(b_pub);
    if (&b % &n) == BigUint::from(0u32) {
        bail!("pair-setup-pin: invalid server public key");
    }
    let s = BigUint::from_bytes_be(salt);
    let a = BigUint::from_bytes_be(a_priv);
    let a_big = g.modpow(&a, &n);

    let k = BigUint::from_bytes_be(&sha1(&[&pad(&n, nlen), &pad(&g, nlen)]));
    let u = BigUint::from_bytes_be(&sha1(&[&pad(&a_big, nlen), &pad(&b, nlen)]));
    let inner = sha1(&[user.as_bytes(), b":", pin.as_bytes()]);
    let x = BigUint::from_bytes_be(&sha1(&[&s.to_bytes_be(), &inner]));

    // S = (B - k * g^x) ^ (a + u * x) mod N
    let kgx = (&k * g.modpow(&x, &n)) % &n;
    let base = ((&b % &n) + &n - kgx) % &n;
    let big_s = base.modpow(&(&a + &u * &x), &n);

    // Apple variant: K = H(S | 00000000) || H(S | 00000001), 40 bytes.
    let s_bytes = big_s.to_bytes_be();
    let mut key = sha1(&[&s_bytes, &[0, 0, 0, 0]]).to_vec();
    key.extend_from_slice(&sha1(&[&s_bytes, &[0, 0, 0, 1]]));

    let h_n = sha1(&[&n.to_bytes_be()]);
    let h_g = sha1(&[&g.to_bytes_be()]);
    let mut h_xor = [0u8; 20];
    for i in 0..20 {
        h_xor[i] = h_n[i] ^ h_g[i];
    }
    let h_i = sha1(&[user.as_bytes()]);
    let m = sha1(&[
        &h_xor,
        &h_i,
        &s.to_bytes_be(),
        &a_big.to_bytes_be(),
        &b.to_bytes_be(),
        &key,
    ]);
    Ok(SrpClient { a_pub: a_big.to_bytes_be(), m, k: key })
}

fn bplist(entries: Vec<(&str, Value)>) -> Result<Vec<u8>> {
    let mut d = plist::Dictionary::new();
    for (k, v) in entries {
        d.insert(k.into(), v);
    }
    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, &Value::Dictionary(d)).context("encode bplist")?;
    Ok(out)
}

fn bplist_data(body: &[u8], key: &str) -> Result<Vec<u8>> {
    let v = Value::from_reader(std::io::Cursor::new(body)).context("decode bplist")?;
    v.as_dictionary()
        .and_then(|d| d.get(key))
        .and_then(|v| v.as_data())
        .map(|d| d.to_vec())
        .ok_or_else(|| anyhow!("pair-setup-pin: response has no '{key}'"))
}

/// The first /pair-setup-pin request met a closed connection: the receiver
/// stopped waiting for the PIN. Nothing was sent that uses the PIN yet.
#[derive(Debug)]
struct ClosedBeforePin;

impl std::fmt::Display for ClosedBeforePin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("receiver closed the connection before the PIN arrived")
    }
}

fn mark_closed_before_pin(e: anyhow::Error) -> anyhow::Error {
    use std::io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset, UnexpectedEof};
    let closed = e.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| matches!(io.kind(), UnexpectedEof | ConnectionReset | ConnectionAborted | BrokenPipe))
    });
    if closed { e.context(ClosedBeforePin) } else { e }
}

fn connection_lost(e: &anyhow::Error) -> bool {
    e.downcast_ref::<ClosedBeforePin>().is_some()
}

/// A new connection to the receiver. /info first, as on the first connection,
/// so UxPlay sees the same request order; its answer is already known.
fn reconnect(transport: &mut Transport, host: &str, port: u16) -> Result<()> {
    *transport = Transport::connect(host, port).context("reconnect")?;
    let _ = crate::info::get_info(transport);
    Ok(())
}

fn post_bplist(transport: &mut Transport, body: &[u8]) -> Result<Vec<u8>> {
    let resp = transport
        .request("POST", "/pair-setup-pin", "application/x-apple-binary-plist", body, &[])
        .context("POST /pair-setup-pin")?;
    Ok(resp.body)
}

/// `/pair-setup-pin` in three steps. `user` becomes UxPlay's client device
/// id; it must equal the SETUP `deviceID` for UxPlay -reg to register us.
/// Fills `keys` with the ed25519 identity (`seed` or a fresh one) and returns
/// the receiver's ed25519 public key.
pub fn pair_setup_pin(
    transport: &mut Transport,
    user: &str,
    pin: &str,
    seed: Option<[u8; 32]>,
    keys: &mut PairKeys,
) -> Result<Vec<u8>> {
    let seed = seed.unwrap_or_else(|| {
        let mut s = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut s);
        s
    });
    let signing = SigningKey::from_bytes(&seed);
    keys.ed25519_public = signing.verifying_key().to_bytes().to_vec();
    keys.ed25519_seed = seed.to_vec();

    // Step 1: method + user -> salt + B.
    let body = bplist(vec![
        ("method", Value::String("pin".into())),
        ("user", Value::String(user.into())),
    ])?;
    let resp = post_bplist(transport, &body).map_err(mark_closed_before_pin)?;
    let salt = bplist_data(&resp, "salt")?;
    let b_pub = bplist_data(&resp, "pk")?;

    // Step 2: A + M -> server proof H(A | M | K).
    let mut a_priv = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut a_priv);
    let srp = srp_client(user, pin, &salt, &b_pub, &a_priv)?;
    // UxPlay copies the proof into a 64-byte buffer and rejects any other
    // length; only the first 20 bytes (the SHA-1 M) are compared.
    let mut proof = srp.m.to_vec();
    proof.resize(64, 0);
    let body = bplist(vec![
        ("pk", Value::Data(srp.a_pub.clone())),
        ("proof", Value::Data(proof)),
    ])
    .context("encode proof")?;
    let resp = post_bplist(transport, &body).context("wrong PIN?")?;
    let server_proof = bplist_data(&resp, "proof")?;
    let expect = sha1(&[&srp.a_pub, &srp.m, &srp.k]);
    if server_proof.get(..20) != Some(&expect[..]) {
        bail!("pair-setup-pin: server proof does not match");
    }

    // Step 3: our ed25519 pk under AES-GCM; the receiver answers with its own,
    // encrypted with the IV's last byte incremented once more.
    let key = sha512_16("Pair-Setup-AES-Key", &srp.k);
    let mut iv = sha512_16("Pair-Setup-AES-IV", &srp.k);
    iv[15] = iv[15].wrapping_add(1);
    let cipher = Aes128Gcm16::new(&key.into());
    let mut epk = keys.ed25519_public.clone();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::<U16>::from_slice(&iv), &[], &mut epk)
        .map_err(|_| anyhow!("pair-setup-pin: encrypt"))?;
    let body = bplist(vec![
        ("epk", Value::Data(epk)),
        ("authTag", Value::Data(tag.to_vec())),
    ])?;
    let resp = post_bplist(transport, &body)?;
    let mut server_pk = bplist_data(&resp, "epk")?;
    let server_tag = bplist_data(&resp, "authTag")?;
    if server_pk.len() != 32 || server_tag.len() != 16 {
        bail!("pair-setup-pin: bad epk/authTag length");
    }
    iv[15] = iv[15].wrapping_add(1);
    cipher
        .decrypt_in_place_detached(
            Nonce::<U16>::from_slice(&iv),
            &[],
            &mut server_pk,
            Tag::from_slice(&server_tag),
        )
        .map_err(|_| anyhow!("pair-setup-pin: receiver key failed authentication"))?;
    Ok(server_pk)
}

/// Pair with a legacy receiver on `transport`. Returns the keys for fp-setup
/// and whether they should be saved (only a PIN pairing is worth keeping).
///
/// * `saved`: identity from a previous PIN pairing. With UxPlay -pin a bare
///   `/pair-verify` with a known key skips the PIN (UxPlay checks its -reg
///   list, or accepts any key without -reg).
/// * PIN receiver or explicit `pin`: `/pair-pin-start` (only when we have to
///   prompt), `/pair-setup-pin`, raw `/pair-verify`.
/// * otherwise: raw `/pair-setup` + raw `/pair-verify`, nothing to save.
#[allow(clippy::too_many_arguments)]
pub fn pair(
    transport: &mut Transport,
    info: &mut ReceiverInfo,
    host: &str,
    port: u16,
    pin: &str,
    saved: Option<(Vec<u8>, [u8; 32])>,
    user: &str,
    pin_provider: &mut dyn FnMut() -> Option<String>,
    progress: &mut dyn FnMut(&str, bool, &str),
) -> Result<(PairKeys, bool)> {
    let use_pin = !pin.is_empty() || wants_pin(info);
    if use_pin && pin.is_empty() {
        if let Some((public, seed)) = &saved {
            let mut keys = PairKeys {
                ed25519_public: public.clone(),
                ed25519_seed: seed.to_vec(),
                ..Default::default()
            };
            match pairing::raw_pair_verify(transport, &mut keys, &info.pk) {
                Ok(()) => {
                    progress("pair-verify", true, "legacy pair-verify with saved identity");
                    return Ok((keys, false));
                }
                Err(e) => {
                    progress("pair-verify", false, &format!("saved identity refused ({e}); pairing with PIN"));
                    // The refused verify leaves UxPlay's session half-open.
                    reconnect(transport, host, port)?;
                }
            }
        }
    }

    let mut keys = PairKeys::default();
    if !use_pin {
        let server_pk = pairing::raw_pair_setup(transport, &mut keys).context("legacy pair-setup")?;
        progress("pair-setup", true, "legacy pair-setup (no PIN)");
        info.pk = server_pk;
        pairing::raw_pair_verify(transport, &mut keys, &info.pk).context("legacy pair-verify")?;
        progress("pair-verify", true, "legacy pair-verify (plaintext)");
        return Ok((keys, false));
    }

    let code = if pin.is_empty() {
        pairing::pair_pin_start(transport).context("pair-pin-start")?;
        progress("pin", true, "asked the receiver to show its pairing code");
        match pin_provider() {
            Some(p) if !p.trim().is_empty() => p.trim().to_string(),
            _ => bail!("pairing requires the code shown on the receiver, but none was provided"),
        }
    } else {
        pin.to_string()
    };
    let seed = saved.map(|(_, s)| s);
    let server_pk = match pair_setup_pin(transport, user, &code, seed, &mut keys) {
        Ok(pk) => pk,
        // UxPlay closes the connection about 17 s after it opens, which is
        // often before the PIN is typed. It keeps the PIN it shows until a
        // /pair-setup-pin uses it, so a fresh connection without a new
        // /pair-pin-start still pairs with that PIN.
        Err(e) if connection_lost(&e) => {
            progress("pin", true, &format!("receiver had closed the connection ({e:#}); reconnecting with the same PIN"));
            reconnect(transport, host, port)?;
            keys = PairKeys::default();
            pair_setup_pin(transport, user, &code, seed, &mut keys)?
        }
        Err(e) => return Err(e),
    };
    progress("pair-setup", true, "legacy PIN pair-setup");
    info.pk = server_pk;
    pairing::raw_pair_verify(transport, &mut keys, &info.pk).context("legacy pair-verify")?;
    progress("pair-verify", true, "legacy pair-verify (plaintext)");
    Ok((keys, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A closed socket on the first /pair-setup-pin means retry; a wrong PIN
    /// (step 2) or any other error does not.
    #[test]
    fn only_a_closed_connection_is_retried() {
        let eof = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
            .context("read response header byte")
            .context("POST /pair-setup-pin");
        assert!(connection_lost(&mark_closed_before_pin(eof)));
        let timeout = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::TimedOut));
        assert!(!connection_lost(&mark_closed_before_pin(timeout)));
        // Step 2 is never marked, so even a closed socket there (UxPlay drops
        // the connection after a wrong proof) is not retried.
        let step2_eof = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
            .context("POST /pair-setup-pin")
            .context("wrong PIN?");
        assert!(!connection_lost(&step2_eof));
    }

    /// Server side of the same SRP, written the way UxPlay's srp.c computes it
    /// (v = g^x, B = k*v + g^b, S = (A * v^u)^b), to prove the client math.
    #[test]
    fn srp_matches_server_math() {
        let n = BigUint::parse_bytes(N_2048_HEX.as_bytes(), 16).unwrap();
        let g = BigUint::from(2u32);
        let (user, pin) = ("02:AB:CD:EF:01:23", "1234");
        // A leading zero byte checks the minimal-length salt hashing.
        let salt = [0u8, 7, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        let x = BigUint::from_bytes_be(&sha1(&[
            &BigUint::from_bytes_be(&salt).to_bytes_be(),
            &sha1(&[user.as_bytes(), b":", pin.as_bytes()]),
        ]));
        let v = g.modpow(&x, &n);
        let k = BigUint::from_bytes_be(&sha1(&[&pad(&n, 256), &pad(&g, 256)]));
        let b_priv = BigUint::from_bytes_be(&[0x42; 32]);
        let b_pub = (&k * &v + g.modpow(&b_priv, &n)) % &n;

        let c = srp_client(user, pin, &salt, &b_pub.to_bytes_be(), &[0x17; 32]).unwrap();
        let a_pub = BigUint::from_bytes_be(&c.a_pub);
        let u = BigUint::from_bytes_be(&sha1(&[&pad(&a_pub, 256), &pad(&b_pub, 256)]));
        let s = (&a_pub * v.modpow(&u, &n)).modpow(&b_priv, &n);
        let mut key = sha1(&[&s.to_bytes_be(), &[0, 0, 0, 0]]).to_vec();
        key.extend_from_slice(&sha1(&[&s.to_bytes_be(), &[0, 0, 0, 1]]));
        assert_eq!(c.k, key);
    }

    #[test]
    fn legacy_detection() {
        let mut info = ReceiverInfo::default();
        assert!(!is_legacy_receiver(&info), "no /info keeps the upstream path");
        info.features = 0x5A7F_FEE6; // UxPlay -pin
        assert!(is_legacy_receiver(&info) && wants_pin(&info));
        info.features = 0x527F_FEE6; // UxPlay without -pin
        assert!(is_legacy_receiver(&info) && !wants_pin(&info));
        info.features = 0xBC17_7FDE_4A7F_DFD5; // Apple TV 4K
        assert!(!is_legacy_receiver(&info));
    }
}
