//! Golden-vector validation against the Go fpemu (doubletake). The Rust port
//! MUST reproduce these byte-for-byte. Vectors generated from the Go engine.

fn vectors() -> std::collections::HashMap<String, Vec<u8>> {
    let txt = include_str!("vectors.txt");
    let mut m = std::collections::HashMap::new();
    for line in txt.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            m.insert(k.trim().to_string(), hex::decode(v.trim()).unwrap());
        }
    }
    m
}

#[test]
fn core_128_to_20() {
    let v = vectors();
    let mut payload = [0u8; 128];
    payload.copy_from_slice(&v["CORE_IN"]);
    let out = fpemu::fp_sap_exchange_standalone(payload);
    assert_eq!(out.to_vec(), v["CORE_OUT"], "core 128->20 mismatch");
}

#[test]
fn m2_to_m3() {
    let v = vectors();
    let m3 = fpemu::fp_sap_exchange_m3(&v["M2"]).expect("exchange failed");
    assert_eq!(m3, v["M3"], "m2 -> m3 mismatch");
}
