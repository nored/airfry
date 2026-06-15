//! TLV8 (HomeKit-style) encode/decode — faithful port of the TLV8 helpers in
//! doubletake's internal/airplay/pairing.go.
//!
//! Values longer than 255 bytes are split into 255-byte chunks that repeat the
//! same tag; decoding concatenates consecutive same-tag chunks.

#![allow(dead_code)]

use std::collections::HashMap;

// TLV8 type tags (HomeKit pairing).
pub const TLV_METHOD: u8 = 0x00;
pub const TLV_IDENTIFIER: u8 = 0x01;
pub const TLV_SALT: u8 = 0x02;
pub const TLV_PUBLIC_KEY: u8 = 0x03;
pub const TLV_PROOF: u8 = 0x04;
pub const TLV_ENCRYPTED_DATA: u8 = 0x05;
pub const TLV_STATE: u8 = 0x06;
pub const TLV_ERROR: u8 = 0x07;
pub const TLV_SIGNATURE: u8 = 0x0A;
pub const TLV_FLAGS: u8 = 0x13;

/// An ordered tag/value pair for deterministic TLV8 encoding.
#[derive(Debug, Clone)]
pub struct Item {
    pub tag: u8,
    pub value: Vec<u8>,
}

impl Item {
    pub fn new(tag: u8, value: impl Into<Vec<u8>>) -> Self {
        Item {
            tag,
            value: value.into(),
        }
    }
}

/// Encode TLV8 items in the order given (matches Go `tlv8EncodeOrdered`).
pub fn encode(items: &[Item]) -> Vec<u8> {
    let mut buf = Vec::new();
    for item in items {
        let mut value: &[u8] = &item.value;
        if value.is_empty() {
            buf.push(item.tag);
            buf.push(0);
            continue;
        }
        while !value.is_empty() {
            let n = value.len().min(255);
            buf.push(item.tag);
            buf.push(n as u8);
            buf.extend_from_slice(&value[..n]);
            value = &value[n..];
        }
    }
    buf
}

/// Decode TLV8 into a map, concatenating same-tag chunks (matches Go
/// `tlv8Decode`). Returns whatever was parsed up to the first malformed entry.
pub fn decode(mut data: &[u8]) -> HashMap<u8, Vec<u8>> {
    let mut result: HashMap<u8, Vec<u8>> = HashMap::new();
    while data.len() >= 2 {
        let tag = data[0];
        let length = data[1] as usize;
        data = &data[2..];
        if length > data.len() {
            break;
        }
        result.entry(tag).or_default().extend_from_slice(&data[..length]);
        data = &data[length..];
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_simple() {
        let items = vec![
            Item::new(TLV_METHOD, vec![0x00]),
            Item::new(TLV_STATE, vec![0x01]),
            Item::new(TLV_FLAGS, 0x00000010u32.to_le_bytes().to_vec()),
        ];
        let enc = encode(&items);
        // method: 00 01 00 ; state: 06 01 01 ; flags: 13 04 10 00 00 00
        assert_eq!(enc, vec![0x00, 0x01, 0x00, 0x06, 0x01, 0x01, 0x13, 0x04, 0x10, 0x00, 0x00, 0x00]);

        let dec = decode(&enc);
        assert_eq!(dec.get(&TLV_METHOD).unwrap(), &vec![0x00]);
        assert_eq!(dec.get(&TLV_STATE).unwrap(), &vec![0x01]);
        assert_eq!(dec.get(&TLV_FLAGS).unwrap(), &0x10u32.to_le_bytes().to_vec());
    }

    #[test]
    fn round_trip_long_value_chunks() {
        // A 600-byte value must split into 255 + 255 + 90 chunks repeating the tag,
        // and decode must concatenate them back into one 600-byte value.
        let big: Vec<u8> = (0..600u32).map(|i| (i & 0xff) as u8).collect();
        let items = vec![Item::new(TLV_PUBLIC_KEY, big.clone())];
        let enc = encode(&items);
        // 3 chunks: (2+255) + (2+255) + (2+90)
        assert_eq!(enc.len(), (2 + 255) + (2 + 255) + (2 + 90));
        assert_eq!(enc[0], TLV_PUBLIC_KEY);
        assert_eq!(enc[1], 255);
        assert_eq!(enc[2 + 255], TLV_PUBLIC_KEY);
        assert_eq!(enc[2 + 255 + 1], 255);

        let dec = decode(&enc);
        assert_eq!(dec.get(&TLV_PUBLIC_KEY).unwrap(), &big);
    }

    #[test]
    fn empty_value_encodes_zero_length() {
        let items = vec![Item::new(TLV_STATE, Vec::new())];
        let enc = encode(&items);
        assert_eq!(enc, vec![TLV_STATE, 0x00]);
    }
}
